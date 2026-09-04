package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// detailsModel is the bubbletea model for the top-right Details pane.
type detailsModel struct {
	node      *TreeNode
	store     *manifest.Store
	cfg       *config.Config
	buildRoot string
	viewport  viewport.Model
	width     int
	height    int
	focused   bool

	// aptSigned is whether this host holds a usable apt signing key, read
	// outside the render path and refreshed by refreshAptSigning.
	aptSigned bool
}

// aptDiskStateNote names whose signing state the pane is reporting. The TUI
// reads the key file; the server holds a signer that outlives it, because a
// reload never takes signing away — so a deleted key leaves the server signing
// an index this pane would call unsigned. The two disagree until a restart,
// and only the server knows which one a client will meet.
const aptDiskStateNote = "This form comes from the signing key on this host's disk, not from the running server: a server that already loaded a key keeps signing until it restarts. GET /api/v1/status reports what the server is actually doing."

// newDetailsModel creates the details pane.
func newDetailsModel(store *manifest.Store, cfg *config.Config) detailsModel {
	vp := viewport.New(80, 20)
	return detailsModel{store: store, cfg: cfg, buildRoot: cfg.BuildRoot, viewport: vp, aptSigned: aptKeyLoaded(cfg)}
}

// refreshAptSigning re-reads the on-disk signing key. Reading once at
// construction meant a key generated while the TUI was open stayed invisible
// until restart, and the pane went on offering [trusted=yes] for a repository
// that had started signing.
func (m *detailsModel) refreshAptSigning() {
	m.aptSigned = aptKeyLoaded(m.cfg)
}

// SetNode updates the node whose metadata is displayed.
func (m *detailsModel) SetNode(n *TreeNode) {
	m.node = n
	m.syncViewport()
}

// SetSize updates the viewport dimensions.
func (m *detailsModel) SetSize(w, h int) {
	m.width = w
	m.height = h
	m.viewport.Width = w
	m.viewport.Height = h
}

// ScrollUp scrolls the details viewport up.
func (m *detailsModel) ScrollUp() { m.viewport.ScrollUp(1) }

// ScrollDown scrolls the details viewport down.
func (m *detailsModel) ScrollDown() { m.viewport.ScrollDown(1) }

func (m *detailsModel) syncViewport() {
	var content string
	if m.node == nil {
		content = dimStyle.Render("  Select an entry in the Sources pane.")
	} else if m.node.IsGroup {
		content = m.renderGroupDetails()
	} else {
		content = m.renderEntryDetails()
	}
	m.viewport.SetContent(content)
	m.viewport.GotoTop()
}

// View renders the details pane content via the scrollable viewport.
func (m detailsModel) View() string {
	return m.viewport.View()
}

// field renders a single key/value pair.
func field(key, value string) string {
	k := keyStyle.Render(key + ":")
	v := valueStyle.Render(value)
	return k + " " + v
}

// noteField renders a value that runs past the pane onto continuation lines
// aligned under the first. wrap truncates, which is right for a path and wrong
// for a consequence: an operator who reads two thirds of why [trusted=yes] is
// permanent and propagates has read none of it, and that paragraph is the
// whole reason the fallback ships with prose attached.
func noteField(key, value string, width int) string {
	// keyStyle pads to 12; field writes one space after it.
	const keyWidth = 13
	body := width - keyWidth
	if body < 24 {
		body = 24
	}
	lines := strings.Split(lipgloss.NewStyle().Width(body).Render(value), "\n")
	var sb strings.Builder
	sb.WriteString(keyStyle.Render(key+":") + " " + valueStyle.Render(lines[0]))
	for _, l := range lines[1:] {
		sb.WriteString("\n" + strings.Repeat(" ", keyWidth) + valueStyle.Render(l))
	}
	return sb.String()
}

// boolField renders a boolean field with coloured yes/no.
func boolField(key string, val bool) string {
	k := keyStyle.Render(key + ":")
	var v string
	if val {
		v = lipgloss_green("yes")
	} else {
		v = dimStyle.Render("no")
	}
	return k + " " + v
}

func lipgloss_green(s string) string {
	return successStyle.Render(s)
}

// s3AndClientFields renders S3 status, S3 path, and client URL for an entry.
func (m detailsModel) s3AndClientFields(n *TreeNode) string {
	var sb strings.Builder
	sb.WriteString(s3StatusField(n.InS3))
	sb.WriteByte('\n')
	if key := s3Path(m.store, n.EntryType, n.Name, n.Version); key != "" {
		s3URI := key
		if m.cfg.Bucket != "" {
			s3URI = "s3://" + m.cfg.Bucket + "/" + key
		}
		sb.WriteString(field("S3 path", s3URI))
		sb.WriteByte('\n')
	}
	if n.EntryType == manifest.TypeApt {
		pm, _ := m.store.GetPackage(context.Background(), manifest.TypeApt, n.Name)
		src := aptSources(m.cfg, pm, m.aptSigned)
		sb.WriteString(field("Sources line", src.OneLine))
		sb.WriteByte('\n')
		for _, note := range append(src.Notes, aptDiskStateNote) {
			sb.WriteString(noteField("Note", note, m.width))
			sb.WriteByte('\n')
		}
		return sb.String()
	}
	if url := clientURL(m.cfg, m.store, n.EntryType, n.Name); url != "" {
		sb.WriteString(field("Package URL", url))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// discoverGitDeps checks the extracted source for known dependency files
// and returns a summary string for the details pane.
func (m detailsModel) discoverGitDeps(name, ref string) string {
	if m.buildRoot == "" {
		return ""
	}
	worktree, err := builder.GitWorktreePath(m.buildRoot, name, ref)
	if err != nil || worktree == "" {
		return ""
	}

	type depFile struct {
		name      string
		ecosystem string
	}
	candidates := []depFile{
		{"requirements.txt", "pypi"},
		{"go.mod", "gomod"},
		{"package.json", "npm"},
		{"Gemfile", "ruby"},
		{"pom.xml", "java"},
		{"build.gradle", "java"},
		{"Cargo.toml", "rust"},
	}

	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(worktree, c.name)); err == nil {
			found = append(found, c.name+" ("+c.ecosystem+")")
		}
	}
	if len(found) == 0 {
		return ""
	}
	return field("Deps", strings.Join(found, ", "))
}

// dependentsOf returns a formatted list of pypi packages that have the given
// git entry name in their RequiredBy field.
func (m detailsModel) dependentsOf(name string) string {
	ctx := context.Background()
	var deps []string
	for _, safeName := range m.store.ListPackages(manifest.TypePypi) {
		pm, err := m.store.GetPackage(ctx, manifest.TypePypi, safeName)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			matched := false
			for _, rb := range ve.RequiredBy {
				if rb == name {
					matched = true
					break
				}
			}
			if matched {
				label := pm.Name
				if ve.Version != "" {
					label += "==" + ve.Version
				}
				deps = append(deps, label)
				break
			}
		}
	}
	if len(deps) == 0 {
		return ""
	}
	return field("Depends on", strings.Join(deps, ", "))
}

// platformAndBuildEnv renders platform and build environment fields.
func platformAndBuildEnv(platform string, env *manifest.BuildEnv) string {
	var sb strings.Builder
	if platform != "" {
		sb.WriteString(field("Platform", platform))
		sb.WriteByte('\n')
	}
	if env != nil {
		sb.WriteString(dimStyle.Render("── Build Environment ──"))
		sb.WriteByte('\n')
		if env.OSRelease != "" {
			sb.WriteString(field("OS", env.OSRelease))
			sb.WriteByte('\n')
		}
		if env.Python != "" {
			sb.WriteString(field("Python", env.Python))
			sb.WriteByte('\n')
		}
		if env.Go != "" {
			sb.WriteString(field("Go", env.Go))
			sb.WriteByte('\n')
		}
		if env.Rust != "" {
			sb.WriteString(field("Rust", env.Rust))
			sb.WriteByte('\n')
		}
		if env.Bodega != "" {
			sb.WriteString(field("Bodega", env.Bodega))
			sb.WriteByte('\n')
		}
		if env.BuiltAt != "" {
			sb.WriteString(field("Built at", env.BuiltAt))
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// checksumFields renders checksum and verification status.
func checksumFields(cs *manifest.Checksum, verified bool) string {
	if cs == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(field("Checksum", cs.Algorithm+":"+cs.Value))
	sb.WriteByte('\n')
	sb.WriteString(boolField("Verified", verified))
	sb.WriteByte('\n')
	return sb.String()
}

func s3StatusField(inS3 bool) string {
	k := keyStyle.Render("S3:")
	var v string
	if inS3 {
		v = successStyle.Render("uploaded")
	} else {
		v = errorStyle.Render("not in S3")
	}
	return k + " " + v
}

// s3Path renders the object key backing a tree node, derived the same way the
// uploader and the server derive it. version selects a specific VersionEntry;
// empty version falls back to the first, which is the package-header behavior.
//
// A key shown here that nothing writes is the same defect as a key probed that
// nothing writes, so this resolves through manifest.ArtifactKeys rather than
// spelling the layouts out again.
func s3Path(store *manifest.Store, entryType, name, version string) string {
	ctx := context.Background()
	pm, err := store.GetPackage(ctx, entryType, name)
	if err != nil || pm == nil || len(pm.Versions) == 0 {
		return typeTreePrefix(entryType)
	}
	ve := pm.Versions[0]
	if version != "" {
		for _, candidate := range pm.Versions {
			if candidate.Version == version || candidate.Ref == version {
				ve = candidate
				break
			}
		}
	}
	keys, err := manifest.ArtifactKeys(pm, ve)
	if err != nil || len(keys) == 0 {
		return typeTreePrefix(entryType)
	}
	return keys[0]
}

// typeTreePrefix names the tree an entry lives under when no single object
// backs it: pypi uploads as a directory, and an apt entry that predates the
// _pool_path metadata key needs a pool listing the details pane will not do.
func typeTreePrefix(entryType string) string {
	switch entryType {
	case manifest.TypeApt:
		return manifest.AptPrefix
	case manifest.TypePypi:
		return manifest.PypiWheelPrefix
	}
	return ""
}

// clientScheme returns the scheme this host's own listener answers on. Start
// enables TLS only when both a cert and a key resolve, and bodega has no
// other way to obtain one, so the pair is the whole signal.
//
// It describes the local listener and nothing else. Behind a reverse proxy
// both TLS keys are empty here while every client speaks https, which is why
// it only ever fills a placeholder that public_url overrides.
func clientScheme(cfg *config.Config) string {
	if cfg != nil && cfg.TLSCert != "" && cfg.TLSKey != "" {
		return "https"
	}
	return "http"
}

// clientBase returns the base URL a client reaches this server at: public_url
// when the operator set one, a placeholder host otherwise. Every client-facing
// URL the pane emits is built from it, so the sources line and the pip line
// cannot disagree about where the server is.
func clientBase(cfg *config.Config) string {
	st := aptsources.State{LocalScheme: clientScheme(cfg)}
	if cfg != nil {
		st.PublicURL = cfg.ResolvePublicURL("")
	}
	return st.BaseURL()
}

// aptSources renders the apt client configuration for a package through the
// one renderer the server and web UI also use.
//
// Signing comes from the same key search the server performs. The TUI holds no
// connection to the running process, so it agrees with what is served except
// in the window between a key changing on disk and the SIGHUP that loads it —
// and the alternative, assuming unsigned, is what told operators to paste
// [trusted=yes] into a signed instance.
func aptSources(cfg *config.Config, pm *manifest.PackageManifest, signed bool) aptsources.Sources {
	st := aptsources.State{
		LocalScheme: clientScheme(cfg),
		Suites:      []string{aptSourcesSuite(cfg, pm)},
		Signed:      signed,
	}
	if cfg != nil {
		st.PublicURL = cfg.ResolvePublicURL("")
	}
	return aptsources.Render(st)
}

// aptKeyLoaded reports whether the server on this host would find a usable
// signing key, using aptsign's own search order and the same acceptance test
// loadAptSigner applies. Stopping at Load is not enough: the server stores a
// signer only once both public forms render, so a key that parses but will not
// serialize leaves the repository unsigned while a pane that stopped at Load
// prints Signed-By: — and a client configured that way fails apt update
// outright rather than degrading to an unverified fetch.
//
// This describes the key file, not the running server; aptDiskStateNote says
// so beside the line. Read when the pane is built and again on every store
// refresh, rather than in the render path: it does file I/O and a key parse,
// and a render runs on every terminal resize.
func aptKeyLoaded(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	kr, err := aptsign.Load(aptsign.DefaultKeyPaths(cfg.StoragePath))
	if err != nil {
		return false
	}
	if _, err := kr.PublicKey(); err != nil {
		return false
	}
	if _, err := kr.Keyring(); err != nil {
		return false
	}
	return true
}

// aptSourcesSuite picks the suite for a sources line: the first suite the
// package is published to that this server also answers for, falling back to
// the first served suite. A package in several suites needs one line per
// suite, and the pane shows one.
//
// The intersection is what keeps the line fetchable. An entry naming a suite
// outside apt_suites never reaches an index, so a line pointing at it 404s and
// the client reports "Unable to locate package" — the message a misspelled
// package name produces. The web UI matches against the server-rendered blocks
// and so can only ever name a served suite; this is the same rule.
func aptSourcesSuite(cfg *config.Config, pm *manifest.PackageManifest) string {
	if cfg == nil {
		return ""
	}
	if pm != nil {
		for _, ve := range pm.Versions {
			if ve.Hidden {
				continue
			}
			for _, suite := range ve.EffectiveSuites(cfg.AptCodename) {
				if cfg.ServesAptSuite(suite) {
					return suite
				}
			}
		}
	}
	// Empty renders aptsources.PlaceholderSuite, which is the honest answer
	// when apt_codename and apt_suites both resolved to nothing.
	if served := cfg.ServedAptSuites(); len(served) > 0 {
		return served[0]
	}
	return ""
}

// clientURL returns the URL a client would use to fetch the artifact from the
// bodega server.
//
// apt has no case here on purpose: a sources line is a configuration stanza
// rather than a URL, and it needs the served suites and the signing state as
// well as the base URL. aptSources renders it.
func clientURL(cfg *config.Config, store *manifest.Store, entryType, name string) string {
	ctx := context.Background()
	base := clientBase(cfg)
	pm, err := store.GetPackage(ctx, entryType, name)
	switch entryType {
	case manifest.TypeGit:
		if err != nil || pm == nil || len(pm.Versions) == 0 {
			return ""
		}
		ve := pm.Versions[0]
		ext := ".bundle"
		if ve.IsRelease() {
			ext = ".tar.gz"
		}
		sn := strings.ReplaceAll(pm.Name, "/", "--")
		return fmt.Sprintf("%s/git/%s/%s-%s%s", base, sn, sn, ve.Ref, ext)
	case manifest.TypeBinary:
		if err != nil || pm == nil || len(pm.Versions) == 0 {
			return ""
		}
		ve := pm.Versions[0]
		fn := ve.Filename
		if fn == "" && ve.URL != "" {
			parts := strings.Split(ve.URL, "/")
			fn = parts[len(parts)-1]
		}
		return fmt.Sprintf("%s/binaries/%s/%s/%s", base, pm.Name, ve.Version, fn)
	case manifest.TypePypi:
		return fmt.Sprintf("pip install --index-url %s/pypi/simple/ %s", base, name)
	case manifest.TypeGomod:
		return fmt.Sprintf("GOPROXY=%s/go,direct go get %s", base, name)
	case manifest.TypeHelm:
		if err != nil || pm == nil || len(pm.Versions) == 0 {
			return ""
		}
		ve := pm.Versions[0]
		return fmt.Sprintf("%s/helm/charts/%s-%s.tgz", base, pm.Name, ve.Version)
	case manifest.TypeNpm:
		return fmt.Sprintf("npm install --registry %s/npm/ %s", base, name)
	}
	return ""
}

func (m detailsModel) renderGroupDetails() string {
	var sb strings.Builder
	n := m.node
	ctx := context.Background()

	// Package sub-group (depth > 0): show package name, version count, description.
	if !strings.HasSuffix(n.Label, "/") {
		sb.WriteString(field("Package", n.Label))
		sb.WriteByte('\n')
		sb.WriteString(field("Type", n.EntryType))
		sb.WriteByte('\n')
		sb.WriteString(field("Versions", fmt.Sprintf("%d", len(n.Children))))
		sb.WriteByte('\n')

		// Show description if available on any child entry.
		if desc := m.packageDescription(n.EntryType, n.Label); desc != "" {
			sb.WriteString(field("Description", desc))
			sb.WriteByte('\n')
		}

		// List versions.
		if len(n.Children) > 0 {
			sb.WriteByte('\n')
			sb.WriteString(dimStyle.Render("── Versions ──"))
			sb.WriteByte('\n')
			for _, child := range n.Children {
				icon := statusIcon(child.InS3, child.Frozen, child.Hidden)
				sb.WriteString("  " + icon + " " + child.Label)
				sb.WriteByte('\n')
			}
		}
		return sb.String()
	}

	// Top-level type group: show repo-level metrics.
	sb.WriteString(field("Type", n.EntryType+"/"))
	sb.WriteByte('\n')

	names := m.store.ListPackages(n.EntryType)
	totalVersions := 0
	frozenCount := 0
	hiddenCount := 0
	for _, name := range names {
		pm, err := m.store.GetPackage(ctx, n.EntryType, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			totalVersions++
			if ve.Frozen {
				frozenCount++
			}
			if ve.Hidden {
				hiddenCount++
			}
		}
	}

	sb.WriteString(field("Packages", fmt.Sprintf("%d", len(names))))
	sb.WriteByte('\n')
	sb.WriteString(field("Versions", fmt.Sprintf("%d", totalVersions)))
	sb.WriteByte('\n')
	if frozenCount > 0 {
		sb.WriteString(field("Frozen", fmt.Sprintf("%d", frozenCount)))
		sb.WriteByte('\n')
	}
	if hiddenCount > 0 {
		sb.WriteString(field("Hidden", fmt.Sprintf("%d", hiddenCount)))
		sb.WriteByte('\n')
	}

	return sb.String()
}

// packageDescription returns a cached description for a package, or empty string.
func (m detailsModel) packageDescription(entryType, name string) string {
	ctx := context.Background()
	pm, err := m.store.GetPackage(ctx, entryType, name)
	if err != nil || pm == nil {
		return ""
	}
	return pm.Description
}

func (m detailsModel) renderEntryDetails() string {
	n := m.node
	if n == nil {
		return ""
	}
	ctx := context.Background()

	var sb strings.Builder

	pm, err := m.store.GetPackage(ctx, n.EntryType, n.Name)
	if err != nil || pm == nil || len(pm.Versions) == 0 {
		return errorStyle.Render("entry not found")
	}

	// Find the version entry matching the selected tree node.
	ve := pm.Versions[0]
	for _, candidate := range pm.Versions {
		vn := candidate.VersionedName(pm.Name)
		if vn == n.Label || candidate.Version == n.Label || candidate.Ref == n.Label {
			ve = candidate
			break
		}
		// Handle policy entry labels like "python3@*".
		if candidate.Version == "*" && n.Label == pm.Name+"@*" {
			ve = candidate
			break
		}
	}

	isPolicyEntry := ve.Version == "*"

	switch n.EntryType {
	case manifest.TypeApt:
		sb.WriteString(field("Name", pm.Name))
		sb.WriteByte('\n')
		if ve.Version != "" {
			sb.WriteString(field("Version", ve.Version))
			sb.WriteByte('\n')
		}
		if ve.SourceName != "" {
			sb.WriteString(field("Package Name", ve.SourceName))
			sb.WriteByte('\n')
		}
		if isPolicyEntry {
			if pm.DepPolicy != "" {
				sb.WriteString(field("Dep Policy", pm.DepPolicy))
				sb.WriteByte('\n')
			}
			if ve.VersionConstraint != "" {
				sb.WriteString(field("Constraint", ve.VersionConstraint))
				sb.WriteByte('\n')
			}
			sb.WriteString(boolField("Frozen", ve.Frozen))
			sb.WriteByte('\n')
			sb.WriteString(boolField("Hidden", ve.Hidden))
			sb.WriteByte('\n')
		} else {
			if ve.URL != "" {
				sb.WriteString(field("Source URL", wrap(ve.URL, m.width-16)))
				sb.WriteByte('\n')
			}
			if ve.BuildCmd != "" {
				sb.WriteString(field("BuildCmd", ve.BuildCmd))
				sb.WriteByte('\n')
			}
			if ve.DebGlob != "" {
				sb.WriteString(field("DebGlob", ve.DebGlob))
				sb.WriteByte('\n')
			}
			sb.WriteString(boolField("Frozen", ve.Frozen))
			sb.WriteByte('\n')
			sb.WriteString(boolField("Hidden", ve.Hidden))
			sb.WriteByte('\n')
			sb.WriteString(m.s3AndClientFields(n))
			sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))
		}

	case manifest.TypeGit:
		sb.WriteString(field("Name", pm.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Ref", ve.Ref))
		sb.WriteByte('\n')
		sb.WriteString(field("Source URL", wrap(ve.URL, m.width-16)))
		sb.WriteByte('\n')
		sb.WriteString(checksumFields(ve.Checksum, ve.ChecksumVerified))
		sb.WriteString(boolField("Frozen", ve.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(boolField("Hidden", ve.Hidden))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))
		// Show discovered dependency files.
		if deps := m.discoverGitDeps(pm.Name, ve.Ref); deps != "" {
			sb.WriteByte('\n')
			sb.WriteString(deps)
		}
		// Show packages that depend on this git entry.
		if depList := m.dependentsOf(pm.Name); depList != "" {
			sb.WriteByte('\n')
			sb.WriteString(depList)
		}

	case manifest.TypePypi:
		sb.WriteString(field("Name", pm.Name))
		sb.WriteByte('\n')

		if len(ve.RequiredBy) > 0 {
			sb.WriteString(field("Required by", strings.Join(ve.RequiredBy, ", ")))
			sb.WriteByte('\n')
		}

		// Load dep graph for version and dependency details.
		var depGraph *builder.PypiDepGraph
		if m.buildRoot != "" {
			wheelsDir := filepath.Join(m.buildRoot, "wheels")
			if ve.Version != "" {
				wheelsDir = filepath.Join(wheelsDir, ve.Version)
			}
			depGraph, _ = builder.LoadDepGraph(filepath.Join(wheelsDir, "dep-graph.json"))
		}

		if depGraph != nil {
			for _, pkg := range depGraph.Packages {
				if strings.EqualFold(pkg.Name, pm.Name) {
					if pkg.Version != "" {
						sb.WriteString(field("Version", pkg.Version))
						sb.WriteByte('\n')
					}
					if len(pkg.Requires) > 0 {
						sb.WriteString(field("Depends on", strings.Join(pkg.Requires, ", ")))
						sb.WriteByte('\n')
					}
					if len(pkg.UsedBy) > 0 {
						sb.WriteString(field("Used by", strings.Join(pkg.UsedBy, ", ")))
						sb.WriteByte('\n')
					}
					break
				}
			}
		} else {
			sb.WriteString(dimStyle.Render("  (build to resolve version and dependencies)"))
			sb.WriteByte('\n')
		}

		sb.WriteString(boolField("Frozen", ve.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(boolField("Hidden", ve.Hidden))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))

	case manifest.TypeBinary:
		sb.WriteString(field("Name", pm.Name))
		sb.WriteByte('\n')
		if ve.Version != "" {
			sb.WriteString(field("Version", ve.Version))
			sb.WriteByte('\n')
		}
		sb.WriteString(field("Source URL", wrap(ve.URL, m.width-16)))
		sb.WriteByte('\n')
		if ve.Filename != "" {
			sb.WriteString(field("Filename", ve.Filename))
			sb.WriteByte('\n')
		}
		if ve.SHA256 != "" {
			sb.WriteString(field("SHA256", ve.SHA256))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(ve.Checksum, ve.ChecksumVerified))
		sb.WriteString(boolField("Frozen", ve.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(boolField("Hidden", ve.Hidden))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))

	case manifest.TypeGomod:
		sb.WriteString(field("Module", pm.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Version", ve.Version))
		sb.WriteByte('\n')
		if ve.URL != "" {
			sb.WriteString(field("Source URL", ve.URL))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(ve.Checksum, ve.ChecksumVerified))
		sb.WriteString(boolField("Frozen", ve.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(boolField("Hidden", ve.Hidden))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))

	case manifest.TypeHelm:
		sb.WriteString(field("Chart", pm.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Version", ve.Version))
		sb.WriteByte('\n')
		sb.WriteString(field("Source URL", wrap(ve.URL, m.width-16)))
		sb.WriteByte('\n')
		if ve.AppVersion != "" {
			sb.WriteString(field("App Version", ve.AppVersion))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(ve.Checksum, ve.ChecksumVerified))
		sb.WriteString(boolField("Frozen", ve.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(boolField("Hidden", ve.Hidden))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))

	case manifest.TypeNpm:
		sb.WriteString(field("Package", pm.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Version", ve.Version))
		sb.WriteByte('\n')
		if ve.URL != "" {
			sb.WriteString(field("Source URL", ve.URL))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(ve.Checksum, ve.ChecksumVerified))
		sb.WriteString(boolField("Frozen", ve.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(boolField("Hidden", ve.Hidden))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))
	}

	// Render metadata map if present.
	if len(ve.Metadata) > 0 {
		sb.WriteString("\n")
		metaHeader := "Metadata"
		if n.EntryType == manifest.TypeApt {
			metaHeader = "Apt Metadata"
		}
		sb.WriteString(dimStyle.Render("── " + metaHeader + " ──"))
		sb.WriteByte('\n')
		keys := make([]string, 0, len(ve.Metadata))
		for k := range ve.Metadata {
			if k != "Description-Full" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteString(field(k, ve.Metadata[k]))
			sb.WriteByte('\n')
		}
	}

	// Append raw JSON below the parsed fields.
	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("── Package JSON Config ──"))
	sb.WriteByte('\n')
	if raw := m.rawJSON(n); raw != "" {
		// Give the wrapper a bit of slack for the viewport border.
		sb.WriteString(dimStyle.Render(wrapJSONLines(raw, m.width-4)))
	}

	return sb.String()
}

// wrapJSONLines soft-wraps any line that exceeds width. Continuation lines
// inherit the original's leading whitespace plus two spaces of indent so the
// shape of the original JSON stays recognizable after wrap. Short lines and
// very-small widths pass through unchanged.
func wrapJSONLines(raw string, width int) string {
	if width < 40 {
		return raw
	}
	var out strings.Builder
	for i, line := range strings.Split(raw, "\n") {
		if i > 0 {
			out.WriteByte('\n')
		}
		indent := leadingWhitespace(line)
		contIndent := indent + "  "
		for len(line) > width {
			cut := strings.LastIndex(line[:width], " ")
			if cut <= len(indent) {
				cut = width // hard break when no word boundary fits
			}
			out.WriteString(line[:cut])
			out.WriteByte('\n')
			line = contIndent + strings.TrimLeft(line[cut:], " ")
		}
		out.WriteString(line)
	}
	return out.String()
}

func leadingWhitespace(s string) string {
	for i, r := range s {
		if r != ' ' && r != '\t' {
			return s[:i]
		}
	}
	return s
}

// rawJSON returns the pretty-printed manifest JSON for the selected node.
// Version leaves get the scoped one-entry shape so the details pane matches
// what `pkg edit`, `pkg export`, and the web UI's version view all produce.
func (m detailsModel) rawJSON(n *TreeNode) string {
	ctx := context.Background()
	pm, err := m.store.GetPackage(ctx, n.EntryType, n.Name)
	if err != nil || pm == nil {
		return ""
	}
	var target any = pm
	if n.Version != "" {
		if scoped := pm.ScopeToVersion(n.Version); scoped != nil {
			target = scoped
		}
	}
	data, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

// wrap truncates a long string to maxWidth, appending "..." if truncated.
func wrap(s string, maxWidth int) string {
	if maxWidth <= 0 || len(s) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return s[:maxWidth]
	}
	return s[:maxWidth-3] + "..."
}
