package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/scaleapi/bodega/internal/builder"
	"github.com/scaleapi/bodega/internal/config"
	"github.com/scaleapi/bodega/internal/manifest"
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
}

// newDetailsModel creates the details pane.
func newDetailsModel(store *manifest.Store, cfg *config.Config) detailsModel {
	vp := viewport.New(80, 20)
	return detailsModel{store: store, cfg: cfg, buildRoot: cfg.BuildRoot, viewport: vp}
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
	if key := s3Path(m.cfg, m.store, n.EntryType, n.Name); key != "" {
		s3URI := key
		if m.cfg.Bucket != "" {
			s3URI = "s3://" + m.cfg.Bucket + "/" + key
		}
		sb.WriteString(field("S3 path", s3URI))
		sb.WriteByte('\n')
	}
	if url := clientURL(m.store, n.EntryType, n.Name); url != "" {
		sb.WriteString(field("Client", url))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// discoverGitDeps checks the extracted source for known dependency files
// and returns a summary string for the details pane.
func (m detailsModel) discoverGitDeps(e *manifest.GitEntry) string {
	if m.buildRoot == "" {
		return ""
	}
	worktree, err := builder.GitWorktreePath(m.buildRoot, e.Name, e.Ref)
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

// dependentsOf returns a formatted list of packages across all manifest types
// that list the given name in their required_by field.
func (m detailsModel) dependentsOf(name string) string {
	var deps []string
	for _, pkg := range m.store.Pypi.Packages {
		for _, rb := range pkg.RequiredBy {
			if rb == name {
				label := pkg.Name
				if pkg.Version != "" {
					label += "==" + pkg.Version
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

// s3Path returns the S3 object key for the given entry.
func s3Path(cfg *config.Config, store *manifest.Store, entryType, name string) string {
	switch entryType {
	case manifest.TypeGit:
		e := store.FindGit(name)
		if e == nil {
			return ""
		}
		ext := ".bundle"
		if e.IsRelease() {
			ext = ".tar.gz"
		}
		sn := strings.ReplaceAll(e.Name, "/", "--")
		return fmt.Sprintf("repos/%s/%s-%s%s", sn, sn, e.Ref, ext)
	case manifest.TypeBinary:
		e := store.FindBinary(name)
		if e == nil {
			return ""
		}
		fn := e.Filename
		if fn == "" && e.URL != "" {
			parts := strings.Split(e.URL, "/")
			fn = parts[len(parts)-1]
		}
		if e.Version != "" {
			return fmt.Sprintf("binaries/%s/%s/%s", e.Name, e.Version, fn)
		}
		return fmt.Sprintf("binaries/%s/%s", e.Name, fn)
	case manifest.TypeApt:
		return "packages/apt/"
	case manifest.TypePypi:
		return "pypi/wheels/"
	case manifest.TypeGomod:
		e := store.FindGomod(name)
		if e == nil {
			return ""
		}
		return fmt.Sprintf("gomod/%s/@v/%s.zip", e.Name, e.Version)
	case manifest.TypeHelm:
		e := store.FindHelm(name)
		if e == nil {
			return ""
		}
		return fmt.Sprintf("charts/%s-%s.tgz", e.Name, e.Version)
	case manifest.TypeNpm:
		e := store.FindNpm(name)
		if e == nil {
			return ""
		}
		return fmt.Sprintf("npm/%s/%s-%s.tgz", e.Name, e.Name, e.Version)
	}
	return ""
}

// clientURL returns the URL a client would use to fetch the artifact from the bodega server.
func clientURL(store *manifest.Store, entryType, name string) string {
	host := "<bodega-host>:8080"
	switch entryType {
	case manifest.TypeGit:
		e := store.FindGit(name)
		if e == nil {
			return ""
		}
		ext := ".bundle"
		if e.IsRelease() {
			ext = ".tar.gz"
		}
		sn := strings.ReplaceAll(e.Name, "/", "--")
		return fmt.Sprintf("http://%s/git/%s/%s-%s%s", host, sn, sn, e.Ref, ext)
	case manifest.TypeBinary:
		e := store.FindBinary(name)
		if e == nil {
			return ""
		}
		fn := e.Filename
		if fn == "" && e.URL != "" {
			parts := strings.Split(e.URL, "/")
			fn = parts[len(parts)-1]
		}
		return fmt.Sprintf("http://%s/binaries/%s/%s/%s", host, e.Name, e.Version, fn)
	case manifest.TypeApt:
		return fmt.Sprintf("deb [trusted=yes] http://%s/apt/ noble main", host)
	case manifest.TypePypi:
		return fmt.Sprintf("pip install --index-url http://%s/pypi/simple/ %s", host, name)
	case manifest.TypeGomod:
		return fmt.Sprintf("GOPROXY=http://%s/go,direct go get %s", host, name)
	case manifest.TypeHelm:
		e := store.FindHelm(name)
		if e == nil {
			return ""
		}
		return fmt.Sprintf("http://%s/helm/charts/%s-%s.tgz", host, e.Name, e.Version)
	case manifest.TypeNpm:
		return fmt.Sprintf("npm install --registry http://%s/npm/ %s", host, name)
	}
	return ""
}

func (m detailsModel) renderGroupDetails() string {
	var sb strings.Builder
	n := m.node

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

	// Top-level type group.
	sb.WriteString(field("Type", n.EntryType+"/"))
	sb.WriteByte('\n')

	switch n.EntryType {
	case manifest.TypeApt:
		sb.WriteString(field("Packages", fmt.Sprintf("%d", len(m.store.Apt))))
	case manifest.TypeGit:
		sb.WriteString(field("Packages", fmt.Sprintf("%d", len(m.store.Git))))
	case manifest.TypePypi:
		if m.store.Pypi.Version != "" {
			sb.WriteString(field("Version", m.store.Pypi.Version))
			sb.WriteByte('\n')
		}
		sb.WriteString(field("Packages", fmt.Sprintf("%d", len(m.store.Pypi.Packages))))
	case manifest.TypeBinary:
		sb.WriteString(field("Packages", fmt.Sprintf("%d", len(m.store.Binary))))
	case manifest.TypeGomod:
		sb.WriteString(field("Packages", fmt.Sprintf("%d", len(m.store.Gomod))))
	case manifest.TypeHelm:
		sb.WriteString(field("Packages", fmt.Sprintf("%d", len(m.store.Helm))))
	case manifest.TypeNpm:
		sb.WriteString(field("Packages", fmt.Sprintf("%d", len(m.store.Npm))))
	}

	return sb.String()
}

// packageDescription returns a cached description for a package, or empty string.
// Descriptions are stored on manifest entries via the Description field.
func (m detailsModel) packageDescription(entryType, name string) string {
	switch entryType {
	case manifest.TypeGit:
		e := m.store.FindGit(name)
		if e != nil {
			return e.Description
		}
	case manifest.TypePypi:
		p := m.store.FindPypiPackage(name)
		if p != nil {
			return p.Description
		}
	case manifest.TypeBinary:
		e := m.store.FindBinary(name)
		if e != nil {
			return e.Description
		}
	case manifest.TypeGomod:
		e := m.store.FindGomod(name)
		if e != nil {
			return e.Description
		}
	case manifest.TypeHelm:
		e := m.store.FindHelm(name)
		if e != nil {
			return e.Description
		}
	case manifest.TypeNpm:
		e := m.store.FindNpm(name)
		if e != nil {
			return e.Description
		}
	case manifest.TypeApt:
		e := m.store.FindApt(name)
		if e != nil {
			return e.Description
		}
	}
	return ""
}

func (m detailsModel) renderEntryDetails() string {
	n := m.node
	if n == nil {
		return ""
	}

	var sb strings.Builder

	switch n.EntryType {
	case manifest.TypeApt:
		e := m.store.FindApt(n.Name)
		if e == nil {
			return errorStyle.Render("entry not found")
		}
		sb.WriteString(field("Name", e.Name))
		sb.WriteByte('\n')
		if e.Version != "" {
			sb.WriteString(field("Version", e.Version))
			sb.WriteByte('\n')
		}
		if e.SourceName != "" {
			sb.WriteString(field("SourceName", e.SourceName))
			sb.WriteByte('\n')
		}
		if e.URL != "" {
			sb.WriteString(field("URL", wrap(e.URL, m.width-16)))
			sb.WriteByte('\n')
		}
		if e.BuildCmd != "" {
			sb.WriteString(field("BuildCmd", e.BuildCmd))
			sb.WriteByte('\n')
		}
		if e.DebGlob != "" {
			sb.WriteString(field("DebGlob", e.DebGlob))
			sb.WriteByte('\n')
		}
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(e.Platform, e.BuildEnv))

	case manifest.TypeGit:
		e := m.store.FindGit(n.Name)
		if e == nil {
			return errorStyle.Render("entry not found")
		}
		sb.WriteString(field("Name", e.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Ref", e.Ref))
		sb.WriteByte('\n')
		sb.WriteString(field("URL", wrap(e.URL, m.width-16)))
		sb.WriteByte('\n')
		sb.WriteString(checksumFields(e.Checksum, e.ChecksumVerified))
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(e.Platform, e.BuildEnv))
		// Show discovered dependency files.
		if deps := m.discoverGitDeps(e); deps != "" {
			sb.WriteByte('\n')
			sb.WriteString(deps)
		}
		// Show packages that depend on this git entry.
		if depList := m.dependentsOf(e.Name); depList != "" {
			sb.WriteByte('\n')
			sb.WriteString(depList)
		}

	case manifest.TypePypi:
		sb.WriteString(field("Name", n.Name))
		sb.WriteByte('\n')

		// Find the package entry to get required_by.
		var pkg *manifest.PypiPackage
		for i := range m.store.Pypi.Packages {
			if m.store.Pypi.Packages[i].Name == n.Name {
				pkg = &m.store.Pypi.Packages[i]
				break
			}
		}

		if pkg != nil && len(pkg.RequiredBy) > 0 {
			sb.WriteString(field("Required by", strings.Join(pkg.RequiredBy, ", ")))
			sb.WriteByte('\n')
		}

		// Load dep graph for version and dependency details.
		var depGraph *builder.PypiDepGraph
		if m.buildRoot != "" {
			wheelsDir := filepath.Join(m.buildRoot, "wheels")
			if m.store.Pypi.Version != "" {
				wheelsDir = filepath.Join(wheelsDir, m.store.Pypi.Version)
			}
			depGraph, _ = builder.LoadDepGraph(filepath.Join(wheelsDir, "dep-graph.json"))
		}

		if depGraph != nil {
			for _, pkg := range depGraph.Packages {
				if strings.EqualFold(pkg.Name, n.Name) {
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

		sb.WriteString(boolField("Frozen", m.store.Pypi.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		if pkg != nil {
			sb.WriteString(platformAndBuildEnv(pkg.Platform, pkg.BuildEnv))
		}

	case manifest.TypeBinary:
		e := m.store.FindBinary(n.Name)
		if e == nil {
			return errorStyle.Render("entry not found")
		}
		sb.WriteString(field("Name", e.Name))
		sb.WriteByte('\n')
		if e.Version != "" {
			sb.WriteString(field("Version", e.Version))
			sb.WriteByte('\n')
		}
		sb.WriteString(field("URL", wrap(e.URL, m.width-16)))
		sb.WriteByte('\n')
		if e.Filename != "" {
			sb.WriteString(field("Filename", e.Filename))
			sb.WriteByte('\n')
		}
		if e.SHA256 != nil && *e.SHA256 != "" {
			sb.WriteString(field("SHA256", *e.SHA256))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(e.Checksum, e.ChecksumVerified))
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(e.Platform, e.BuildEnv))

	case manifest.TypeGomod:
		e := m.store.FindGomod(n.Name)
		if e == nil {
			return errorStyle.Render("entry not found")
		}
		sb.WriteString(field("Module", e.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Version", e.Version))
		sb.WriteByte('\n')
		if e.URL != "" {
			sb.WriteString(field("Upstream", e.URL))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(e.Checksum, e.ChecksumVerified))
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(e.Platform, e.BuildEnv))

	case manifest.TypeHelm:
		e := m.store.FindHelm(n.Name)
		if e == nil {
			return errorStyle.Render("entry not found")
		}
		sb.WriteString(field("Chart", e.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Version", e.Version))
		sb.WriteByte('\n')
		sb.WriteString(field("URL", wrap(e.URL, m.width-16)))
		sb.WriteByte('\n')
		if e.AppVersion != "" {
			sb.WriteString(field("App Version", e.AppVersion))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(e.Checksum, e.ChecksumVerified))
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(e.Platform, e.BuildEnv))

	case manifest.TypeNpm:
		e := m.store.FindNpm(n.Name)
		if e == nil {
			return errorStyle.Render("entry not found")
		}
		sb.WriteString(field("Package", e.Name))
		sb.WriteByte('\n')
		sb.WriteString(field("Version", e.Version))
		sb.WriteByte('\n')
		if e.URL != "" {
			sb.WriteString(field("Registry", e.URL))
			sb.WriteByte('\n')
		}
		sb.WriteString(checksumFields(e.Checksum, e.ChecksumVerified))
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(e.Platform, e.BuildEnv))
	}

	// Append raw JSON below the parsed fields.
	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("── Raw JSON ──"))
	sb.WriteByte('\n')
	if raw := m.rawJSON(n); raw != "" {
		sb.WriteString(dimStyle.Render(raw))
	}

	return sb.String()
}

// rawJSON returns the pretty-printed JSON for the entry matching the given node.
func (m detailsModel) rawJSON(n *TreeNode) string {
	var v interface{}
	switch n.EntryType {
	case manifest.TypeApt:
		v = m.store.FindApt(n.Name)
	case manifest.TypeGit:
		v = m.store.FindGit(n.Name)
	case manifest.TypeBinary:
		v = m.store.FindBinary(n.Name)
	case manifest.TypePypi:
		// Show only the individual package, not the full manifest.
		for i := range m.store.Pypi.Packages {
			if m.store.Pypi.Packages[i].Name == n.Name {
				v = m.store.Pypi.Packages[i]
				break
			}
		}
	case manifest.TypeGomod:
		v = m.store.FindGomod(n.Name)
	case manifest.TypeHelm:
		v = m.store.FindHelm(n.Name)
	case manifest.TypeNpm:
		v = m.store.FindNpm(n.Name)
	}
	if v == nil {
		return ""
	}
	data, err := json.MarshalIndent(v, "", "  ")
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
