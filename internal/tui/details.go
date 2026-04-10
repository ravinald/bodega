package tui

import (
	"context"
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

// s3Path returns the S3 object key for the given entry (first version).
func s3Path(cfg *config.Config, store *manifest.Store, entryType, name string) string {
	ctx := context.Background()
	pm, err := store.GetPackage(ctx, entryType, name)
	if err != nil || pm == nil || len(pm.Versions) == 0 {
		switch entryType {
		case manifest.TypeApt:
			return "packages/apt/"
		case manifest.TypePypi:
			return "pypi/wheels/"
		}
		return ""
	}
	ve := pm.Versions[0]
	switch entryType {
	case manifest.TypeGit:
		ext := ".bundle"
		if ve.IsRelease() {
			ext = ".tar.gz"
		}
		sn := strings.ReplaceAll(pm.Name, "/", "--")
		return fmt.Sprintf("repos/%s/%s-%s%s", sn, sn, ve.Ref, ext)
	case manifest.TypeBinary:
		fn := ve.Filename
		if fn == "" && ve.URL != "" {
			parts := strings.Split(ve.URL, "/")
			fn = parts[len(parts)-1]
		}
		if ve.Version != "" {
			return fmt.Sprintf("binaries/%s/%s/%s", pm.Name, ve.Version, fn)
		}
		return fmt.Sprintf("binaries/%s/%s", pm.Name, fn)
	case manifest.TypeApt:
		return "packages/apt/"
	case manifest.TypePypi:
		return "pypi/wheels/"
	case manifest.TypeGomod:
		return fmt.Sprintf("gomod/%s/@v/%s.zip", pm.Name, ve.Version)
	case manifest.TypeHelm:
		return fmt.Sprintf("charts/%s-%s.tgz", pm.Name, ve.Version)
	case manifest.TypeNpm:
		return fmt.Sprintf("npm/%s/%s-%s.tgz", pm.Name, pm.Name, ve.Version)
	}
	return ""
}

// clientURL returns the URL a client would use to fetch the artifact from the bodega server.
func clientURL(store *manifest.Store, entryType, name string) string {
	ctx := context.Background()
	host := "<bodega-host>:8080"
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
		return fmt.Sprintf("http://%s/git/%s/%s-%s%s", host, sn, sn, ve.Ref, ext)
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
		return fmt.Sprintf("http://%s/binaries/%s/%s/%s", host, pm.Name, ve.Version, fn)
	case manifest.TypeApt:
		return fmt.Sprintf("deb [trusted=yes] http://%s/apt/ noble main", host)
	case manifest.TypePypi:
		return fmt.Sprintf("pip install --index-url http://%s/pypi/simple/ %s", host, name)
	case manifest.TypeGomod:
		return fmt.Sprintf("GOPROXY=http://%s/go,direct go get %s", host, name)
	case manifest.TypeHelm:
		if err != nil || pm == nil || len(pm.Versions) == 0 {
			return ""
		}
		ve := pm.Versions[0]
		return fmt.Sprintf("http://%s/helm/charts/%s-%s.tgz", host, pm.Name, ve.Version)
	case manifest.TypeNpm:
		return fmt.Sprintf("npm install --registry http://%s/npm/ %s", host, name)
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

// store_ListPackages is a helper to list packages for a type.
func store_ListPackages(store *manifest.Store, _ context.Context, typ string) []string {
	return store.ListPackages(typ)
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
	ve := pm.Versions[0]

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
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))

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
		sb.WriteString(m.s3AndClientFields(n))
		sb.WriteString(platformAndBuildEnv(ve.Platform, ve.BuildEnv))
	}

	// Append raw JSON below the parsed fields.
	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("── Package JSON Config ──"))
	sb.WriteByte('\n')
	if raw := m.rawJSON(n); raw != "" {
		sb.WriteString(dimStyle.Render(raw))
	}

	return sb.String()
}

// rawJSON returns the pretty-printed JSON for the package manifest matching the given node.
func (m detailsModel) rawJSON(n *TreeNode) string {
	ctx := context.Background()
	pm, err := m.store.GetPackage(ctx, n.EntryType, n.Name)
	if err != nil || pm == nil {
		return ""
	}
	data, err := json.MarshalIndent(pm, "", "  ")
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
