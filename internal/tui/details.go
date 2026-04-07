package tui

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/builder"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

// detailsModel is the bubbletea model for the top-right Details pane.
type detailsModel struct {
	node      *TreeNode
	store     *manifest.Store
	buildRoot string
	width     int
	height    int
	focused   bool
}

// newDetailsModel creates the details pane.
func newDetailsModel(store *manifest.Store, buildRoot string) detailsModel {
	return detailsModel{store: store, buildRoot: buildRoot}
}

// SetNode updates the node whose metadata is displayed.
func (m *detailsModel) SetNode(n *TreeNode) {
	m.node = n
}

// View renders the details pane content (without the outer border).
func (m detailsModel) View() string {
	if m.node == nil {
		return dimStyle.Render("  Select an entry in the Sources pane.")
	}
	if m.node.IsGroup {
		return m.renderGroupDetails()
	}
	return m.renderEntryDetails()
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

func (m detailsModel) renderGroupDetails() string {
	var sb strings.Builder
	n := m.node
	sb.WriteString(field("Type", n.EntryType+"/"))
	sb.WriteByte('\n')

	switch n.EntryType {
	case manifest.TypeApt:
		sb.WriteString(field("Entries", fmt.Sprintf("%d", len(m.store.Apt))))
	case manifest.TypeGit:
		sb.WriteString(field("Entries", fmt.Sprintf("%d", len(m.store.Git))))
	case manifest.TypePypi:
		sb.WriteString(field("Version", m.store.Pypi.Version))
		sb.WriteByte('\n')
		sb.WriteString(field("Packages", fmt.Sprintf("%d extra", len(m.store.Pypi.Packages))))
		sb.WriteByte('\n')
		sb.WriteString(boolField("Frozen", m.store.Pypi.Frozen))
	case manifest.TypeBinary:
		sb.WriteString(field("Entries", fmt.Sprintf("%d", len(m.store.Binary))))
	case manifest.TypeGomod:
		sb.WriteString(field("Entries", fmt.Sprintf("%d", len(m.store.Gomod))))
	case manifest.TypeHelm:
		sb.WriteString(field("Entries", fmt.Sprintf("%d", len(m.store.Helm))))
	case manifest.TypeNpm:
		sb.WriteString(field("Entries", fmt.Sprintf("%d", len(m.store.Npm))))
	}

	return sb.String()
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
		sb.WriteString(s3StatusField(n.InS3))

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
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(s3StatusField(n.InS3))

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
		sb.WriteString(s3StatusField(n.InS3))

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
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(s3StatusField(n.InS3))

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
		if e.Checksum != nil {
			sb.WriteString(field("Checksum", e.Checksum.Algorithm+":"+e.Checksum.Value))
			sb.WriteByte('\n')
		}
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(s3StatusField(n.InS3))

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
		if e.Checksum != nil {
			sb.WriteString(field("Checksum", e.Checksum.Algorithm+":"+e.Checksum.Value))
			sb.WriteByte('\n')
		}
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(s3StatusField(n.InS3))

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
		if e.Checksum != nil {
			sb.WriteString(field("Checksum", e.Checksum.Algorithm+":"+e.Checksum.Value))
			sb.WriteByte('\n')
		}
		sb.WriteString(boolField("Frozen", e.Frozen))
		sb.WriteByte('\n')
		sb.WriteString(s3StatusField(n.InS3))
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
