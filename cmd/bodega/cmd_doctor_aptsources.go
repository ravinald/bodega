package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/manifest"
)

// aptSourcesHost is the apt sources --configure apt takes out of apt's path
// once bodega.sources serves the host: every source naming a public archive,
// so apt cannot fetch around bodega. A struct so a test can point it at a
// fixture root and a scratch record.
type aptSourcesHost struct {
	goos string
	// root prefixes every sources file read and edited.
	root string
	// record holds the edits --configure apt --apply made, which is the
	// whole of what --restore-apt-sources undoes.
	record string
}

var aptSources = &aptSourcesHost{
	goos:   runtime.GOOS,
	root:   "/",
	record: "/etc/bodega/doctor-apt-sources.json",
}

func (h *aptSourcesHost) ledger() stepRecord {
	return stepRecord{
		path: h.record, lookup: h.step,
		quietFlag: "--configure apt --apply", restoreFlag: "--restore-apt-sources", what: "apt source edits",
	}
}

// step resolves a recorded name, which carries the whole edit, so the
// restore needs nothing but the record.
func (h *aptSourcesHost) step(name string) (quietStep, bool) {
	e, err := host.ParseAptEdit(name)
	if err != nil {
		return quietStep{}, false
	}
	return quietStep{
		row:    e.String(),
		edit:   func() error { return e.Apply(h.root) },
		revert: func() error { return e.Revert(h.root) },
	}, true
}

// bodegaAptSources returns the target of the plan's bodega.sources, or ""
// when the plan writes none, and every apt target the plan writes.
func bodegaAptSources(changes []clientconf.Change) (string, []string) {
	var main string
	var targets []string
	for _, c := range changes {
		if c.Record.System != manifest.TypeApt {
			continue
		}
		targets = append(targets, c.Target)
		if strings.HasSuffix(c.Record.Path, clientconf.AptSourcesPath) {
			main = c.Target
		}
	}
	return main, targets
}

// plan names the edits that disable every public-archive source on this
// host, and prints each source it disables or leaves in place. written are
// the files the plan itself writes, never edited; baseURL is the bodega the
// host reads from, whose sources are neither disabled nor listed.
func (h *aptSourcesHost) plan(written []string, baseURL string) ([]string, error) {
	if h.goos != "linux" {
		return nil, nil
	}
	sources, err := host.AptSources(h.root)
	if err != nil {
		return nil, fmt.Errorf("apt: %w; nothing was written. Run doctor as root, or correct the source, then re-run", err)
	}
	rec, err := h.ledger().load()
	if err != nil {
		return nil, err
	}
	recorded := map[string]bool{}
	for _, s := range rec.Steps {
		if e, err := host.ParseAptEdit(s); err == nil {
			recorded[e.Path] = true
		}
	}
	bodegaHost := ""
	if u, err := url.Parse(baseURL); err == nil {
		bodegaHost = strings.ToLower(u.Hostname())
	}
	namesBodega := func(uris []string) bool {
		return slices.ContainsFunc(uris, func(uri string) bool {
			u, err := url.Parse(uri)
			return err == nil && bodegaHost != "" && strings.EqualFold(u.Hostname(), bodegaHost)
		})
	}

	var steps []string
	var order []string
	byFile := map[string][]host.AptSource{}
	for _, s := range sources {
		if slices.Contains(written, filepath.Join(h.root, s.File)) {
			continue
		}
		if _, seen := byFile[s.File]; !seen {
			order = append(order, s.File)
		}
		byFile[s.File] = append(byFile[s.File], s)
	}
	keep := func(s host.AptSource, why string) {
		fmt.Printf("keep       %-10s %s:%d  %s %s; left in place\n", manifest.TypeApt, s.File, s.Line, strings.Join(s.URIs, " "), why)
	}
	for _, file := range order {
		var disable []host.AptSource
		for _, s := range byFile[file] {
			switch {
			case s.Public != "" && s.SetsEnabled:
				keep(s, "names "+s.Public+" and sets Enabled itself; set it to no by hand")
			case s.Public != "":
				disable = append(disable, s)
			case !namesBodega(s.URIs):
				keep(s, "names neither a public archive nor bodega")
			}
		}
		if len(disable) == 0 {
			continue
		}
		if recorded[file] {
			for _, s := range disable {
				keep(s, "names "+s.Public+", and "+h.record+" already records edits to this file; run bodega doctor --restore-apt-sources, then re-run")
			}
			continue
		}
		lines := make([]int, len(disable))
		how := "comments the line out"
		if disable[0].Deb822 {
			how = "adds Enabled: no"
		}
		for i, s := range disable {
			lines[i] = s.Line
			fmt.Printf("disable    %-10s %s:%d  %s names %s; %s\n", manifest.TypeApt, s.File, s.Line, strings.Join(s.URIs, " "), s.Public, how)
		}
		steps = append(steps, host.DisableAptSources(file, disable[0].Deb822, lines).String())
	}
	if len(steps) > 0 {
		fmt.Printf("           (undo: bodega doctor --restore-apt-sources)\n")
	}
	return steps, nil
}

// aptUpdateAgainst is apt-get update reading only the sources file given,
// so it proves bodega serves this host before anything else is disabled.
// Error-Mode=any makes a failed fetch an error; without it apt-get update
// exits 0 on an index it could not download. List-Cleanup=0 keeps the lists
// of the sources it was told not to read.
func aptUpdateAgainst(sources string) []string {
	return []string{"apt-get", "update",
		"-o", "Dir::Etc::SourceList=" + sources,
		"-o", "Dir::Etc::SourceParts=-",
		"-o", "APT::Get::List-Cleanup=0",
		"-o", "APT::Update::Error-Mode=any"}
}
