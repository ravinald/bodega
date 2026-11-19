package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/aptsources"
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
		path: h.record, lookup: h.step, newestFirst: true,
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
	if _, err := h.ledger().load(); err != nil {
		return nil, err
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
		fmt.Printf("keep       %-10s %s:%d  %s %s; left in place\n", manifest.TypeApt, s.File, s.Line, clientconf.RedactLocations(strings.Join(s.URIs, " ")), why)
	}
	for _, file := range order {
		var disable []host.AptSource
		for _, s := range byFile[file] {
			switch {
			case s.Public != "":
				disable = append(disable, s)
			case !namesBodega(s.URIs):
				keep(s, "names neither a public archive nor bodega")
			}
		}
		if len(disable) == 0 {
			continue
		}
		lines := make([]int, len(disable))
		for i, s := range disable {
			lines[i] = s.Line
			how := "comments the line out"
			switch {
			case s.Deb822 && s.SetsEnabled:
				how = "sets Enabled: no"
			case s.Deb822:
				how = "adds Enabled: no"
			}
			fmt.Printf("disable    %-10s %s:%d  %s names %s; %s\n", manifest.TypeApt, s.File, s.Line, clientconf.RedactLocations(strings.Join(s.URIs, " ")), s.Public, how)
		}
		e, err := host.DisableAptSources(h.root, file, disable[0].Deb822, lines)
		if err != nil {
			return nil, fmt.Errorf("apt: %w", err)
		}
		steps = append(steps, e.Name())
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

// aptServedRoots asks the server where it serves each apt suite: the URI of
// the block /api/v1/status renders for it. A codename in an apt_archives
// archive is served under /apt/{archive}/ and nowhere else, which only the
// server's config knows.
func aptServedRoots(client *Client) (map[string]string, error) {
	var status struct {
		Apt struct {
			Sources []aptsources.Sources `json:"sources"`
		} `json:"apt"`
	}
	if err := getJSON(client, "/api/v1/status", &status); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, src := range status.Apt.Sources {
		if src.Suite != "" && src.URI != "" {
			out[src.Suite] = src.URI
		}
	}
	return out, nil
}

// aptRootPath is the path of an apt URI under bodega's apt tree, without a
// trailing slash: /apt, or /apt/{archive}. ok is false for any other path.
func aptRootPath(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", false
	}
	p := strings.TrimRight(u.Path, "/")
	return p, p == "/apt" || strings.HasPrefix(p, "/apt/")
}

// rootFinding folds into the apt-sources row whether each source naming
// bodega reads its suites from the root bodega serves them under. A codename
// moved into an apt_archives archive answers 404 at /apt/dists/, so a host
// whose sources predate the move stops receiving that suite at the next
// "apt-get update". Any root under /apt/ counts as bodega's; only a root
// that differs from the one served is reported.
//
// served is asked only when a source names bodega, so a host that reads
// nothing from bodega makes no request. A failure to ask leaves the row
// unable to say, which an OK row reports as a skip and a WARN row adds to
// what it already says. A certificate that did not verify is the exception:
// the trust check measures that against the stores apt reads and remedies it
// with --ca-file, which a token cannot, and it judges only OK and WARN rows,
// so the row keeps its status and only notes what went unchecked.
func (h *aptSourcesHost) rootFinding(f host.Finding, base string, served func() (map[string]string, error)) host.Finding {
	if h.goos != "linux" || f.Check != "apt-sources" || (f.Status != host.StatusOK && f.Status != host.StatusWarn) {
		return f
	}
	b, err := url.Parse(base)
	if err != nil || b.Host == "" {
		return f
	}
	entries, err := clientconf.LoadAptSources(h.root)
	if err != nil {
		return f
	}
	defaultPort := map[string]int{"https": 443, "http": 80}
	wantPort := defaultPort[b.Scheme]
	if p, err := strconv.Atoi(b.Port()); err == nil {
		wantPort = p
	}
	type bodegaSource struct {
		entry clientconf.AptSourceEntry
		uri   string
		root  string
	}
	var ours []bodegaSource
	for _, e := range entries {
		for _, uri := range e.URIs {
			access, hostname, port := clientconf.AptURIHost(uri)
			if port == 0 {
				port = defaultPort[access]
			}
			root, ok := aptRootPath(uri)
			if ok && strings.EqualFold(hostname, b.Hostname()) && port == wantPort {
				ours = append(ours, bodegaSource{entry: e, uri: uri, root: root})
			}
		}
	}
	if len(ours) == 0 {
		return f
	}
	roots, err := served()
	if err != nil {
		unchecked := "whether each apt source naming bodega reads its suites from the root bodega serves them under is unchecked: " + err.Error()
		remedy := "pass --token with a read-scope token (or bind this host's address with bodega identity bind cidr), and --url naming the server, then re-run doctor"
		var cert *tls.CertificateVerificationError
		switch {
		case errors.As(err, &cert):
			f.Detail = strings.TrimPrefix(f.Detail+"; "+unchecked, "; ")
		case f.Status == host.StatusOK:
			f.Status = host.StatusSkip
			f.Detail = strings.TrimPrefix(f.Detail+"; "+unchecked, "; ")
			f.Remediation = remedy
		default:
			f.Detail = f.Detail + "; " + unchecked
			f.Remediation = strings.TrimPrefix(f.Remediation+"; "+remedy, "; ")
		}
		return f
	}
	isServed := func(suite string) bool { _, ok := roots[suite]; return ok }
	var moved, fixes []string
	for _, o := range ours {
		for _, suite := range o.entry.Suites {
			want, ok := roots[suite]
			if !ok {
				continue
			}
			if wantRoot, _ := aptRootPath(want); wantRoot == o.root {
				continue
			}
			file := strings.TrimPrefix(o.entry.File, strings.TrimRight(h.root, "/"))
			moved = append(moved, fmt.Sprintf("%s entry %d reads %s from %s, which bodega serves at %s and answers 404 for there", file, o.entry.Entry, suite, o.uri, want))
			// A vendor archive's own file is rewritten by naming the archive;
			// --suite there would make the vendor codename the host's main
			// stanza. bodega's own file is rewritten whole from its base,
			// since the plan refuses a pocket named on its own.
			codename := suite
			if b, ok := clientconf.AptPocketBase(suite, isServed); ok {
				codename = b
			}
			selects := "--suite " + codename
			if file == clientconf.AptArchiveSourcesPath(o.entry.Suites[0]) {
				selects = "--suite <this host's codename> --archive " + o.entry.Suites[0]
			}
			fix := fmt.Sprintf("bodega doctor --configure apt %s --apply --url %s", selects, strings.TrimRight(base, "/"))
			if !slices.Contains(fixes, fix) {
				fixes = append(fixes, fix)
			}
		}
	}
	if len(moved) == 0 {
		return f
	}
	detail := "apt sources name a root bodega no longer serves their suite under: " + strings.Join(moved, "; ")
	remedy := "rewrite bodega's sources from the server's plan: " + strings.Join(fixes, "; ")
	if f.Status == host.StatusWarn {
		f.Detail, f.Remediation = f.Detail+"; "+detail, f.Remediation+"; "+remedy
	} else {
		f.Status, f.Detail, f.Remediation = host.StatusWarn, detail, remedy
	}
	return f
}

// aptServedRootsAt is rootFinding's served for the server at base, bounded
// so a server that does not answer cannot hold the report.
func aptServedRootsAt(base, token string, allowPlaintext bool) func() (map[string]string, error) {
	return func() (map[string]string, error) {
		client, err := NewClient(base, token, allowPlaintext)
		if err != nil {
			return nil, err
		}
		client.HTTP.Timeout = 10 * time.Second
		return aptServedRoots(client)
	}
}
