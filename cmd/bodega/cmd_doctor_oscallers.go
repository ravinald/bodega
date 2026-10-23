package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/host"
)

// quietStep is one change a --quiet-* flag makes, printed under row, with an
// undo fixed rather than recorded: a step is planned only when the host is
// not already in the quiet state, so the undo returns it to what it was.
type quietStep struct {
	row      string
	do, undo []string
}

// stepRecord is the file a --quiet-* flag writes and its --restore-* flag
// reads: the names of the steps that ran, which is the whole of what the
// restore undoes.
type stepRecord struct {
	path        string
	steps       map[string]quietStep
	quietFlag   string
	restoreFlag string
	what        string // the steps' subject, for errors
	run         func(argv []string) (string, error)
}

type proRecord struct {
	Steps []string `json:"steps"`
}

// shellJoin prints argv so it pastes into a shell as the same argv.
func shellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./=:@%+-") == "" {
			out[i] = a
			continue
		}
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(out, " ")
}

// printPlan writes the steps into the plan output, each beside its undo,
// before anything is written. none prefixes the line saying why there are
// none.
func (r stepRecord) printPlan(steps []string, why, none string) {
	if len(steps) == 0 {
		fmt.Printf("\n%s  nothing to quiet: %s\n", none, why)
		return
	}
	fmt.Println()
	for _, s := range steps {
		st := r.steps[s]
		fmt.Printf("%s  %s  (undo: %s)\n", st.row, shellJoin(st.do), shellJoin(st.undo))
	}
}

// quiet runs steps and adds each one that succeeded to the record, so a run
// that fails halfway can still be undone for the part it changed.
func (r stepRecord) quiet(steps []string) error {
	rec, err := r.load()
	if err != nil {
		return err
	}
	var runErr error
	for _, s := range steps {
		argv := r.steps[s].do
		if out, err := r.run(argv); err != nil {
			runErr = fmt.Errorf("%s failed (%v): %s; nothing after it ran. Re-run as root", shellJoin(argv), err, out)
			break
		}
		fmt.Printf("ran        %s\n", shellJoin(argv))
		if !slices.Contains(rec.Steps, s) {
			rec.Steps = append(rec.Steps, s)
		}
	}
	if err := r.save(rec); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

// restore undoes the recorded steps and nothing else, and deletes the record
// once every undo succeeded.
func (r stepRecord) restore() error {
	rec, err := r.load()
	if err != nil {
		return err
	}
	if len(rec.Steps) == 0 {
		fmt.Printf("Nothing to restore: %s records no step %s ran on this host.\n", r.path, r.quietFlag)
		return nil
	}
	for len(rec.Steps) > 0 {
		argv := r.steps[rec.Steps[0]].undo
		if out, err := r.run(argv); err != nil {
			return errors.Join(
				fmt.Errorf("%s failed (%v): %s. Re-run as root; %s still records what is left", shellJoin(argv), err, out, r.path),
				r.save(rec))
		}
		fmt.Printf("ran        %s\n", shellJoin(argv))
		rec.Steps = rec.Steps[1:]
	}
	if err := os.Remove(r.path); err != nil {
		return fmt.Errorf("every step was undone, and removing %s failed: %w", r.path, err)
	}
	return nil
}

func (r stepRecord) load() (proRecord, error) {
	var rec proRecord
	b, err := os.ReadFile(r.path)
	if errors.Is(err, fs.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return rec, fmt.Errorf("read %s: %w", r.path, err)
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("%s is not the record %s writes (%v); move it aside, then re-run", r.path, r.quietFlag, err)
	}
	for _, s := range rec.Steps {
		if _, ok := r.steps[s]; !ok {
			return rec, fmt.Errorf("%s names a step this doctor does not know, %q; move it aside, then re-run", r.path, s)
		}
	}
	return rec, nil
}

func (r stepRecord) save(rec proRecord) error {
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(r.path), err)
	}
	if err := os.WriteFile(r.path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("record the %s in %s: %w; undo them by hand with the commands printed above", r.what, r.path, err)
	}
	return nil
}

const motdNewsDefaults = "/etc/default/motd-news"

const (
	oscStepMotdNews  = "motd-news"
	oscStepMotdTimer = "motd-news.timer"
	oscStepSnapHold  = "snap-refresh-hold"
)

var osCallerSteps = map[string]quietStep{
	oscStepMotdNews: {
		row:  "motd-news",
		do:   []string{"sed", "-i", "s/^[[:space:]]*ENABLED=.*/ENABLED=0/", motdNewsDefaults},
		undo: []string{"sed", "-i", "s/^[[:space:]]*ENABLED=.*/ENABLED=1/", motdNewsDefaults},
	},
	oscStepMotdTimer: {
		row:  "motd-news",
		do:   []string{"systemctl", "disable", "--now", "motd-news.timer"},
		undo: []string{"systemctl", "enable", "--now", "motd-news.timer"},
	},
	oscStepSnapHold: {
		row:  "snapd-refresh",
		do:   []string{"snap", "refresh", "--hold"},
		undo: []string{"snap", "refresh", "--unhold"},
	},
}

// osCallersHost is the surface doctor reads for the OS services that reach
// out on their own whatever bodega serves. A struct so a test can point it at
// a fixture root, a scratch record and a scripted runner.
type osCallersHost struct {
	goos string
	// root prefixes every file read.
	root string
	// record holds the steps --quiet-os-callers ran.
	record string
	// run executes one local tool and returns its combined output.
	run func(argv []string) (string, error)
}

var osCallers = &osCallersHost{
	goos:   runtime.GOOS,
	root:   "/",
	record: "/etc/bodega/doctor-os-callers.json",
	run:    runLocalTool,
}

const localToolTimeout = 10 * time.Second

// runLocalTool runs systemctl and snap, which answer from the host's own
// state; the bound is there so a wedged systemd cannot hang a report.
func runLocalTool(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(backgroundCtx(), localToolTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("no answer within %s, %w: %w", localToolTimeout, ctx.Err(), err)
	}
	return strings.TrimSpace(string(out)), err
}

func (h *osCallersHost) ledger() stepRecord {
	return stepRecord{
		path: h.record, steps: osCallerSteps, run: h.run,
		quietFlag: "--quiet-os-callers", restoreFlag: "--restore-os-callers", what: "OS caller steps",
	}
}

func (h *osCallersHost) path(p string) string { return filepath.Join(h.root, p) }

func (h *osCallersHost) exists(p string) bool {
	_, err := os.Stat(h.path(p))
	return err == nil
}

// unitState is systemctl's one-word answer. is-enabled and is-active exit
// non-zero for every state but the one they ask about, so the answer is the
// output and the exit status says nothing more.
func (h *osCallersHost) unitState(verb, unit string) string {
	out, _ := h.run([]string{"systemctl", verb, unit})
	return out
}

// findings reports a row per caller that is active on this host, and none for
// one that is absent or off. internal names the hosts chrony may take time
// from without calling out: the bodega server and any the operator names.
// Every row is read from files and systemctl, never the network, so it
// answers on a host whose egress reaches only bodega.
func (h *osCallersHost) findings(internal []string) []host.Finding {
	if h.goos != "linux" {
		return nil
	}
	var out []host.Finding
	for _, check := range []func() (host.Finding, bool){
		func() (host.Finding, bool) { return h.chronyNTS(internal) },
		h.motdNews,
		h.snapdRefresh,
	} {
		if f, ok := check(); ok {
			out = append(out, f)
		}
	}
	return out
}

var chronyConfs = []string{"/etc/chrony/chrony.conf", "/etc/chrony.conf"}

func (h *osCallersHost) chronyNTS(internal []string) (host.Finding, bool) {
	f := host.Finding{Check: "chrony-nts"}
	if !h.exists("/usr/sbin/chronyd") {
		return f, false
	}
	var conf string
	for _, c := range chronyConfs {
		if h.exists(c) {
			conf = c
			break
		}
	}
	if conf == "" {
		return f, false
	}
	sources, err := h.chronySources(conf)
	if err != nil {
		f.Status = host.StatusSkip
		f.Detail = "could not read chrony's sources: " + err.Error()
		f.Remediation = skipRemedy(h.path(conf), err)
		return f, true
	}
	var nts []string
	for _, s := range sources {
		if slices.ContainsFunc(internal, func(i string) bool { return strings.EqualFold(i, s.host) }) {
			return f, false
		}
		if s.nts {
			nts = append(nts, s.host)
		}
	}
	if len(nts) == 0 {
		return f, false
	}
	f.Status = host.StatusWarn
	f.Detail = "chrony takes time over NTS from " + strings.Join(nts, ", ") +
		", whose key exchange is TCP 4460; a host that cannot reach them keeps no time at all, " +
		"which surfaces later as TLS failures and apt Valid-Until errors that look like bodega's"
	f.Remediation = "point chrony at an internal NTP server (server <host> iburst in " + conf +
		" or a file under its sourcedir, then systemctl restart chrony), or allow TCP 4460 to the NTS servers; " +
		"bodega doctor --ntp-server <host> names an internal one this row accepts"
	return f, true
}

type chronySource struct {
	host string
	nts  bool
}

// chronySources reads the server, pool and peer directives in conf and every
// file it pulls in through include, confdir (*.conf) and sourcedir
// (*.sources). A directory that does not exist contributes nothing:
// Ubuntu's chrony.conf names /run/chrony-dhcp, which only DHCP creates.
func (h *osCallersHost) chronySources(conf string) ([]chronySource, error) {
	var sources []chronySource
	seen := map[string]bool{}
	var read func(p string) error
	read = func(p string) error {
		if seen[p] {
			return nil
		}
		seen[p] = true
		fh, err := os.Open(h.path(p))
		if err != nil {
			return err
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 0 || strings.ContainsAny(fields[0][:1], "#!;%") {
				continue
			}
			var more []string
			switch strings.ToLower(fields[0]) {
			case "server", "pool", "peer":
				if len(fields) > 1 {
					sources = append(sources, chronySource{host: fields[1], nts: slices.Contains(fields[2:], "nts")})
				}
			case "include":
				for _, pat := range fields[1:] {
					m, _ := filepath.Glob(h.path(pat))
					more = append(more, h.unroot(m)...)
				}
			case "confdir", "sourcedir":
				ext := ".conf"
				if strings.EqualFold(fields[0], "sourcedir") {
					ext = ".sources"
				}
				for _, dir := range fields[1:] {
					m, _ := filepath.Glob(filepath.Join(h.path(dir), "*"+ext))
					more = append(more, h.unroot(m)...)
				}
			}
			for _, m := range more {
				if err := read(m); err != nil {
					return err
				}
			}
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("read %s: %w", h.path(p), err)
		}
		return nil
	}
	return sources, read(conf)
}

func (h *osCallersHost) unroot(paths []string) []string {
	for i, p := range paths {
		if rel, err := filepath.Rel(h.root, p); err == nil {
			paths[i] = "/" + rel
		}
	}
	return paths
}

// motdEnabled reports whether /etc/default/motd-news turns the fetch on,
// read the way 50-motd-news sources it: the last ENABLED wins.
func (h *osCallersHost) motdEnabled() (bool, error) {
	b, err := os.ReadFile(h.path(motdNewsDefaults))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	enabled := false
	for line := range strings.Lines(string(b)) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && k == "ENABLED" {
			enabled = strings.Trim(strings.TrimSpace(v), `"'`) == "1"
		}
	}
	return enabled, nil
}

func (h *osCallersHost) motdNews() (host.Finding, bool) {
	f := host.Finding{Check: "motd-news"}
	enabled, err := h.motdEnabled()
	if err != nil {
		f.Status = host.StatusSkip
		f.Detail = "could not read " + h.path(motdNewsDefaults) + ": " + err.Error()
		f.Remediation = skipRemedy(h.path(motdNewsDefaults), err)
		return f, true
	}
	timer := h.unitState("is-enabled", "motd-news.timer") == "enabled"
	if !enabled && !timer {
		return f, false
	}
	var why []string
	if enabled {
		why = append(why, motdNewsDefaults+" has ENABLED=1")
	}
	if timer {
		why = append(why, "motd-news.timer is enabled")
	}
	f.Status = host.StatusWarn
	f.Detail = strings.Join(why, " and ") + "; motd-news.service fetches motd.ubuntu.com over HTTPS twice a day"
	f.Remediation = "set ENABLED=0 in " + motdNewsDefaults + " and systemctl disable --now motd-news.timer, " +
		"or bodega doctor --configure <system> --quiet-os-callers --apply, which records both for --restore-os-callers"
	return f, true
}

var snapdBinaries = []string{"/usr/lib/snapd/snapd", "/usr/libexec/snapd/snapd"}

// snapdActive counts the socket as well as the service: with no snaps
// installed snapd goes to standby seconds after boot, once it has asked the
// store, and the socket starts it again on demand.
func (h *osCallersHost) snapdActive() bool {
	if !slices.ContainsFunc(snapdBinaries, h.exists) {
		return false
	}
	return h.unitState("is-active", "snapd.service") == "active" || h.unitState("is-active", "snapd.socket") == "active"
}

func (h *osCallersHost) snapdRefresh() (host.Finding, bool) {
	f := host.Finding{Check: "snapd-refresh"}
	if !h.snapdActive() {
		return f, false
	}
	f.Status = host.StatusWarn
	f.Detail = "snapd is active (its service, or the socket that starts it) and checks api.snapcraft.io for refreshes on its own schedule, whatever bodega serves"
	f.Remediation = "snap refresh --hold to stop the refresh checks; to keep snaps current from inside the network, " +
		"run a Snap Store Proxy and point snapd at it with snap set system proxy.store=<store-id>. " +
		"bodega doctor --configure <system> --quiet-os-callers --apply runs the hold and records it for --restore-os-callers"
	return f, true
}

// quietSteps plans what --quiet-os-callers changes on this host, and leaves
// out a step whose end state the host already has, so the record never
// claims a change somebody else made. chrony is never in it: which time
// source a host trusts is the operator's to choose.
func (h *osCallersHost) quietSteps() (steps []string, why string, err error) {
	if h.goos != "linux" {
		return nil, "not a Linux host", nil
	}
	enabled, err := h.motdEnabled()
	if err != nil {
		return nil, "", fmt.Errorf("--quiet-os-callers cannot read %s: %w", h.path(motdNewsDefaults), err)
	}
	if enabled {
		steps = append(steps, oscStepMotdNews)
	}
	if h.unitState("is-enabled", "motd-news.timer") == "enabled" {
		steps = append(steps, oscStepMotdTimer)
	}
	snapd := h.snapdActive()
	if snapd {
		out, err := h.run([]string{"snap", "refresh", "--time"})
		if err != nil {
			return nil, "", fmt.Errorf("--quiet-os-callers cannot read snapd's refresh hold: `snap refresh --time` failed (%v): %s", err, out)
		}
		if !heldForever(out) {
			steps = append(steps, oscStepSnapHold)
		}
	}
	if len(steps) == 0 {
		why = "motd-news is off, and snapd is "
		if snapd {
			why += "already held"
		} else {
			why += "not active"
		}
	}
	return steps, why, nil
}

func heldForever(refreshTime string) bool {
	for line := range strings.Lines(refreshTime) {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "hold" && strings.TrimSpace(v) == "forever" {
			return true
		}
	}
	return false
}

// internalTimeSources is what the chrony-nts row accepts as a time source
// inside the network: the bodega server, from --url or public_url, and every
// --ntp-server.
func internalTimeSources(gf *globalFlags, baseURL string, named []string) []string {
	if baseURL == "" {
		if cfg, err := loadConfig(gf); err == nil {
			baseURL = cfg.PublicURL
		}
	}
	if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
		named = append(named, u.Hostname())
	}
	return named
}
