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
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ravinald/bodega/internal/host"
)

// quietStep is one change a --quiet-* flag makes, printed under row, with an
// undo fixed rather than recorded: a step is planned only when the host is
// not already in the quiet state, so the undo returns it to what it was.
//
// A step that edits a file rather than running a tool sets edit and revert
// instead of do and undo, and row then names the edit.
type quietStep struct {
	row          string
	do, undo     []string
	edit, revert func() error
}

// stepRecord is the file a --quiet-* flag writes and its --restore-* flag
// reads: the names of the steps that ran, which is the whole of what the
// restore undoes.
type stepRecord struct {
	path  string
	steps map[string]quietStep
	// lookup resolves a step the map does not hold, for steps whose name
	// carries the change itself.
	lookup      func(name string) (quietStep, bool)
	quietFlag   string
	restoreFlag string
	what        string // the steps' subject, for errors
	// newestFirst undoes the last step recorded first, for steps that edit
	// a file a later step edited again and so read against its edit.
	newestFirst bool
	run         func(argv []string) (string, error)
}

type proRecord struct {
	Steps []string `json:"steps"`
}

func (r stepRecord) step(name string) (quietStep, bool) {
	if st, ok := r.steps[name]; ok {
		return st, true
	}
	if r.lookup != nil {
		return r.lookup(name)
	}
	return quietStep{}, false
}

// perform runs the step's change, or its undo, and returns what it ran.
func (r stepRecord) perform(st quietStep, undo bool) (string, error) {
	if st.edit != nil {
		if undo {
			return "revert " + st.row, st.revert()
		}
		return "edit " + st.row, st.edit()
	}
	argv := st.do
	if undo {
		argv = st.undo
	}
	if out, err := r.run(argv); err != nil {
		return shellJoin(argv), fmt.Errorf("%s failed (%v): %s", shellJoin(argv), err, out)
	}
	return shellJoin(argv), nil
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
		st, _ := r.step(s)
		if st.edit != nil {
			fmt.Printf("%s  (undo: bodega doctor %s)\n", st.row, r.restoreFlag)
			continue
		}
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
		st, _ := r.step(s)
		ran, err := r.perform(st, false)
		if err != nil {
			runErr = fmt.Errorf("%w; nothing after it ran. Re-run as root", err)
			break
		}
		fmt.Printf("ran        %s\n", ran)
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
		next := 0
		if r.newestFirst {
			next = len(rec.Steps) - 1
		}
		st, _ := r.step(rec.Steps[next])
		ran, err := r.perform(st, true)
		if err != nil {
			return errors.Join(
				fmt.Errorf("%w. Re-run as root; %s still records what is left", err, r.path),
				r.save(rec))
		}
		fmt.Printf("ran        %s\n", ran)
		rec.Steps = slices.Delete(rec.Steps, next, next+1)
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
		if _, ok := r.step(s); !ok {
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
		path: h.record, steps: osCallerSteps, lookup: h.releaseUpgradeStep, run: h.run,
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
// one that is absent or off, except release-upgrade-check, which reports OK
// and N/A rows as well. internal names the hosts chrony may take time
// from without calling out: the bodega server and any the operator names.
// Every row is read from files, systemctl and a snapd already running, never
// the network, so it answers on a host whose egress reaches only bodega.
func (h *osCallersHost) findings(internal []string) []host.Finding {
	if h.goos != "linux" {
		return nil
	}
	var out []host.Finding
	for _, check := range []func() (host.Finding, bool){
		func() (host.Finding, bool) { return h.chronyNTS(internal) },
		h.motdNews,
		h.snapdRefresh,
		h.releaseUpgradeCheck,
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
	if !h.chronyActive() {
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

// chronyActive asks for both unit names: Debian and Ubuntu call it chrony,
// RHEL and Fedora chronyd. A chrony that is installed but stopped, disabled
// or masked makes no NTS key exchange, so it has nothing to warn about.
func (h *osCallersHost) chronyActive() bool {
	if !h.exists("/usr/sbin/chronyd") {
		return false
	}
	return h.unitState("is-active", "chrony.service") == "active" || h.unitState("is-active", "chronyd.service") == "active"
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

// motdNews warns only when both halves are on: motd-news.service, which the
// timer alone starts, runs 50-motd-news --force, and the script exits before
// fetching unless ENABLED=1. A login runs it without --force and prints the
// cache, so either half off makes no request.
func (h *osCallersHost) motdNews() (host.Finding, bool) {
	f := host.Finding{Check: "motd-news"}
	enabled, err := h.motdEnabled()
	if err != nil {
		f.Status = host.StatusSkip
		f.Detail = "could not read " + h.path(motdNewsDefaults) + ": " + err.Error()
		f.Remediation = skipRemedy(h.path(motdNewsDefaults), err)
		return f, true
	}
	if !enabled || h.unitState("is-enabled", "motd-news.timer") != "enabled" {
		return f, false
	}
	f.Status = host.StatusWarn
	f.Detail = motdNewsDefaults + " has ENABLED=1 and motd-news.timer is enabled, and the fetch needs both; " +
		"motd-news.service fetches motd.ubuntu.com over HTTPS twice a day"
	f.Remediation = "set ENABLED=0 in " + motdNewsDefaults + " or systemctl disable --now motd-news.timer (either stops the fetch), " +
		"or bodega doctor --configure <system> --quiet-os-callers --apply, which does both and records them for --restore-os-callers"
	return f, true
}

var snapdBinaries = []string{"/usr/lib/snapd/snapd", "/usr/libexec/snapd/snapd"}

func (h *osCallersHost) snapdInstalled() bool { return slices.ContainsFunc(snapdBinaries, h.exists) }

// snapdState tells a running snapd from one in standby behind its socket:
// with no snaps installed snapd goes to standby seconds after boot, once it
// has asked the store, and the socket starts it again on demand. Only a
// running snapd can be asked anything without being woken.
func (h *osCallersHost) snapdState() (running, standby bool) {
	if !h.snapdInstalled() {
		return false, false
	}
	if h.unitState("is-active", "snapd.service") == "active" {
		return true, false
	}
	return false, h.unitState("is-active", "snapd.socket") == "active"
}

// holdRecorded reports whether the record says --quiet-os-callers applied
// the refresh hold. It is the only answer a standby snapd gives without being
// woken, and it cannot see a hold applied, or lifted, by hand.
func (h *osCallersHost) holdRecorded() (bool, error) {
	rec, err := h.ledger().load()
	if err != nil {
		return false, err
	}
	return slices.Contains(rec.Steps, oscStepSnapHold), nil
}

var snapRefreshTime = []string{"snap", "refresh", "--time", "--abs-time"}

// snapHoldWindow is how far out a refresh hold has to reach before the row
// treats snapd as quiet; a nearer one lapses and snapd asks the store again.
const snapHoldWindow = 30 * 24 * time.Hour

// snapdRefresh asks snapd for its hold only while snapd.service is running.
// The question goes to snapd's socket, and a snapd in standby that it wakes
// asks the store, which is the call this row exists to report. In standby the
// row reads the record --quiet-os-callers writes instead.
func (h *osCallersHost) snapdRefresh() (host.Finding, bool) {
	f := host.Finding{Check: "snapd-refresh"}
	running, standby := h.snapdState()
	if !running && !standby {
		return f, false
	}
	remedy := "snap refresh --hold to stop the refresh checks; to keep snaps current from inside the network, " +
		"run a Snap Store Proxy and point snapd at it with snap set system proxy.store=<store-id>. " +
		"bodega doctor --configure <system> --quiet-os-callers --apply runs the hold and records it for --restore-os-callers"
	record := h.ledger().path
	if standby {
		recorded, err := h.holdRecorded()
		if err != nil {
			f.Status = host.StatusSkip
			f.Detail = "snapd is in standby behind snapd.socket, so its refresh hold is read from " + record +
				" rather than by waking snapd, and that record could not be used: " + err.Error()
			f.Remediation = "make " + record + " readable JSON again, or move it aside, then re-run `bodega doctor`; " +
				"moved aside, its recorded steps are no longer undone by --restore-os-callers, and " +
				"bodega doctor --configure <system> --quiet-os-callers --apply records the hold again"
			return f, true
		}
		if recorded {
			return f, false
		}
		f.Status = host.StatusWarn
		f.Detail = "snapd is in standby behind snapd.socket, which starts it on demand to check api.snapcraft.io for refreshes; " +
			"a hold applied by hand cannot be seen without waking snapd, and " +
			"bodega doctor --configure <system> --quiet-os-callers --apply records the hold in " + record + " where this row can read it"
		f.Remediation = remedy
		return f, true
	}
	out, err := h.run(snapRefreshTime)
	if err != nil {
		f.Status = host.StatusSkip
		f.Detail = "could not read snapd's refresh hold: `" + shellJoin(snapRefreshTime) + "` failed (" + err.Error() + "): " + out
		f.Remediation = "run `" + shellJoin(snapRefreshTime) + "` to see why snapd did not answer, then re-run `bodega doctor`"
		return f, true
	}
	if snapHeld(out, time.Now()) {
		return f, false
	}
	f.Status = host.StatusWarn
	f.Detail = "snapd is running with no refresh hold reaching 30 days out, and checks api.snapcraft.io for refreshes on its own schedule, whatever bodega serves"
	if recorded, err := h.holdRecorded(); err == nil && recorded {
		f.Detail += "; " + record + " says bodega applied a hold and snapd now reports none, so it was lifted by hand or lapsed"
	}
	f.Remediation = remedy
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
	running, standby := h.snapdState()
	snapd := running || standby
	// A standby snapd whose hold the record already names is left asleep;
	// with no such record the operator has asked doctor to change snapd, so
	// waking it to read the hold is part of that.
	recorded := false
	if standby {
		recorded, _ = h.holdRecorded()
	}
	if snapd && !recorded {
		out, err := h.run(snapRefreshTime)
		if err != nil {
			return nil, "", fmt.Errorf("--quiet-os-callers cannot read snapd's refresh hold: `%s` failed (%v): %s", shellJoin(snapRefreshTime), err, out)
		}
		if !snapHeld(out, time.Now()) {
			steps = append(steps, oscStepSnapHold)
		}
	}
	prompt, err := h.readPrompt()
	if err != nil {
		return nil, "", fmt.Errorf("--quiet-os-callers cannot read %s: %w", h.path(releaseUpgrades), err)
	}
	if prompt.exists && !prompt.never() {
		steps = append(steps, prompt.stepName())
	}
	if len(steps) == 0 {
		why = "motd-news is off, and snapd is "
		switch {
		case recorded:
			why += "in standby with its refresh hold recorded in " + h.ledger().path
		case snapd:
			why += "already held"
		default:
			why += "not active"
		}
		if prompt.exists {
			why += "; the release-upgrade check is off"
		}
	}
	return steps, why, nil
}

// snapHeld reads the hold line of `snap refresh --time --abs-time`: forever,
// or an RFC 3339 time past snapHoldWindow from now. A hold already lapsed,
// or one snapd printed in a form this does not parse, is not a hold.
func snapHeld(refreshTime string, now time.Time) bool {
	for line := range strings.Lines(refreshTime) {
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(k) != "hold" {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "forever" {
			return true
		}
		t, err := time.Parse(time.RFC3339, v)
		return err == nil && t.After(now.Add(snapHoldWindow))
	}
	return false
}

const releaseUpgrades = "/etc/update-manager/release-upgrades"

// oscStepPrompt names the step that sets Prompt=never. A recorded name of
// oscStepPrompt+"="+v put back v; the bare name inserted a Prompt line the
// file did not have, and its undo removes that line. oscStepPromptDefault
// prepended defaultPrefix to a file with no [DEFAULT] header, where
// ConfigParser's DEFAULT section is implicit, and its undo strips that prefix.
const (
	oscStepPrompt        = "release-upgrade-prompt"
	oscStepPromptDefault = oscStepPrompt + "+default"
)

// defaultPrefix is what insertDefault puts before every byte of text, so
// whatever came first, a comment, another section or nothing, stays exactly as
// it was and removing the prefix gives the file back. Prompt takes the indent
// of text's first line that is not blank or a comment: any shallower and
// ConfigParser would read that line, a section header in a valid file, and
// everything up to the next shallower line as Prompt's continuation.
func defaultPrefix(text string) string {
	return "[DEFAULT]\n" + firstIndent(text) + "Prompt=never\n"
}

// cutDefaultPrefix gives back the text insertDefault was handed, when text is
// that text with defaultPrefix of it in front.
func cutDefaultPrefix(text string) (string, bool) {
	after, ok := strings.CutPrefix(text, "[DEFAULT]\n")
	if !ok {
		return "", false
	}
	_, rest, ok := strings.Cut(after, "\n")
	return rest, ok && text == defaultPrefix(rest)+rest
}

func firstIndent(text string) string {
	for line := range strings.Lines(text) {
		content := strings.TrimRightFunc(line, unicode.IsSpace)
		if v := strings.TrimSpace(content); v != "" && v[0] != '#' && v[0] != ';' {
			return leadingSpace(content)
		}
	}
	return ""
}

// promptSetting is the Prompt option of the [DEFAULT] section in
// release-upgrades, read the way ubuntu-release-upgrader's ConfigParser
// reads it: the key in any case and at any indent, = or : between key and
// value, # and ; comment lines, a header ending at its last ], and a line
// indented deeper than its option continuing that option's value. Offsets
// index text, so an edit replaces the value's bytes and nothing around them.
type promptSetting struct {
	exists bool
	text   string
	// joined is the first line's value and every continuation's, joined by
	// newlines, as ConfigParser stores it. value is what ConfigParser.get
	// returns: joined with its %(name)s references to other [DEFAULT] options
	// resolved, or joined unchanged when resolveErr says they do not resolve.
	joined, value string
	resolveErr    error
	// line is where the Prompt option's first line starts, or -1, and start
	// and end bound its value, continuations included.
	line, start, end int
	// below is where the line after the first [DEFAULT] header starts, or -1,
	// and indent is the indent of the first line under it that is not blank
	// or a comment.
	below  int
	indent string
	// headers and options count the section headers and option lines
	// ConfigParser reads, continuations excluded, so an edit can check that it
	// added or removed exactly what it meant to and turned no line into a
	// continuation.
	headers, options int
}

func (p promptSetting) found() bool { return p.line >= 0 }

// never is true only when what ConfigParser.get returns is never, in any
// case. The upgrader also skips the check at no, but doctor's contract is
// that only never is off, so no warns and --quiet-os-callers replaces it. A
// Prompt whose references do not resolve makes get raise, which is not a
// setting anybody chose, so it counts as on as well.
func (p promptSetting) never() bool {
	return p.found() && p.resolveErr == nil && strings.EqualFold(p.value, "never")
}

// raw is the value as the file spells it, which is what the restore writes
// back.
func (p promptSetting) raw() string { return p.text[p.start:p.end] }

func (p promptSetting) stepName() string {
	if !p.found() && p.below < 0 {
		return oscStepPromptDefault
	}
	if !p.found() {
		return oscStepPrompt
	}
	return oscStepPrompt + "=" + p.raw()
}

// shown is the setting as the row prints it. With no Prompt option the
// upgrader takes the default, normal, which checks for every release.
func (p promptSetting) shown() string {
	if !p.found() {
		return "no Prompt line, which means Prompt=normal"
	}
	shown := "Prompt=" + quoteMultiline(p.joined)
	switch {
	case p.resolveErr != nil:
		shown += ", which ConfigParser cannot resolve (" + p.resolveErr.Error() + ")"
	case p.value != p.joined:
		shown += ", which resolves to " + quoteMultiline(p.value)
	}
	return shown
}

// promptJoined is the stored value of a raw one, references unresolved:
// they name options of the file the raw value came from, and a recorded raw
// value is shown without it. Its continuations were indented past their
// option's indent, so past none at all here too.
func promptJoined(raw string) string {
	return parsePrompt("[DEFAULT]\nPrompt=" + raw).joined
}

func quoteMultiline(v string) string {
	if strings.ContainsAny(v, "\r\n") {
		return strconv.Quote(v)
	}
	return v
}

func leadingSpace(s string) string {
	return s[:len(s)-len(strings.TrimLeftFunc(s, unicode.IsSpace))]
}

func parsePrompt(text string) promptSetting {
	p := promptSetting{exists: true, text: text, line: -1, below: -1}
	defaults := map[string]string{}
	section, opt, inOption, inPrompt, underHeader := "", "", false, false, false
	indent, off := 0, 0
	for line := range strings.Lines(text) {
		lineOff := off
		off += len(line)
		content := strings.TrimRightFunc(line, unicode.IsSpace)
		v := strings.TrimSpace(content)
		if v == "" || v[0] == '#' || v[0] == ';' {
			// A blank line inside a value is part of it; a comment is not.
			if v == "" && opt != "" {
				defaults[opt] += "\n"
			}
			continue
		}
		lead := leadingSpace(content)
		cur := utf8.RuneCountInString(lead)
		if inOption && cur > indent {
			if opt != "" {
				defaults[opt] += "\n" + v
			}
			if inPrompt {
				p.end = lineOff + len(content)
			}
			continue
		}
		indent = cur
		if underHeader {
			p.indent, underHeader = lead, false
		}
		if j := strings.LastIndexByte(v, ']'); v[0] == '[' && j > 1 {
			section = v[1:j]
			p.headers++
			opt, inOption, inPrompt = "", false, false
			if section == "DEFAULT" && p.below < 0 {
				p.below, underHeader = off, true
			}
			continue
		}
		sep := strings.IndexAny(content, "=:")
		if sep < 0 || section == "" || strings.TrimSpace(content[:sep]) == "" {
			continue // ConfigParser refuses the file, so nothing reads Prompt
		}
		inOption, opt = true, ""
		p.options++
		if section == "DEFAULT" {
			opt = strings.ToLower(strings.TrimSpace(content[:sep]))
			defaults[opt] = strings.TrimSpace(content[sep+1:])
		}
		inPrompt = opt == "prompt"
		if !inPrompt {
			continue
		}
		p.line = lineOff
		p.start = lineOff + sep + 1 + len(leadingSpace(content[sep+1:]))
		p.end = lineOff + len(content)
	}
	for k, v := range defaults {
		defaults[k] = strings.TrimRightFunc(v, unicode.IsSpace)
	}
	p.joined = defaults["prompt"]
	p.value = p.joined
	if p.found() {
		if v, err := interpolate(p.joined, defaults, 1); err != nil {
			p.resolveErr = err
		} else {
			p.value = v
		}
	}
	return p
}

// maxInterpolationDepth is configparser's MAX_INTERPOLATION_DEPTH: a chain
// of references nested deeper, a cycle included, makes get raise.
const maxInterpolationDepth = 10

var interpolationRef = regexp.MustCompile(`^%\(([^)]+)\)s`)

// interpolate is configparser.BasicInterpolation over the [DEFAULT] options,
// which is all a get on DEFAULT consults: %% is a literal %, %(name)s is the
// option name, looked up lowercased, and resolved in turn when it holds a %.
func interpolate(rest string, defaults map[string]string, depth int) (string, error) {
	if depth > maxInterpolationDepth {
		return "", fmt.Errorf("references nest more than %d deep", maxInterpolationDepth)
	}
	var b strings.Builder
	for rest != "" {
		i := strings.IndexByte(rest, '%')
		if i < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:i])
		rest = rest[i:]
		if strings.HasPrefix(rest, "%%") {
			b.WriteByte('%')
			rest = rest[2:]
			continue
		}
		m := interpolationRef.FindStringSubmatch(rest)
		if m == nil {
			return "", fmt.Errorf("%q is not %%%% or a %%(name)s reference", rest)
		}
		rest = rest[len(m[0]):]
		v, ok := defaults[strings.ToLower(m[1])]
		if !ok {
			return "", fmt.Errorf("%%(%s)s names no [DEFAULT] option", m[1])
		}
		if strings.Contains(v, "%") {
			var err error
			if v, err = interpolate(v, defaults, depth+1); err != nil {
				return "", err
			}
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

func (h *osCallersHost) readPrompt() (promptSetting, error) {
	b, err := os.ReadFile(h.path(releaseUpgrades))
	if errors.Is(err, fs.ErrNotExist) {
		return promptSetting{line: -1, below: -1}, nil
	}
	if err != nil {
		return promptSetting{line: -1, below: -1}, err
	}
	return parsePrompt(string(b)), nil
}

// writePrompt replaces the file with text once a fresh parse of text gives check
// what it wants and reads the headers and options of was, changed by the
// counts the edit itself adds or removes, so an edit this parser and
// ConfigParser would read differently, or one that turns a line into a
// continuation, fails before anything is written.
func (h *osCallersHost) writePrompt(was promptSetting, text string, headers, options int, check func(promptSetting) bool, want string) error {
	got := parsePrompt(text)
	if !check(got) {
		return fmt.Errorf("editing %s would leave %s, not %s; the file is unchanged, so set it by hand",
			h.path(releaseUpgrades), got.shown(), want)
	}
	if got.headers != was.headers+headers || got.options != was.options+options {
		return fmt.Errorf("editing %s would read %d section header(s) and %d option(s) where %d and %d belong, "+
			"so a line would change meaning; the file is unchanged, so set it by hand",
			h.path(releaseUpgrades), got.headers, got.options, was.headers+headers, was.options+options)
	}
	return os.WriteFile(h.path(releaseUpgrades), []byte(text), 0o644)
}

// setPrompt replaces the Prompt value, continuations included, with to and
// nothing around it; to is a raw value, so a restore writes back every byte
// the edit took out.
func (h *osCallersHost) setPrompt(to string) error {
	p, err := h.readPrompt()
	if err != nil {
		return err
	}
	if !p.found() {
		return fmt.Errorf("%s has no Prompt line under [DEFAULT] to set to %s; add Prompt=%s under [DEFAULT], then re-run",
			h.path(releaseUpgrades), quoteMultiline(to), quoteMultiline(to))
	}
	return h.writePrompt(p, p.text[:p.start]+to+p.text[p.end:], 0, 0,
		func(got promptSetting) bool { return got.found() && got.raw() == to }, "Prompt="+quoteMultiline(promptJoined(to)))
}

// insertPrompt adds Prompt=never directly under [DEFAULT], and removePrompt
// takes the Prompt line out again, newline included, so the pair leaves the
// file as it was. The new line takes the indent of the line after it: any
// shallower and ConfigParser would read that line as a continuation of
// Prompt.
func (h *osCallersHost) insertPrompt() error {
	p, err := h.readPrompt()
	if err != nil {
		return err
	}
	if p.below < 0 {
		return fmt.Errorf("%s has no [DEFAULT] section to add Prompt=never to; set it by hand", h.path(releaseUpgrades))
	}
	add := p.indent + "Prompt=never\n"
	if !strings.HasSuffix(p.text[:p.below], "\n") {
		add = "\n" + p.indent + "Prompt=never"
	}
	return h.writePrompt(p, p.text[:p.below]+add+p.text[p.below:], 0, 1, promptSetting.never, "Prompt=never")
}

func (h *osCallersHost) removePrompt() error {
	p, err := h.readPrompt()
	if err != nil {
		return err
	}
	if !p.found() {
		return nil
	}
	from, to := p.line, len(p.text)
	if i := strings.IndexByte(p.text[p.end:], '\n'); i >= 0 {
		to = p.end + i + 1
	} else if from > 0 {
		from-- // the newline insertPrompt put before a header ending the file
	}
	return h.writePrompt(p, p.text[:from]+p.text[to:], 0, -1,
		func(got promptSetting) bool { return !got.found() }, "no Prompt line")
}

// insertDefault prepends defaultPrefix to a file whose DEFAULT section is
// implicit, and removeDefault strips it again. The removal refuses once the
// prefix is not the one the edit wrote, or once options were added under it,
// because removing the header would then hand those options to no section
// and ConfigParser would refuse the file.
func (h *osCallersHost) insertDefault() error {
	p, err := h.readPrompt()
	if err != nil {
		return err
	}
	if p.below >= 0 {
		return fmt.Errorf("%s gained a [DEFAULT] section after the plan was made; re-run --quiet-os-callers", h.path(releaseUpgrades))
	}
	return h.writePrompt(p, defaultPrefix(p.text)+p.text, 1, 1, promptSetting.never, "Prompt=never")
}

func (h *osCallersHost) removeDefault() error {
	p, err := h.readPrompt()
	if err != nil {
		return err
	}
	rest, ok := cutDefaultPrefix(p.text)
	if !ok {
		if !p.found() && p.below < 0 {
			return nil // already restored
		}
		return fmt.Errorf("%s no longer starts with the [DEFAULT] header and Prompt=never line --quiet-os-callers added; remove those lines by hand",
			h.path(releaseUpgrades))
	}
	if optionBeforeHeader(rest) {
		return fmt.Errorf("%s has options under the [DEFAULT] header --quiet-os-callers added; "+
			"remove the header and the Prompt=never line by hand, keeping those options under a section", h.path(releaseUpgrades))
	}
	return h.writePrompt(p, rest, -1, -1, func(got promptSetting) bool { return !got.found() && got.below < 0 }, "no [DEFAULT] header")
}

// optionBeforeHeader is true when a line before the first section header is
// anything but blank or a comment, which ConfigParser refuses.
func optionBeforeHeader(text string) bool {
	for line := range strings.Lines(text) {
		v := strings.TrimSpace(line)
		switch {
		case v == "" || v[0] == '#' || v[0] == ';':
		case v[0] == '[' && strings.LastIndexByte(v, ']') > 1:
			return false
		default:
			return true
		}
	}
	return false
}

// releaseUpgradeStep resolves a recorded oscStepPrompt name, which carries
// the value the step found, so the restore needs nothing but the record.
func (h *osCallersHost) releaseUpgradeStep(name string) (quietStep, bool) {
	if name == oscStepPromptDefault {
		return quietStep{
			row:  "release-upgrade-check  set Prompt=never in " + releaseUpgrades + ", found no [DEFAULT] header and no Prompt line",
			edit: h.insertDefault, revert: h.removeDefault,
		}, true
	}
	found, hadLine := strings.CutPrefix(name, oscStepPrompt+"=")
	if !hadLine && name != oscStepPrompt {
		return quietStep{}, false
	}
	st := quietStep{edit: func() error { return h.setPrompt("never") }}
	shown := "no Prompt line"
	if hadLine {
		shown = "Prompt=" + quoteMultiline(promptJoined(found))
		st.revert = func() error { return h.setPrompt(found) }
	} else {
		st.edit = h.insertPrompt
		st.revert = h.removePrompt
	}
	st.row = "release-upgrade-check  set Prompt=never in " + releaseUpgrades + ", found " + shown
	return st, true
}

// releaseUpgradeCheck reports ubuntu-release-upgrader's new-release check,
// which the update-notifier timers and the motd's release-upgrade fragment
// run against changelogs.ubuntu.com unless Prompt=never. It fetches no
// packages, so it never bypasses bodega; on a locked host it fails on every
// run and fills the drop log.
func (h *osCallersHost) releaseUpgradeCheck() (host.Finding, bool) {
	f := host.Finding{Check: "release-upgrade-check"}
	p, err := h.readPrompt()
	switch {
	case err != nil:
		f.Status = host.StatusSkip
		f.Detail = "could not read " + h.path(releaseUpgrades) + ": " + err.Error()
		f.Remediation = skipRemedy(h.path(releaseUpgrades), err)
	case !p.exists:
		f.Status = host.StatusNA
		f.Detail = "no " + releaseUpgrades + ", so ubuntu-release-upgrader is not installed"
	case p.never():
		f.Status = host.StatusOK
		f.Detail = releaseUpgrades + " has " + p.shown() + ", so the new-release check makes no request"
	default:
		f.Status = host.StatusWarn
		f.Detail = releaseUpgrades + " has " + p.shown() + ", so ubuntu-release-upgrader checks changelogs.ubuntu.com " +
			"for a new release from the update-notifier timers and the motd's release-upgrade fragment; " +
			"it fetches no packages, and on a host that cannot reach it the check fails every time and fills the drop log"
		f.Remediation = "set Prompt=never in " + releaseUpgrades + ", or bodega doctor --configure <system> --quiet-os-callers --apply, " +
			"which sets it and records the value it found for --restore-os-callers"
	}
	return f, true
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
