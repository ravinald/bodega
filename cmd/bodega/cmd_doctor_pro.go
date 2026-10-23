package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/host"
)

// esmHookConf is ubuntu-pro-client's apt hook. Its APT::Update::Pre-Invoke
// starts apt-news.service and esm-cache.service, and its AptCli upgrade hook
// runs apt-esm-json-hook; all three reach esm.ubuntu.com whatever the apt
// sources say, so a host reading apt only from bodega still calls out on every
// update.
const esmHookConf = "/etc/apt/apt.conf.d/20apt-esm-hook.conf"

// Each quiet step is named by what it changes, and its undo is fixed rather
// than recorded: a step is planned only when the host is not already in the
// quiet state, and apt_news defaults to true and an unmasked unit falls back
// to whatever its unit file says, so the undo returns the host to what it was.
const (
	proStepAptNews  = "apt_news"
	proStepESMCache = "esm-cache"
)

var proSteps = map[string]quietStep{
	proStepAptNews: {
		row:  "ubuntu-pro",
		do:   []string{"pro", "config", "set", "apt_news=false"},
		undo: []string{"pro", "config", "set", "apt_news=true"},
	},
	proStepESMCache: {
		row:  "ubuntu-pro",
		do:   []string{"systemctl", "mask", "esm-cache.service"},
		undo: []string{"systemctl", "unmask", "esm-cache.service"},
	},
}

// proHost is the Ubuntu Pro surface doctor reads and changes. A struct so a
// test can point it at a fixture root, a scratch record and a scripted pro.
type proHost struct {
	// root prefixes esmHookConf.
	root string
	// record holds the steps --quiet-ubuntu-pro ran, which is the whole of
	// what --restore-ubuntu-pro undoes.
	record string
	// run executes one tool and returns its combined output.
	run func(argv []string) (string, error)
	// lookPath finds pro before anything asks it a question.
	lookPath func(string) (string, error)
}

var ubuntuPro = &proHost{
	root:     "/",
	record:   "/etc/bodega/doctor-ubuntu-pro.json",
	run:      runProTool,
	lookPath: exec.LookPath,
}

const proToolTimeout = 30 * time.Second

// runProTool bounds every call: `pro status` asks Canonical's contract
// server, and on the egress-locked host this row exists for that would
// otherwise hang doctor on a connect that never completes. A call cut off at
// the bound returns an error wrapping context.DeadlineExceeded, so a caller
// can tell a host that cannot answer from a tool that refused.
func runProTool(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(backgroundCtx(), proToolTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("no answer within %s, %w: %w", proToolTimeout, ctx.Err(), err)
	}
	return strings.TrimSpace(string(out)), err
}

func (h *proHost) ledger() stepRecord {
	return stepRecord{
		path: h.record, steps: proSteps, run: h.run,
		quietFlag: "--quiet-ubuntu-pro", restoreFlag: "--restore-ubuntu-pro", what: "Ubuntu Pro steps",
	}
}

// finding reports the ESM hook on a host Ubuntu Pro is not attached to. A
// host without the hook, one whose pro is gone, and an attached one, which is
// paying for what the hook fetches, get no row at all.
func (h *proHost) finding() (host.Finding, bool) {
	f, ok, _ := h.check()
	return f, ok
}

// check is finding plus, when there is no row, why not. The hook is a dpkg
// conffile, so `apt remove ubuntu-pro-client` leaves it behind with pro gone;
// its commands are guarded on the client's binaries existing, so nothing runs
// it and there is nothing to report.
func (h *proHost) check() (f host.Finding, ok bool, why string) {
	f = host.Finding{Check: "ubuntu-pro-hook"}
	hook := filepath.Join(h.root, esmHookConf)
	if _, err := os.Stat(hook); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return f, false, "no " + esmHookConf
		}
		f.Status = host.StatusSkip
		f.Detail = "could not stat " + hook + ": " + err.Error()
		f.Remediation = skipRemedy(hook, err)
		return f, true, ""
	}
	if _, err := h.lookPath("pro"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return f, false, filepath.Base(esmHookConf) + " is left from a removed ubuntu-pro-client; nothing runs it"
		}
		f.Status = host.StatusSkip
		f.Detail = esmHookConf + " is present and looking up `pro` in $PATH failed: " + err.Error()
		f.Remediation = "run `command -v pro` to see why the lookup fails, then re-run `bodega doctor`"
		return f, true, ""
	}
	attached, err := h.attached()
	if err != nil {
		f.Status = host.StatusSkip
		f.Detail = esmHookConf + " is present and " + err.Error()
		f.Remediation = "run `pro api u.pro.status.is_attached.v1` and `pro status --format json` to see why they fail, then re-run `bodega doctor`"
		return f, true, ""
	}
	if attached {
		return f, false, "Ubuntu Pro is attached"
	}
	f.Status = host.StatusWarn
	f.Detail = esmHookConf + " starts apt-news.service and esm-cache.service on every apt update and runs " +
		"apt-esm-json-hook on upgrade, and each contacts esm.ubuntu.com whatever the apt sources say; " +
		"Ubuntu Pro is not attached, so they fetch nothing this host uses"
	f.Remediation = "pro config set apt_news=false and systemctl mask esm-cache.service, " +
		"or bodega doctor --configure apt --quiet-ubuntu-pro --apply, which records both for --restore-ubuntu-pro"
	return f, true, ""
}

// attached asks pro api first because it reads the host's own attachment
// state, while `pro status` contacts Canonical's contract server and so never
// answers on a host whose egress reaches only bodega. An ubuntu-pro-client
// too old to know the endpoint falls back to `pro status`.
func (h *proHost) attached() (bool, error) {
	attached, apiErr := h.attachedAPI()
	if apiErr == nil {
		return attached, nil
	}
	out, err := h.run([]string{"pro", "status", "--format", "json"})
	if err != nil {
		msg := fmt.Sprintf("%v, and the fallback `pro status --format json` failed (%v): %s", apiErr, err, out)
		if errors.Is(err, context.DeadlineExceeded) {
			msg += "; `pro status` needs to reach Canonical's contract server, so on a host that cannot, " +
				"run `pro config set apt_news=false` and `systemctl mask esm-cache.service` by hand"
		}
		return false, errors.New(msg)
	}
	var st struct {
		Attached *bool `json:"attached"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Attached == nil {
		return false, fmt.Errorf("%v, and the fallback `pro status --format json` printed no attached field this doctor can read", apiErr)
	}
	return *st.Attached, nil
}

func (h *proHost) attachedAPI() (bool, error) {
	out, err := h.run([]string{"pro", "api", "u.pro.status.is_attached.v1"})
	if err != nil {
		return false, fmt.Errorf("`pro api u.pro.status.is_attached.v1` failed (%v): %s", err, out)
	}
	var resp struct {
		Result string `json:"result"`
		Data   struct {
			Attributes struct {
				IsAttached *bool `json:"is_attached"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return false, fmt.Errorf("`pro api u.pro.status.is_attached.v1` printed no JSON this doctor can read: %s", out)
	}
	if resp.Result != "success" || resp.Data.Attributes.IsAttached == nil {
		return false, fmt.Errorf("`pro api u.pro.status.is_attached.v1` did not report is_attached (result %q): %s", resp.Result, out)
	}
	return *resp.Data.Attributes.IsAttached, nil
}

// quietSteps plans what --quiet-ubuntu-pro changes on this host. It plans
// nothing, and says why, where doctor would report no row, and leaves out a
// step whose end state the host already has, so the record never claims a
// change somebody else made.
func (h *proHost) quietSteps() (steps []string, why string, err error) {
	switch f, ok, why := h.check(); {
	case !ok:
		return nil, why, nil
	case f.Status != host.StatusWarn:
		return nil, "", fmt.Errorf("--quiet-ubuntu-pro cannot plan: %s", f.Detail)
	}
	news, err := h.run([]string{"pro", "config", "show", "apt_news"})
	if err != nil {
		return nil, "", fmt.Errorf("--quiet-ubuntu-pro cannot read apt_news: `pro config show apt_news` failed (%v): %s", err, news)
	}
	if fields := strings.Fields(news); len(fields) != 2 || !strings.EqualFold(fields[1], "false") {
		steps = append(steps, proStepAptNews)
	}
	// is-enabled exits non-zero for a masked unit, so its answer is the output.
	state, err := h.run([]string{"systemctl", "is-enabled", "esm-cache.service"})
	if state == "" {
		return nil, "", fmt.Errorf("--quiet-ubuntu-pro cannot read esm-cache.service: `systemctl is-enabled` printed nothing (%v)", err)
	}
	if !strings.HasPrefix(state, "masked") {
		steps = append(steps, proStepESMCache)
	}
	if len(steps) == 0 {
		why = "apt_news is already false and esm-cache.service already masked"
	}
	return steps, why, nil
}
