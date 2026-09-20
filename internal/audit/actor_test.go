package audit

import "testing"

func TestCurrentActor_SudoUserWins(t *testing.T) {
	t.Setenv("SUDO_USER", "ravi")
	t.Setenv("USER", "root")
	if got := CurrentActor(); got != "ravi" {
		t.Errorf("got %q, want ravi (SUDO_USER should win over USER)", got)
	}
}

func TestCurrentActor_NoSudo(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	if got := CurrentActor(); got == "" {
		t.Error("CurrentActor returned empty string")
	}
	if got := CurrentActor(); got == "unknown" {
		t.Error("CurrentActor fell all the way through to unknown on a normal run")
	}
}

func TestCurrentActor_BlankSudoUserIsIgnored(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("USER", "ci-bot")
	// Blank SUDO_USER shouldn't short-circuit the chain — the fallbacks still need
	// to be reachable. We can't reliably force os/user.Current() to fail, so just
	// assert the result isn't the empty-string we'd get if SUDO_USER's blank value
	// got returned verbatim.
	if got := CurrentActor(); got == "" {
		t.Error("blank SUDO_USER should not produce an empty actor")
	}
}
