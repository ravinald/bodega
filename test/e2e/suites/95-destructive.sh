# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The commands that remove things, run last and on the client guest.
#
# The client rather than the server because everything earlier in the run built
# its state on the server, and because the client is the guest that can be
# restored from a snapshot without taking the run's evidence with it.
#
# `reset` is asserted by refusing it. Confirming it would leave the guest empty
# for the next run and prove only that deletion works, which nobody doubts. What
# is worth knowing is that the confirmation cannot be walked past.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"
# shellcheck source=../lib/fixtures.sh
. "${E2E_DIR:?}/lib/fixtures.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_CLIENT_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block DST-BLOCK "the destructive commands" "the client guest is unreachable"
	return 0
fi

E2E_HOST=client

# A store of its own on the client, so nothing here can reach the server's.
fx="$(e2e_fixture binary)"
e2e_on client "cat > /tmp/e2e-dst.json <<'E2EFIXTURE'
$fx
E2EFIXTURE" || true
e2e_bodega client "pkg import /tmp/e2e-dst.json" || true
e2e_bodega client "build fetch binary" || true
e2e_bodega client "build upload binary" || true
e2e_bodega client "show pkg binary hello-binary json" || true
check_contains DST-01 "the client has an entry to delete" "hello-binary" "$E2E_OUT" \
	"cmd/bodega/cmd_import.go:29" "bodega pkg import on the client"

# ---- freeze protects ---------------------------------------------------------
#
# A frozen entry cannot be deleted. That is the whole protection, so it is worth
# more than the delete that follows it.

e2e_bodega client "pkg freeze binary hello-binary" || true
e2e_bodega client "pkg delete binary hello-binary" || true
check_ne DST-02 "a frozen entry refuses deletion" 0 "$E2E_RC" \
	"cmd/bodega/cmd_freeze.go:15" "bodega pkg delete on a frozen entry" "$E2E_RC"

e2e_bodega client "pkg freeze binary hello-binary" || true

# ---- remove artifacts, keep the manifest -----------------------------------

e2e_bodega client "pkg remove binary hello-binary" || true
check_eq DST-03 "pkg remove drops the artifacts" 0 "$E2E_RC" \
	"cmd/bodega/cmd_remove.go:14" "bodega pkg remove binary hello-binary" "$E2E_RC"

e2e_bodega client "show pkg binary hello-binary json" || true
check_contains DST-04 "pkg remove leaves the manifest entry standing" \
	"hello-binary" "$E2E_OUT" "cmd/bodega/cmd_remove.go:14" "bodega show pkg binary hello-binary json"

# ---- delete ----------------------------------------------------------------

e2e_bodega client "pkg delete binary hello-binary --remove-artifacts" || true
check_eq DST-05 "pkg delete --remove-artifacts succeeds" 0 "$E2E_RC" \
	"cmd/bodega/cmd_delete.go:22" "bodega pkg delete binary hello-binary --remove-artifacts" "$E2E_RC"

e2e_bodega client "show pkg binary hello-binary json" || true
check_ne DST-06 "the deleted entry is gone" 0 "$E2E_RC" \
	"cmd/bodega/cmd_delete.go:22" "bodega show pkg binary hello-binary json after delete" "$E2E_RC"

# ---- reset refuses a wrong answer ------------------------------------------
#
# The confirmation is a random word printed at the prompt, so feeding it a fixed
# string is a wrong answer by construction. An empty answer is the other shape:
# a script piping /dev/null at it must not be read as consent.

e2e_on client "printf 'definitely-not-the-word\n' | sudo bodega reset 2>&1 | tail -5; true" || true
check_lacks DST-07 "reset refuses a wrong confirmation word" \
	"Reset complete" "$E2E_OUT$E2E_ERR" "cmd/bodega/cmd_reset.go:24" \
	"printf a wrong word | bodega reset"

e2e_on client "sudo bodega reset < /dev/null 2>&1 | tail -5; true" || true
check_lacks DST-08 "reset refuses an empty answer" \
	"Reset complete" "$E2E_OUT$E2E_ERR" "cmd/bodega/cmd_reset.go:24" \
	"bodega reset < /dev/null"

e2e_on client "sudo ls /var/lib/bodega/manifests 2>/dev/null | wc -l" || true
check_ne DST-09 "the store survived both refused resets" "" "$E2E_OUT" \
	"cmd/bodega/cmd_reset.go:24" "ls /var/lib/bodega/manifests | wc -l"

unset fx
