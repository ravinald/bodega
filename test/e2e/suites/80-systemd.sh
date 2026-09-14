# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The unit file, exercised rather than read. docs/bodega.service carries its own
# header of claims — Type=notify, reload on SIGHUP, restart after a kill,
# credentials through LoadCredential, a relative manifest_dir that needs
# WorkingDirectory. Each one is a promise to an operator at 03:00.
#
# The from-scratch replay runs on the client, which is the guest that can be
# torn down without taking the rest of the run with it. #264 was found that way:
# a replay on a host that already has state hides the step that was missing.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block SYS-BLOCK "the service unit" "the server guest is unreachable"
	return 0
fi

E2E_HOST=server

# ---- readiness -------------------------------------------------------------
#
# Type=notify is the difference between "systemd started the process" and "the
# listener is accepting". A unit that reaches active while still binding makes
# every dependent unit race it.

e2e_on server "systemctl show bodega -p Type --value" || true
check_eq SYS-01 "the unit is Type=notify" "notify" "$E2E_OUT" \
	"docs/bodega.service" "systemctl show bodega -p Type"

e2e_on server "sudo systemctl restart bodega && systemctl is-active bodega" || true
check_eq SYS-02 "a restart reaches active rather than sitting in activating" \
	"active" "$E2E_OUT" "docs/bodega.service" "systemctl restart bodega; systemctl is-active"

e2e_on server "curl -sf -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8080/healthz" || true
check_eq SYS-03 "the listener answers the moment the unit is active" "200" "$E2E_OUT" \
	"docs/bodega.service" "curl /healthz immediately after systemctl reports active"

# ---- reload ----------------------------------------------------------------

e2e_on server "sudo systemctl reload bodega && systemctl is-active bodega" || true
check_eq SYS-04 "reload keeps the process running" "active" "$E2E_OUT" \
	"docs/bodega.service" "systemctl reload bodega"

e2e_on server "systemctl show bodega -p MainPID --value" || true
pid_before="$E2E_OUT"
e2e_on server "sudo systemctl reload bodega; systemctl show bodega -p MainPID --value" || true
check_eq SYS-05 "reload signals the running process instead of replacing it" \
	"$pid_before" "$E2E_OUT" "docs/bodega.service" "systemctl show bodega -p MainPID, before and after reload"

# ---- restart on failure ----------------------------------------------------

e2e_on server "systemctl show bodega -p Restart --value" || true
check_contains SYS-06 "the unit restarts on failure" "on-failure" "$E2E_OUT" \
	"docs/bodega.service" "systemctl show bodega -p Restart"

e2e_on server "sudo kill -9 \$(systemctl show bodega -p MainPID --value)" || true
if e2e_wait_for_health server 45; then
	e2e_record SYS-07 PASS "the service comes back after a kill -9" \
		"healthy within 45s" "healthy" "kill -9 the main pid" 0 "docs/bodega.service"
else
	e2e_record SYS-07 FAIL "the service comes back after a kill -9" \
		"healthy within 45s" "still down" "kill -9 the main pid" 1 "docs/bodega.service"
fi

check_ne SYS-08 "the replacement process is a new one" "$pid_before" \
	"$(
		e2e_on server "systemctl show bodega -p MainPID --value" >/dev/null 2>&1 || true
		printf '%s' "$E2E_OUT"
	)" "docs/bodega.service" "systemctl show bodega -p MainPID after the kill"

# ---- credentials -----------------------------------------------------------
#
# LoadCredential puts the apt signing key somewhere only this unit can read.
# The fingerprint the server publishes has to be the one the key carries, or
# the whole apt trust path rests on a file nobody compared.

e2e_on server "systemctl cat bodega | grep -c LoadCredential || true" || true
if [ "${E2E_OUT:-0}" -gt 0 ]; then
	e2e_bodega server "apt key show" || true
	fpr="$(printf '%s' "$E2E_OUT" | tr -dc '[:alnum:]\n' | grep -Eo '[0-9A-F]{40}' | head -1)"
	e2e_on server "curl -s --max-time 30 http://127.0.0.1:8080/apt/bodega-archive-keyring.gpg | \
		gpg --show-keys --with-colons 2>/dev/null | awk -F: '/^fpr:/{print \$10; exit}'" || true
	check_eq SYS-09 "the served keyring carries the key the server reports" \
		"$fpr" "$E2E_OUT" "docs/bodega.service" "compare apt key show against the served keyring"
else
	e2e_skip SYS-09 "the served keyring carries the key the server reports" \
		"this unit declares no LoadCredential"
fi

# ---- the plaintext override ------------------------------------------------
#
# --allow-plaintext=false on ExecStart must beat allow_plaintext in the config.
# A flag that loses to a file is a posture an operator cannot enforce.

e2e_on server "sudo bodega serve --addr 127.0.0.1:18080 --allow-plaintext=false 2>&1 | head -5; true" || true
check_matches SYS-10 "--allow-plaintext=false refuses a plaintext listener" \
	'plaintext|TLS|cert' "$E2E_OUT$E2E_ERR" "internal/server/server.go:438" \
	"bodega serve --allow-plaintext=false with allow_plaintext true in the config"

# ---- the ownership trap ----------------------------------------------------
#
# The unit's header names config.json and audit.db. The pepper is created later,
# by the command the quick start tells you to run, and is not on the list.

e2e_on server "stat -c '%U' /etc/bodega/config.json /var/log/bodega/audit.db 2>/dev/null | sort -u | tr '\n' ' '" || true
check_lacks SYS-11 "neither config nor audit db is left owned by root" \
	"root" "$E2E_OUT" "docs/bodega.service" "stat -c %U /etc/bodega/config.json /var/log/bodega/audit.db"

unset pid_before fpr
