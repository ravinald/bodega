# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The audit trail, read back. #278 has been open since v0.1.0-203 on exactly
# this question: the denial rows are written and nobody has ever read one. A
# gate that records nothing readable is a gate you cannot answer an incident
# with, so this suite provokes a denial of each kind and then looks for it.
#
# Ordering is deliberate: provoke first, read second, and read through the
# product's own query path rather than with sqlite3. A row only counts if
# `bodega audit events` can find it.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block AUD-BLOCK "the audit trail" "a guest is unreachable"
	return 0
fi

E2E_CLIENT_CIDR="${E2E_CLIENT_ADDR:-127.0.0.1}/32"

# ---- provoke ---------------------------------------------------------------

E2E_HOST=client
# A served fetch, a 404 on a package route, and two requests that must not be
# recorded at all.
e2e_http client "/binaries/hello-binary/1.0.0/LICENSE" || true
e2e_http client "/binaries/no-such-package/9.9.9/nothing" || true
e2e_http client "/healthz" || true
e2e_http client "/api/v1/packages" || true

# ip_not_permitted: a mutation from an address the admin list does not carry.
e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
	-d '{\"config_version\":1,\"name\":\"e2e-audit-probe\",\"type\":\"binary\",\"versions\":[{\"version\":\"1.0.0\",\"url\":\"https://example.invalid/x\"}]}' \
	'$E2E_BASE_URL/api/v1/packages/binary'" || true
check_eq AUD-01 "the denial the suite reads back was actually provoked" "403" "$E2E_OUT" \
	"internal/server/middleware.go:703" "POST /api/v1/packages/binary from an unpermitted address"

# deny_list: refused before any route, including one with no auth at all.
E2E_HOST=server
e2e_bodega server "acl deny add $E2E_CLIENT_CIDR --comment 'e2e audit probe'" || true
e2e_reload server || true
sleep 3
E2E_HOST=client
e2e_http client "/healthz" || true
check_eq AUD-02 "the deny-list denial was provoked" "403" "$E2E_OUT" \
	"internal/server/middleware.go:199" "GET /healthz from a denied address"
E2E_HOST=server
e2e_bodega server "acl deny remove $E2E_CLIENT_CIDR" || true
e2e_reload server || true
sleep 3

# push_refused: git-receive-pack is deliberately not exempt from the gate.
E2E_HOST=client
e2e_on client "curl -s -o /dev/null -w '%{http_code}' \
	'$E2E_BASE_URL/git/uuid/uuid.git/git-receive-pack'" || true
check_matches AUD-03 "a push attempt is refused" '^(40[0-9]|500)$' "$E2E_OUT" \
	"internal/server/githttp.go:216" "GET git-receive-pack"

# ---- read it back ----------------------------------------------------------

E2E_HOST=server
e2e_bodega server "audit events --limit 200" || true
events="$E2E_OUT"
check_eq AUD-04 "the audit query path answers at all" 0 "$E2E_RC" \
	"cmd/bodega/cmd_audit.go:25" "bodega audit events --limit 200" "$E2E_RC"

check_contains AUD-05 "a served fetch is recorded" "hello-binary" "$events" \
	"internal/server/middleware.go:549" "bodega audit events"

check_contains AUD-06 "the client's address is recorded on the row" \
	"${E2E_CLIENT_ADDR:-172.}" "$events" "internal/server/middleware.go:549" "bodega audit events"

# The 404 is dropped on purpose: an unresolvable path is not a fetch. Asserting
# it stays out is what keeps a future change from filling the trail with noise.
check_lacks AUD-07 "a 404 on a package route is not recorded as a fetch" \
	"no-such-package" "$events" "internal/server/middleware.go:583" "bodega audit events"

check_lacks AUD-08 "healthz is not recorded" "/healthz" "$events" \
	"internal/server/middleware.go:561" "bodega audit events"

# ---- the denial rows #278 asks about ---------------------------------------

e2e_bodega server "audit events --type denied --limit 100" || true
denials="$E2E_OUT"
check_eq AUD-09 "the trail can be filtered to denials" 0 "$E2E_RC" \
	"cmd/bodega/cmd_audit.go:114" "bodega audit events --type denied" "$E2E_RC"

for reason in ip_not_permitted deny_list; do
	check_contains "AUD-DENY-$reason" "a $reason denial is readable back" \
		"$reason" "$denials" "internal/server/audit.go:107" "bodega audit events --type denied"
done

# ---- what must never be recorded -------------------------------------------
#
# A credential in the trail turns the audit database into the thing an attacker
# wants most. The invalid-token path records a hash prefix; the token itself
# must appear nowhere.

E2E_HOST=client
e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X POST \
	-H 'Authorization: Bearer e2e-canary-token-value' \
	-H 'Content-Type: application/json' -d '{}' \
	'$E2E_BASE_URL/api/v1/packages/binary'" || true

E2E_HOST=server
e2e_bodega server "audit events --limit 200" || true
check_lacks AUD-10 "a rejected credential is never written to the trail" \
	"e2e-canary-token-value" "$E2E_OUT" "internal/server/middleware.go:797" "bodega audit events"

# ---- filters ---------------------------------------------------------------

e2e_bodega server "audit events --pkg-type binary --limit 20" || true
check_contains AUD-11 "the pkg-type filter selects" "binary" "$E2E_OUT" \
	"cmd/bodega/cmd_audit.go:114" "bodega audit events --pkg-type binary"

e2e_bodega server "audit events --client ${E2E_CLIENT_ADDR:-127.0.0.1} --limit 20" || true
check_eq AUD-12 "the client filter is accepted" 0 "$E2E_RC" \
	"cmd/bodega/cmd_audit.go:114" "bodega audit events --client ${E2E_CLIENT_ADDR:-127.0.0.1}" "$E2E_RC"

# A date, not a duration: --since takes RFC3339 or YYYY-MM-DD.
e2e_on server "sudo bodega audit events --since \$(date -u +%Y-%m-%d) --limit 20" || true
check_eq AUD-13 "the since filter accepts a date" 0 "$E2E_RC" \
	"cmd/bodega/cmd_audit.go:114" "bodega audit events --since <today>" "$E2E_RC"

# The duration form reads naturally and is not supported, so the refusal is
# what a user meets. It has to name the formats rather than just failing.
e2e_bodega server "audit events --since 1h --limit 5" || true
check_matches AUD-13b "a rejected --since names the formats it accepts" \
	'RFC3339|YYYY-MM-DD' "$E2E_OUT$E2E_ERR" "cmd/bodega/cmd_audit.go:114" "bodega audit events --since 1h"

# ---- lifecycle rows --------------------------------------------------------

e2e_bodega server "audit events --type serve_start --limit 5" || true
check_contains AUD-14 "the server records its own starts" "serve_start" "$E2E_OUT" \
	"internal/server/audit.go:87" "bodega audit events --type serve_start"

# ---- the API view ----------------------------------------------------------
#
# Admin-gated, so it is read from the server's own loopback.

e2e_on server "curl -s -o /dev/null -w '%{http_code}' --max-time 30 'http://127.0.0.1:8080/api/v1/audit?limit=5'" || true
check_eq AUD-15 "the audit API answers an admin" "200" "$E2E_OUT" \
	"internal/server/server.go:1278" "GET /api/v1/audit from loopback"

E2E_HOST=client
e2e_http client "/api/v1/audit?limit=5" || true
check_eq AUD-16 "the audit API refuses a non-admin" "403" "$E2E_OUT" \
	"internal/server/server.go:1278" "GET /api/v1/audit from the client"

unset events denials reason
