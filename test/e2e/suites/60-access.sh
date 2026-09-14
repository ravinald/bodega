# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Who may change what. The mutation API, the CIDR lists, bearer tokens and the
# identity bindings, driven from the client guest so the request carries a
# source address that is not loopback. Every one of these controls is a no-op
# against a request from 127.0.0.1, which is why a unit test cannot stand in
# for this suite.
#
# The suite leaves the admin list back at localhost. A run that widened it and
# died would leave the guest accepting mutations from the subnet.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block ACC-BLOCK "access control" "a guest is unreachable"
	return 0
fi

E2E_CLIENT_CIDR="${E2E_CLIENT_ADDR:-127.0.0.1}/32"
CREATE_BODY='{"config_version":1,"name":"e2e-acl-probe","type":"binary","versions":[{"version":"1.0.0","url":"https://example.invalid/x"}]}'

# A probe entry left by an earlier run makes the authorized create answer 409.
# That still proves the token was accepted, but it proves it by accident: the
# same 409 arrives when the gate is wide open. Removing it first keeps the
# verdict about authorization.
E2E_HOST=server
e2e_bodega server "pkg delete binary e2e-acl-probe" >/dev/null 2>&1 || true

# ---- the shape before anything is widened ----------------------------------

E2E_HOST=server
e2e_bodega server "acl admin list" || true
check_contains ACC-01 "the admin list starts at loopback" "127.0.0.0/8" "$E2E_OUT" \
	"internal/config/config.go:131" "bodega acl admin list"

E2E_HOST=client
e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
	-d '$CREATE_BODY' '$E2E_BASE_URL/api/v1/packages/binary'" || true
check_eq ACC-02 "a mutation from off-host is refused while the list is loopback-only" \
	"403" "$E2E_OUT" "internal/server/middleware.go:703" "POST /api/v1/packages/binary from the client"

# A read is open by design, and saying so out loud is what stops someone
# "fixing" it later.
e2e_http client "/api/v1/packages" || true
check_eq ACC-03 "reads stay open from off-host" "200" "$E2E_OUT" \
	"internal/server/middleware.go:727" "GET /api/v1/packages from the client"

# ---- admin-gated reads -----------------------------------------------------
#
# Before the widening, while the client is still an ordinary address. Run after
# it, these measure an admin asking itself whether it is an admin and pass
# against a server with no gate at all.
#
# The status endpoint blanks its sensitive fields rather than refusing, so a
# 200 proves nothing on its own and the assertion has to be about the field.

e2e_body client "/api/v1/status" || true
client_status="$E2E_OUT"
E2E_HOST=server
e2e_on server "curl -s --max-time 30 http://127.0.0.1:8080/api/v1/status" || true
check_ne ACC-14 "the status endpoint tells an admin more than it tells a stranger" \
	"$client_status" "$E2E_OUT" "internal/server/server.go:985" "GET /api/v1/status from each end"

check_lacks ACC-14b "a non-admin status response carries no version" \
	'"version"' "$client_status" "internal/server/server.go:985" "GET /api/v1/status from the client"

E2E_HOST=client
e2e_http client "/api/v1/config" || true
check_eq ACC-15 "the config endpoint refuses a non-admin address" "403" "$E2E_OUT" \
	"internal/server/server.go:1048" "GET /api/v1/config from the client"

# ---- widening refuses to lock the operator out -----------------------------
#
# Widening past localhost is what turns the bearer requirement on, so widening
# with no token would answer 401 with nothing naming the cause.

E2E_HOST=server
e2e_bodega server "token list" || true
check_lacks ACC-04 "no API token exists yet" "e2e-token" "$E2E_OUT" \
	"cmd/bodega/cmd_token.go:140" "bodega token list"

e2e_bodega server "acl admin add $E2E_CLIENT_CIDR" || true
check_ne ACC-05 "widening past loopback is refused while no token exists" \
	"0" "$E2E_RC" "docs/QUICKSTART.md:227" "bodega acl admin add $E2E_CLIENT_CIDR" "$E2E_RC"

# ---- a token, then the widening -------------------------------------------

e2e_bodega server "token generate e2e-token expiry 1d 'e2e run'" || true
# Anchored on the "Token:" label. Taking the longest string in the output
# instead picks up the token ID, which is the same shape, printed two lines
# later, and produces a 401 that reads as a broken auth path.
E2E_TOKEN="$(printf '%s' "$E2E_OUT" | awk '/^[[:space:]]*Token:/ {print $2; exit}')"
check_matches ACC-06 "token generate prints a token once" '.{24,}' "${E2E_TOKEN:-none}" \
	"cmd/bodega/cmd_token.go:37" "bodega token generate e2e-token expiry 1d"

# The pepper is the file the token hash is keyed on. `token generate` creates
# /etc/bodega/pepper when run as root, mode 0600 root:root, and the service runs
# as its own user: it cannot read that file, falls back to the pepper under its
# own XDG path, and rejects every token the admin mints. The refusal is
# "invalid token" and 401, which names the credential rather than the file, so
# the operator re-mints instead of looking at ownership.
#
# The unit's header calls for an ownership pass over config.json and audit.db.
# The pepper is not on that list and is created later, by the one command the
# quick start tells you to run before widening the admin list.
# The pepper is removed and re-created here rather than inspected where it
# lies. A previous run of this suite repairs the ownership at the end, so
# reading whatever is on disk measures the last repair instead of what
# `token generate` writes, and the check passes on every run after the first.
e2e_on server "sudo rm -f /etc/bodega/pepper" || true
e2e_bodega server "token generate e2e-pepper-probe expiry 1d 'e2e pepper probe'" || true
e2e_on server "stat -c '%U:%G %a' /etc/bodega/pepper 2>/dev/null || echo absent" || true
pepper_state="$E2E_OUT"
if [ "$pepper_state" = absent ]; then
	e2e_skip ACC-06b "the service user can read the pepper token generate wrote" \
		"token generate wrote no /etc/bodega/pepper on this install"
else
	e2e_on server "sudo -u ${E2E_SERVICE_USER:-bodega} test -r /etc/bodega/pepper && echo readable || echo unreadable" || true
	check_eq ACC-06b "the service user can read the pepper token generate wrote" \
		"readable" "$E2E_OUT ($pepper_state)" "internal/audit/pepper.go:17" \
		"rm /etc/bodega/pepper; sudo bodega token generate; sudo -u ${E2E_SERVICE_USER:-bodega} test -r /etc/bodega/pepper"
fi
e2e_bodega server "token revoke e2e-pepper-probe" >/dev/null 2>&1 || true

# Repaired here rather than left broken, so the checks below measure the token
# path instead of re-reporting the pepper. ACC-06b above is where the defect is
# recorded.
e2e_on server "sudo chown ${E2E_SERVICE_USER:-bodega} /etc/bodega/pepper 2>/dev/null; true" || true
e2e_restart server || true

e2e_bodega server "acl admin add $E2E_CLIENT_CIDR --comment 'e2e run'" || true
check_eq ACC-07 "widening is accepted once a token exists" 0 "$E2E_RC" \
	"cmd/bodega/cmd_acl.go:90" "bodega acl admin add $E2E_CLIENT_CIDR" "$E2E_RC"

# ACL rows live in the audit database and the server re-reads them on a cycle,
# so this is a reload rather than a restart. A restart here would hide a broken
# refresh path behind a process that read the list at startup anyway.
e2e_reload server || true
sleep 3

E2E_HOST=client
e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
	-d '$CREATE_BODY' '$E2E_BASE_URL/api/v1/packages/binary'" || true
check_eq ACC-08 "a permitted address with no bearer token is 401, not 403" \
	"401" "$E2E_OUT" "internal/server/middleware.go:756" "POST with no Authorization header"

e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
	-H 'Authorization: Bearer not-a-real-token' \
	-d '$CREATE_BODY' '$E2E_BASE_URL/api/v1/packages/binary'" || true
check_eq ACC-09 "a wrong bearer token is refused" "401" "$E2E_OUT" \
	"internal/server/middleware.go:776" "POST with a bogus bearer token"

e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
	-H 'Authorization: Bearer $E2E_TOKEN' \
	-d '$CREATE_BODY' '$E2E_BASE_URL/api/v1/packages/binary'" || true
check_matches ACC-10 "the real token is accepted" '^(200|201)$' "$E2E_OUT" \
	"internal/server/server.go:1073" "POST with the generated bearer token"

e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X DELETE \
	-H 'Authorization: Bearer $E2E_TOKEN' \
	'$E2E_BASE_URL/api/v1/packages/binary/e2e-acl-probe'" || true
check_matches ACC-11 "the token authorizes a delete as well as a create" '^(200|204)$' "$E2E_OUT" \
	"internal/server/server.go:1136" "DELETE /api/v1/packages/binary/e2e-acl-probe"

# ---- revocation ------------------------------------------------------------

E2E_HOST=server
e2e_bodega server "token revoke e2e-token" || true
check_eq ACC-12 "the token revokes" 0 "$E2E_RC" \
	"cmd/bodega/cmd_token.go:189" "bodega token revoke e2e-token" "$E2E_RC"
e2e_reload server || true

# Polled rather than measured once. A revocation that lands inside a cache TTL
# and one that never lands both read as "still accepted" on a single request,
# and those are a documentation note and an incident respectively. The loop
# records which of the two it is, and how long it took.
E2E_HOST=client
revoked_after=""
for waited in 0 5 10 15 20 25 30 35; do
	[ "$waited" -gt 0 ] && sleep 5
	e2e_on client "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
		-H 'Authorization: Bearer $E2E_TOKEN' \
		-d '$CREATE_BODY' '$E2E_BASE_URL/api/v1/packages/binary'" || true
	if [ "$E2E_OUT" = "401" ]; then
		revoked_after="$waited"
		break
	fi
done
check_matches ACC-13 "a revoked token stops working within the ACL refresh window" \
	'^[0-9]+$' "${revoked_after:-still accepted after 35s: $E2E_OUT}" \
	"internal/server/middleware.go:776" "POST with the revoked token, polled to 35s"

# ---- the deny list ---------------------------------------------------------
#
# Outermost gate: it answers before the mutation gate and before any route, so
# a denied address cannot even read.

E2E_HOST=server
e2e_bodega server "acl deny add $E2E_CLIENT_CIDR --comment 'e2e run'" || true
e2e_reload server || true

E2E_HOST=client
e2e_http client "/healthz" || true
check_eq ACC-16 "a denied address is refused on every route" "403" "$E2E_OUT" \
	"internal/server/middleware.go:199" "GET /healthz from a denied address"

E2E_HOST=server
e2e_bodega server "acl deny remove $E2E_CLIENT_CIDR" || true
e2e_reload server || true
E2E_HOST=client
e2e_http client "/healthz" || true
check_eq ACC-17 "removing the deny entry restores access" "200" "$E2E_OUT" \
	"internal/server/middleware.go:199" "GET /healthz after the deny entry is removed"

# ---- identity --------------------------------------------------------------

E2E_HOST=server
e2e_bodega server "identity bind cidr $E2E_CLIENT_CIDR e2e-client --comment 'e2e run'" || true
check_eq ACC-18 "an identity binds to a CIDR" 0 "$E2E_RC" \
	"cmd/bodega/cmd_identity.go:59" "bodega identity bind cidr $E2E_CLIENT_CIDR e2e-client" "$E2E_RC"

e2e_bodega server "identity list" || true
check_contains ACC-19 "the binding is listed" "e2e-client" "$E2E_OUT" \
	"cmd/bodega/cmd_identity.go:169" "bodega identity list"

# ---- restore ---------------------------------------------------------------
#
# The admin list goes back to loopback before the suite ends. A run that died
# after widening would leave the guest taking mutations from the subnet, and
# the next suite would measure a posture nobody chose.

e2e_bodega server "identity unbind cidr $E2E_CLIENT_CIDR" || true
e2e_bodega server "acl admin remove $E2E_CLIENT_CIDR" || true
e2e_reload server || true
e2e_bodega server "acl admin list" || true
check_lacks ACC-20 "the admin list is back to loopback" "$E2E_CLIENT_CIDR" "$E2E_OUT" \
	"cmd/bodega/cmd_acl.go:246" "bodega acl admin list"

unset CREATE_BODY client_status pepper_state revoked_after waited
