# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Does the ground hold. Everything after this assumes two reachable guests with
# passwordless sudo, a sane clock and room on disk; when one of those is false
# the failure surfaces fifty checks later as something that looks like a bodega
# bug. Cheap precondition first, expensive operation second.
#
# Sets E2E_SERVER_UP and E2E_CLIENT_UP, which every later suite reads to decide
# between BLOCKED and a real verdict.

# Loaded again so this suite lints and runs on its own; the libs guard against
# a second load resetting the counters.
# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"

E2E_SERVER_UP=no
E2E_CLIENT_UP=no
export E2E_SERVER_UP E2E_CLIENT_UP

# ---- reachability ----------------------------------------------------------

E2E_HOST=server
if e2e_on server true 2>/dev/null; then
	E2E_SERVER_UP=yes
	e2e_record PRE-01 PASS "server answers ssh" "reachable" "reachable" "ssh $E2E_SERVER_HOST true" 0 ""
else
	e2e_record PRE-01 FAIL "server answers ssh" "reachable" "$E2E_ERR" "ssh $E2E_SERVER_HOST true" "$E2E_RC" "test/e2e/README.md"
fi

E2E_HOST=client
if e2e_on client true 2>/dev/null; then
	E2E_CLIENT_UP=yes
	e2e_record PRE-02 PASS "client answers ssh" "reachable" "reachable" "ssh $E2E_CLIENT_HOST true" 0 ""
else
	e2e_record PRE-02 FAIL "client answers ssh" "reachable" "$E2E_ERR" "ssh $E2E_CLIENT_HOST true" "$E2E_RC" "test/e2e/README.md"
fi

if [ "$E2E_SERVER_UP" != yes ] || [ "$E2E_CLIENT_UP" != yes ]; then
	E2E_HOST=local
	e2e_block PRE-BLOCK "remaining preflight checks" "a guest is unreachable; power it on" "test/e2e/README.md"
	return 0
fi

# ---- identity --------------------------------------------------------------
#
# A guest answering on the right address is not proof it is the right guest.
# The SNAP twins carry the same MAC as their live counterparts, so booting one
# while its twin runs puts two interfaces on one address and ssh reaches
# whichever answered last. The hostname is what tells them apart.

E2E_HOST=server
e2e_on server "hostname -s" || true
check_eq PRE-03 "server is the host it claims to be" \
	"${E2E_SERVER_HOST%%.*}" "$E2E_OUT" "test/e2e/README.md" "hostname -s"

E2E_HOST=client
e2e_on client "hostname -s" || true
check_eq PRE-04 "client is the host it claims to be" \
	"${E2E_CLIENT_HOST%%.*}" "$E2E_OUT" "test/e2e/README.md" "hostname -s"

# ---- privilege -------------------------------------------------------------

for h in server client; do
	E2E_HOST="$h"
	e2e_on "$h" "sudo -n id -u" || true
	check_eq "PRE-0$([ "$h" = server ] && echo 5 || echo 6)" \
		"$h sudo is passwordless" "0" "$E2E_OUT" "test/e2e/README.md" "sudo -n id -u" "$E2E_RC"
done

# ---- clock -----------------------------------------------------------------
#
# Audit rows carry timestamps and several checks assert ordering across the two
# guests. A minute of skew turns those into intermittent failures that read as
# race conditions.

local_now="$(date -u +%s)"
for h in server client; do
	E2E_HOST="$h"
	e2e_on "$h" "date -u +%s" || true
	skew=$((E2E_OUT - local_now))
	[ "$skew" -lt 0 ] && skew=$((-skew))
	if [ "$skew" -le 5 ]; then
		e2e_record "PRE-0$([ "$h" = server ] && echo 7 || echo 8)" PASS \
			"$h clock is within 5s of this workstation" "<=5s" "${skew}s" "date -u +%s" 0 ""
	else
		e2e_record "PRE-0$([ "$h" = server ] && echo 7 || echo 8)" FAIL \
			"$h clock is within 5s of this workstation" "<=5s" "${skew}s" "date -u +%s" 0 ""
	fi
done

# ---- capacity --------------------------------------------------------------
#
# The proxy suite pulls real artifacts from live upstreams and the spool writes
# them to disk. A guest that runs out mid-run fails as a bodega error rather
# than as a full filesystem.

for h in server client; do
	E2E_HOST="$h"
	e2e_on "$h" "df -BG --output=avail / | tail -1 | tr -dc '0-9'" || true
	avail="${E2E_OUT:-0}"
	if [ "${avail:-0}" -ge 5 ]; then
		e2e_record "PRE-09-$h" PASS "$h has at least 5G free on /" ">=5G" "${avail}G" "df -BG /" 0 ""
	else
		e2e_record "PRE-09-$h" FAIL "$h has at least 5G free on /" ">=5G" "${avail}G" "df -BG /" 0 ""
	fi
done

# ---- network ---------------------------------------------------------------

# The guests resolve through 8.8.8.8 and 1.1.1.1 and cannot see the internal
# zone, so guest-to-guest traffic by name is something the ship suite
# establishes with /etc/hosts rather than something preflight can assume. What
# preflight needs is the addresses, and this workstation is what resolves them.
E2E_HOST=local
for pair in "server:$E2E_SERVER_HOST" "client:$E2E_CLIENT_HOST" \
	"freebsd-server:$E2E_FREEBSD_SERVER_HOST" "freebsd-client:$E2E_FREEBSD_CLIENT_HOST"; do
	alias="${pair%%:*}"
	name="${pair#*:}"
	addr="$(dscacheutil -q host -a name "$name" 2>/dev/null | awk '/^ip_address:/ {print $2; exit}')"
	[ -n "$addr" ] || addr="$(getent hosts "$name" 2>/dev/null | awk '{print $1; exit}')"
	check_matches "PRE-10-$alias" "this workstation resolves $name" \
		'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "${addr:-unresolved}" \
		"test/e2e/README.md" "dscacheutil -q host -a name $name"
	case "$alias" in
	server) E2E_SERVER_ADDR="$addr" ;;
	client) E2E_CLIENT_ADDR="$addr" ;;
	esac
done
export E2E_SERVER_ADDR E2E_CLIENT_ADDR

# Loopback only. Whether the client can reach the listener depends on the
# address it is bound to, which the ship suite sets; asserting it here would
# fail on a stock install for a reason that is not a defect.
E2E_HOST=server
e2e_on server "curl -sS -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8080/healthz" || true
check_eq PRE-11 "a bodega server answers on the server's loopback" "200" "$E2E_OUT" \
	"internal/server/server.go:748" "curl http://127.0.0.1:8080/healthz"

# The proxy/cache suite misses through to these. Checking now means a later
# cache failure is a bodega finding rather than a guest with no route out.
E2E_HOST=server
for up in proxy.golang.org registry.npmjs.org index.crates.io pypi.org; do
	e2e_on server "curl -sS -o /dev/null -w '%{http_code}' --max-time 20 https://$up/" || true
	case "$E2E_OUT" in
	2* | 3* | 4*)
		e2e_record "PRE-12-$up" PASS "server reaches $up" "an HTTP response" "$E2E_OUT" "curl https://$up/" 0 ""
		;;
	*)
		e2e_record "PRE-12-$up" FAIL "server reaches $up" "an HTTP response" "${E2E_OUT:-no response} ${E2E_ERR}" "curl https://$up/" "$E2E_RC" ""
		;;
	esac
done

unset h local_now skew avail up pair alias name addr
