# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Ships HEAD to both guests and puts the server on an address the client can
# reach. Everything after this measures the commit under test; without the
# version assertion a run measures whatever was installed last, which on both
# guests was a binary 35 commits old built with bare `go build`.
#
# This suite mutates the guests: it installs a binary, rewrites
# /etc/bodega/config.json and appends to /etc/hosts. Originals land in the
# run's artifacts/ directory.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"

E2E_BASE_URL=""
E2E_SERVICE_USER="bodega"
export E2E_BASE_URL E2E_SERVICE_USER

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block SHIP-BLOCK "ship and install" "preflight could not reach a guest"
	return 0
fi

# e2e_wait_for <alias> <seconds> <shell test>
# Polls instead of sleeping a fixed interval: a restart that takes 400ms and one
# that takes 9s both pass, and a hung one fails at a known bound rather than
# intermittently.
e2e_wait_for() {
	local alias="$1" budget="$2" probe="$3" waited=0
	while [ "$waited" -lt "$budget" ]; do
		if e2e_on "$alias" "$probe" >/dev/null 2>&1; then return 0; fi
		sleep 1
		waited=$((waited + 1))
	done
	return 1
}

# ---- build -----------------------------------------------------------------

E2E_HOST=local
BIN="$REPO_ROOT/dist/bodega-linux-arm64"

if [ "${E2E_SHIP:-yes}" = yes ]; then
	# arm64 only. Both guests are aarch64, and an amd64 binary lands there as
	# `cannot execute binary file`, which reads as a truncated upload.
	e2e_local make -C "$REPO_ROOT" cross CROSS_TARGETS=linux/arm64 || true
	check_eq SHIP-01 "make cross builds the arm64 binary" 0 "$E2E_RC" \
		"Makefile" "make cross CROSS_TARGETS=linux/arm64" "$E2E_RC"
else
	e2e_skip SHIP-01 "make cross builds the arm64 binary" "--no-ship"
fi

if [ -f "$BIN" ] || [ "${E2E_DRY_RUN:-no}" = yes ]; then
	e2e_local file "$BIN" || true
	check_contains SHIP-02 "the shipped binary is aarch64" "ARM aarch64" "$E2E_OUT" \
		"test/e2e/README.md" "file dist/bodega-linux-arm64"
else
	e2e_record SHIP-02 FAIL "the shipped binary is aarch64" "dist/bodega-linux-arm64 exists" "missing" "file $BIN" 1 ""
	e2e_block SHIP-BLOCK-BIN "install on both guests" "no binary to ship"
	return 0
fi

# ---- install ---------------------------------------------------------------

for h in server client; do
	E2E_HOST="$h"
	n="$([ "$h" = server ] && echo 3 || echo 4)"
	if [ "${E2E_SHIP:-yes}" = yes ]; then
		if e2e_put "$h" "$BIN" /tmp/bodega-under-test &&
			e2e_on "$h" "sudo install -o root -g root -m 0755 /tmp/bodega-under-test /usr/local/bin/bodega"; then
			e2e_record "SHIP-0$n" PASS "$h takes the new binary" "installed" "installed" "install /usr/local/bin/bodega" 0 ""
		else
			e2e_record "SHIP-0$n" FAIL "$h takes the new binary" "installed" "$E2E_ERR" "install /usr/local/bin/bodega" "$E2E_RC" ""
		fi
	else
		e2e_skip "SHIP-0$n" "$h takes the new binary" "--no-ship"
	fi
done

# The stamp is the whole point of shipping through make: a bare `go build`
# leaves main.version at "unit-test", and a guest carrying that cannot tell you
# what it is running.
for h in server client; do
	E2E_HOST="$h"
	n="$([ "$h" = server ] && echo 5 || echo 6)"
	e2e_on "$h" "bodega --version" || true
	check_contains "SHIP-0$n" "$h runs the commit under test" \
		"$E2E_COMMIT" "$E2E_OUT" "Makefile" "bodega --version"
done

# A version string can be stamped on a tree missing half its commands. The
# command list is the second, independent read of the same question.
E2E_HOST=server
e2e_on server "bodega --help" || true
help_out="$E2E_OUT"
missing=""
for want in acl apt audit build discover doctor identity init pkg policy profile repair reset serve shell show status token; do
	case "$help_out" in
	*"  $want "*) ;;
	*) missing="$missing $want" ;;
	esac
done
check_eq SHIP-07 "the installed binary registers every top-level command" \
	"" "$missing" "cmd/bodega/main.go:173" "bodega --help"

# ---- names -----------------------------------------------------------------
#
# The guests resolve through 8.8.8.8 and 1.1.1.1 and cannot see the internal
# zone, so guest-to-guest traffic by name needs /etc/hosts. The addresses come
# from this workstation's resolver at run time rather than from a constant: a
# hardcoded address in the repo is wrong the first time DHCP disagrees.

for h in server client; do
	E2E_HOST="$h"
	e2e_on "$h" "sudo sed -i '/# bodega-e2e\$/d' /etc/hosts && \
		printf '%s %s # bodega-e2e\n%s %s # bodega-e2e\n' \
		'$E2E_SERVER_ADDR' '$E2E_SERVER_HOST' \
		'$E2E_CLIENT_ADDR' '$E2E_CLIENT_HOST' | sudo tee -a /etc/hosts >/dev/null" || true
done

E2E_HOST=client
e2e_on client "getent hosts $E2E_SERVER_HOST | awk '{print \$1; exit}'" || true
check_eq SHIP-08 "the client resolves the server by name" \
	"$E2E_SERVER_ADDR" "$E2E_OUT" "test/e2e/README.md" "getent hosts $E2E_SERVER_HOST"

# ---- listener --------------------------------------------------------------

E2E_HOST=server
e2e_on server "systemctl show bodega -p User --value" || true
[ -n "$E2E_OUT" ] && E2E_SERVICE_USER="$E2E_OUT"

e2e_on server "sudo cp -p /etc/bodega/config.json /etc/bodega/config.json.e2e-orig" || true
e2e_on server "sudo cat /etc/bodega/config.json" || true
printf '%s\n' "$E2E_OUT" >"$E2E_ARTIFACT_DIR/server-config.orig.json"

# Bound to every interface rather than to the guest's address: the address is a
# DHCP lease, and a listener pinned to one that changes fails at start with
# "cannot assign requested address" on a host that looks fine.
e2e_on server "sudo jq '.listen_addr = \"0.0.0.0:8080\"
	| .allow_plaintext = true
	| .public_url = \"http://$E2E_SERVER_HOST:8080\"' \
	/etc/bodega/config.json > /tmp/cfg.e2e && \
	sudo install -o root -g $E2E_SERVICE_USER -m 0640 /tmp/cfg.e2e /etc/bodega/config.json" || true
check_eq SHIP-09 "the server config takes a reachable listen address" 0 "$E2E_RC" \
	"internal/config/config.go" "jq .listen_addr=0.0.0.0:8080" "$E2E_RC"

e2e_on server "sudo systemctl restart bodega" || true
if e2e_wait_for server 30 "systemctl is-active --quiet bodega"; then
	e2e_record SHIP-10 PASS "the service comes back active" active active "systemctl restart bodega" 0 "docs/bodega.service"
else
	e2e_on server "sudo journalctl -u bodega -n 20 --no-pager" || true
	e2e_record SHIP-10 FAIL "the service comes back active" active "not active in 30s" "systemctl restart bodega" 1 "docs/bodega.service"
fi

E2E_BASE_URL="http://$E2E_SERVER_HOST:8080"
export E2E_BASE_URL

E2E_HOST=client
e2e_status client "$E2E_BASE_URL/healthz" || true
check_eq SHIP-11 "the client reaches the server over the network" "200" "$E2E_OUT" \
	"internal/server/server.go:748" "curl $E2E_BASE_URL/healthz"

# ---- the stanza the operator is told to copy -------------------------------
#
# docs/usage.md tells the reader to paste what the banner prints, so the banner
# is a client configuration rather than a log line, and it is read back from the
# journal of the restart above. A codename mirrored from upstream serves whatever
# that archive publishes: a stanza naming only main installs everything up to the
# first package outside it, and "apt-get install redis-server" then 404s at the
# pool after apt update reported success.

# jq through e2e_on rather than e2e_config_get: this suite sources assert.sh and
# remote.sh only, and a call to a function lib/bodega.sh defines is swallowed by
# the "|| true" every read here carries, leaving the previous command's E2E_OUT
# to be asserted against.
E2E_HOST=server
e2e_on server "sudo jq -r '.apt_upstreams // {} | keys | length' /etc/bodega/config.json" || true
mirrored_n="${E2E_OUT:-0}"
e2e_on server "sudo jq -r '.apt_upstreams // {} | keys | join(\" \")' /etc/bodega/config.json" || true
mirrored_suites="$E2E_OUT"
# The last banner in the window, not the first: the journal holds every restart
# this guest has ever done, and an assertion over all of them measures history.
e2e_on server "sudo journalctl -u bodega --no-pager -n 300 | awk '/bodega.sources/{buf=\"\"} {buf=buf \$0 \"\\n\"} END{printf \"%s\", buf}'" || true
banner="$E2E_OUT"

if [ "${mirrored_n:-0}" -lt 2 ]; then
	e2e_skip SHIP-APT-01 "the banner collapses the mirrored codenames onto one stanza" \
		"this guest mirrors fewer than two codenames, so there is nothing to collapse" "internal/server/apt.go:1692"
	e2e_skip SHIP-APT-02 "the mirrored stanza names the components its codename serves" \
		"this guest mirrors no codename" "internal/aptsources/aptsources.go:189"
else
	check_contains SHIP-APT-01 "the banner collapses the mirrored codenames onto one stanza" \
		"Suites: $mirrored_suites" "$banner" \
		"internal/server/apt.go:1692; every mirrored codename on one Suites: line, as the generated half already prints; four printed as four stanzas is four sources entries where apt wants one" \
		"journalctl -u bodega | the last startup banner"
	check_contains SHIP-APT-02 "the mirrored stanza names the components its codename serves" \
		"Components: main restricted universe multiverse" "$banner" \
		"internal/aptsources/aptsources.go:189; the same line docs/usage.md prints under Mirroring an upstream archive, against Components: main which drops universe and multiverse" \
		"journalctl -u bodega | the last startup banner"
fi
unset mirrored_n mirrored_suites banner

# ---- ownership -------------------------------------------------------------
#
# Every bodega command run as root leaves config.json and audit.db owned by
# root, and the service does not start on either. The unit's header calls for
# an ownership pass after any such command; this suite just ran several.

E2E_HOST=server
e2e_on server "sudo chown -R $E2E_SERVICE_USER /var/log/bodega /var/lib/bodega 2>/dev/null; \
	stat -c '%U' /etc/bodega/config.json" || true
check_ne SHIP-12 "the config is not left owned by root alone" "root:root" "$E2E_OUT:$(
	e2e_on server "stat -c '%G' /etc/bodega/config.json" >/dev/null 2>&1
	printf '%s' "$E2E_OUT"
)" "docs/bodega.service" "stat -c %U:%G /etc/bodega/config.json"

# ---- the type list ---------------------------------------------------------
#
# The stale binary served seven types here with cargo missing. manifest.AllTypes
# is the canonical list and the API is one of the surfaces B48 found had drifted
# from it.

E2E_HOST=client
e2e_curl client "$E2E_BASE_URL/api/v1/packages" || true
api_types="$E2E_OUT"
for t in apt git pypi binary gomod helm npm cargo freebsd; do
	check_contains "SHIP-13-$t" "the package API lists $t" "\"$t\"" "$api_types" \
		"internal/manifest/types.go:43" "curl $E2E_BASE_URL/api/v1/packages"
done

unset h n want missing help_out api_types t BIN
