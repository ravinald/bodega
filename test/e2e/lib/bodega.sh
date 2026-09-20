# shellcheck shell=bash
#
# bodega-specific plumbing the suites share: running the CLI on a guest,
# reading and writing config, and getting the service back to a known state.

[ -n "${E2E_LIB_BODEGA:-}" ] && return 0
E2E_LIB_BODEGA=1

# e2e_bodega <alias> <args...> — run the CLI as root and repair ownership.
#
# Every bodega command run as root leaves the files it touched owned by root,
# and the service runs as its own user. The failure is not a refusal: the cache
# write logs `permission denied` at WARN and the request still succeeds from
# upstream, so an install serves correctly for weeks while caching nothing. The
# unit's own header calls for the ownership pass; doing it here means no suite
# can forget it.
e2e_bodega() {
	local alias="$1"
	shift
	e2e_on "$alias" "sudo bodega $* ; rc=\$?; sudo chown -R ${E2E_SERVICE_USER:-bodega} /var/lib/bodega /var/log/bodega 2>/dev/null; exit \$rc"
}

# e2e_bodega_user <alias> <args...> — run the CLI unprivileged.
# The posture checks read differently without root, which is a property worth
# measuring rather than working around.
e2e_bodega_user() {
	local alias="$1"
	shift
	e2e_on "$alias" "bodega $*"
}

# e2e_config_get <alias> <jq-filter>
e2e_config_get() {
	e2e_on "$1" "sudo jq -r '$2' /etc/bodega/config.json"
}

# e2e_config_set <alias> <jq-program>
#
# Followed by a restart, never a reload: SIGHUP re-reads manifests, ACLs and
# profiles, and config.json is not among them. A reload after a config edit
# leaves the old value in force and the file on disk saying otherwise, which
# reads as the setting having no effect.
e2e_config_set() {
	local alias="$1" prog="$2"
	e2e_on "$alias" "sudo jq '$prog' /etc/bodega/config.json > /tmp/e2e-cfg.json && \
		sudo install -o root -g ${E2E_SERVICE_USER:-bodega} -m 0640 /tmp/e2e-cfg.json /etc/bodega/config.json"
}

# e2e_restart <alias> [seconds] — restart and wait for the listener to answer.
e2e_restart() {
	local alias="$1" budget="${2:-30}" waited=0
	# reset-failed first, always. systemd's default start limit is 5 starts in
	# 10 seconds and a suite walking several postures reaches that on a healthy
	# service; once the limit trips, every later restart in the run is refused
	# before the process is even forked. The suite then reports a config change
	# that never took effect as a server that will not start, which sends the
	# reader to the wrong half of the system. A unit that genuinely cannot start
	# still fails the health poll below, so nothing is masked.
	e2e_on "$alias" "sudo systemctl reset-failed bodega; sudo systemctl restart bodega" || return 1
	while [ "$waited" -lt "$budget" ]; do
		if e2e_on "$alias" "curl -sf -o /dev/null --max-time 5 http://127.0.0.1:8080/healthz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	return 1
}

# e2e_reload <alias> — SIGHUP, for the things reload does cover.
e2e_reload() {
	e2e_on "$1" "sudo systemctl reload bodega"
}

# e2e_http <alias> <path> — status code of a GET against the server under test.
e2e_http() {
	e2e_on "$1" "curl -s -o /dev/null -w '%{http_code}' --max-time ${E2E_HTTP_TIMEOUT:-60} '${E2E_BASE_URL}$2'"
}

# e2e_body <alias> <path> — response body.
e2e_body() {
	e2e_on "$1" "curl -s --max-time ${E2E_HTTP_TIMEOUT:-60} '${E2E_BASE_URL}$2'"
}

# e2e_reset_store <alias> — drop every manifest and artifact, keep the config.
#
# `bodega reset` wants an interactive confirmation word, so a suite that needs a
# clean store removes the trees directly. The confirmation itself is what
# 95-destructive asserts.
e2e_reset_store() {
	e2e_on "$1" "sudo systemctl stop bodega; \
		sudo rm -rf /var/lib/bodega/manifests /var/lib/bodega/repos /var/lib/bodega/pypi \
			/var/lib/bodega/gomod /var/lib/bodega/packages /var/lib/bodega/cargo \
			/var/lib/bodega/binaries /var/lib/bodega/npm /var/lib/bodega/charts \
			/var/lib/bodega/freebsd; \
		sudo chown -R ${E2E_SERVICE_USER:-bodega} /var/lib/bodega; \
		sudo systemctl start bodega"
}

# e2e_apt_version — the guest's candidate version for the apt fixture, resolved
# once and cached in E2E_APT_VERSION.
#
# Read from the guest rather than pinned in a fixture: an apt version is a
# property of the suite the guest tracks, and a constant goes stale at the next
# point release and fails as "no candidate", which reads as a bodega defect.
e2e_apt_version() {
	if [ -z "${E2E_APT_VERSION:-}" ]; then
		e2e_on server "apt-cache policy hello | awk '/Candidate:/{print \$2}'" || true
		E2E_APT_VERSION="$E2E_OUT"
		export E2E_APT_VERSION
	fi
	printf '%s' "$E2E_APT_VERSION"
}

# e2e_wait_for_health <alias> [seconds] — poll /healthz until it answers.
#
# Used after a deliberate kill, where the question is whether the supervisor
# brings the process back and how long it takes. A fixed sleep answers neither:
# too short and a working restart reads as a failure, too long and a unit that
# never comes back costs the budget anyway.
e2e_wait_for_health() {
	local alias="$1" budget="${2:-30}" waited=0
	while [ "$waited" -lt "$budget" ]; do
		if e2e_on "$alias" "curl -sf -o /dev/null --max-time 5 http://127.0.0.1:8080/healthz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	return 1
}
