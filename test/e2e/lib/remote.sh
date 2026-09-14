# shellcheck shell=bash
#
# ssh/scp plumbing. Every remote command in the harness goes through e2e_on,
# which captures stdout, stderr and the exit code separately and keeps a full
# transcript on disk.
#
# The alias -> hostname map is the safety boundary. Suites name "server" and
# "client"; nothing in a suite can name a host, so no suite can reach
# bodega.cow.org however it is edited. e2e_reset and the destructive suite make
# that boundary the difference between a scratch guest and production.

# Sourcing is idempotent: run.sh loads the libs once, and each suite loads them
# again so a suite can be linted and run on its own. A second load must not
# reset the counters.
[ -n "${E2E_LIB_REMOTE:-}" ] && return 0
E2E_LIB_REMOTE=1

E2E_SERVER_HOST="bodega-server.oak.cow.org"
E2E_CLIENT_HOST="bodega-client.oak.cow.org"

# Resolve an alias to a hostname, or fail closed.
e2e_host_for() {
	case "$1" in
	server) printf '%s' "$E2E_SERVER_HOST" ;;
	client) printf '%s' "$E2E_CLIENT_HOST" ;;
	*)
		printf 'e2e: unknown host alias %q; suites may name only "server" or "client"\n' "$1" >&2
		return 2
		;;
	esac
}

# A control socket per run. A full pass makes several hundred ssh calls and a
# fresh handshake each time roughly triples wall-clock.
#
# %C rather than %r@%h:%p, and the socket directory under /tmp rather than
# $TMPDIR: a Unix domain socket path caps at 104 bytes, and macOS hands out a
# per-user $TMPDIR long enough that the expanded name overruns it. ssh reports
# that as `unix_listener: path too long` and exits 255, which reads as an
# unreachable host rather than as a path-length problem.
e2e_ssh_opts() {
	local host="$1"
	printf '%s\n' \
		-o BatchMode=yes \
		-o ConnectTimeout=10 \
		-o ControlMaster=auto \
		-o "ControlPath=${E2E_SSH_CTL_DIR}/%C" \
		-o ControlPersist=300 \
		"$host"
}

# e2e_on <alias> <command-string>
#
# The command is one string, run by the guest's shell exactly as written, so
# pipelines, redirects and quoting behave the way they would if you typed them
# there. ssh concatenates its arguments with spaces and hands the result to a
# remote shell regardless, so a multi-argument form only looks safe: the local
# quoting is gone by the time the remote shell parses it. Use e2e_onq when an
# argument holds data rather than syntax.
#
# Sets E2E_OUT, E2E_ERR, E2E_RC and returns E2E_RC. The caller reads the
# globals; returning the output would lose stderr, and stderr is where bodega
# puts the error text most checks assert on.
e2e_on() {
	local alias="$1"
	shift
	local host outf errf
	host="$(e2e_host_for "$alias")" || return 2

	# A dry run reaches no guest. Every command is logged and reported as if it
	# had succeeded with empty output, which walks each suite to its end and
	# proves the scripts parse and reach every check. It does not prove the
	# assertions: a suite branching on output takes the happy path here.
	if [ "${E2E_DRY_RUN:-no}" = yes ]; then
		E2E_OUT=""
		E2E_ERR=""
		E2E_RC=0
		e2e_log_transcript "$alias" 0 "[dry-run] $*"
		printf '%s\n' "[dry-run] $alias: $*" >>"${E2E_DRY_PLAN:-/dev/null}"
		return 0
	fi

	outf="$(mktemp "${TMPDIR:-/tmp}/e2e-out.XXXXXX")"
	errf="$(mktemp "${TMPDIR:-/tmp}/e2e-err.XXXXXX")"

	local opts=()
	while IFS= read -r o; do opts+=("$o"); done < <(e2e_ssh_opts "$host")

	set +e
	timeout "${E2E_SSH_TIMEOUT:-300}" ssh "${opts[@]}" -- "$@" >"$outf" 2>"$errf"
	E2E_RC=$?
	set -e

	E2E_OUT="$(cat "$outf")"
	E2E_ERR="$(cat "$errf")"
	rm -f "$outf" "$errf"

	e2e_log_transcript "$alias" "$E2E_RC" "$*"
	return "$E2E_RC"
}

# e2e_onq <alias> <argv...> — argv quoted per-word, for arguments carrying data
# rather than shell syntax. A version string with a semicolon in it is a value
# here and a command separator in e2e_on.
e2e_onq() {
	local alias="$1"
	shift
	local q=""
	local a
	for a in "$@"; do
		q="$q$(printf '%q' "$a") "
	done
	e2e_on "$alias" "$q"
}

# e2e_local <command...> — same contract, on this workstation.
e2e_local() {
	local outf errf
	if [ "${E2E_DRY_RUN:-no}" = yes ]; then
		E2E_OUT=""
		E2E_ERR=""
		E2E_RC=0
		printf '%s\n' "[dry-run] local: $*" >>"${E2E_DRY_PLAN:-/dev/null}"
		return 0
	fi
	outf="$(mktemp "${TMPDIR:-/tmp}/e2e-out.XXXXXX")"
	errf="$(mktemp "${TMPDIR:-/tmp}/e2e-err.XXXXXX")"

	set +e
	"$@" >"$outf" 2>"$errf"
	E2E_RC=$?
	set -e

	E2E_OUT="$(cat "$outf")"
	E2E_ERR="$(cat "$errf")"
	rm -f "$outf" "$errf"

	e2e_log_transcript local "$E2E_RC" "$*"
	return "$E2E_RC"
}

e2e_log_transcript() {
	[ -n "${E2E_LOG_DIR:-}" ] || return 0
	local host="$1" rc="$2" cmd="$3"
	{
		printf '\n=== %s  host=%s  rc=%s  suite=%s\n' \
			"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$host" "$rc" "${E2E_SUITE:-?}"
		printf '$ %s\n' "$cmd"
		[ -n "$E2E_OUT" ] && printf -- '--- stdout\n%s\n' "$E2E_OUT"
		[ -n "$E2E_ERR" ] && printf -- '--- stderr\n%s\n' "$E2E_ERR"
		return 0
	} >>"$E2E_LOG_DIR/${E2E_SUITE:-run}.log"
}

# e2e_put <alias> <local-path> <remote-path>
e2e_put() {
	local alias="$1" src="$2" dst="$3" host
	host="$(e2e_host_for "$alias")" || return 2
	if [ "${E2E_DRY_RUN:-no}" = yes ]; then
		printf '%s\n' "[dry-run] $alias: scp $src -> $dst" >>"${E2E_DRY_PLAN:-/dev/null}"
		return 0
	fi
	local opts=()
	while IFS= read -r o; do opts+=("$o"); done < <(e2e_ssh_opts "$host")
	# e2e_ssh_opts ends with the host; scp wants it in the destination instead.
	unset 'opts[${#opts[@]}-1]'
	scp -q "${opts[@]}" -- "$src" "$host:$dst"
}

# e2e_curl <alias> <curl-args...> — curl run on a guest, not here. The client
# guest's source address is what the mutation ACL and the audit rows record, so
# a request issued from the workstation tests a path nothing in production uses.
e2e_curl() {
	local alias="$1"
	shift
	e2e_on "$alias" curl --silent --show-error --max-time "${E2E_HTTP_TIMEOUT:-60}" "$@"
}

# e2e_status <alias> <url> — the HTTP status alone, in E2E_OUT.
e2e_status() {
	e2e_curl "$1" -o /dev/null -w '%{http_code}' "$2"
}
