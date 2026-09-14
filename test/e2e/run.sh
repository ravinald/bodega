#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# End-to-end harness for bodega, driven from this workstation against the two
# UTM dev guests described in docs-internal/DEV_HOSTS.md.
#
# The runner lives here rather than on a guest for two reasons. The client
# guest carries no toolchain on purpose and has to stay that way to keep
# representing a user's machine. And the checks that matter most need both ends
# at once: the mutation ACL only means anything when the request arrives from
# the client's address rather than from loopback.
#
#   ./run.sh                    # full pass
#   ./run.sh --self-test        # the harness's own tests, no guest needed
#   ./run.sh --list             # suite names
#   ./run.sh --suite 45-        # only suites whose name starts 45-
#   ./run.sh --no-ship          # reuse what is installed; for iterating
#   ./run.sh --file <run-id>    # open an issue per unmapped FAIL
#
# Before a long unattended run:
#
#   ./run.sh --validate         # every script parses; no guest touched
#   ./run.sh --dry-run          # walk every suite, reach no guest, list every
#                               # command it would run and every check id
#   ./run.sh --preflight        # the foundation only, for real, in seconds
#   ./run.sh --deadline 480     # stop after 8h with a report rather than hang

set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$E2E_DIR/../.." && pwd)"

# shellcheck source=lib/assert.sh
. "$E2E_DIR/lib/assert.sh"
# shellcheck source=lib/remote.sh
. "$E2E_DIR/lib/remote.sh"
# shellcheck source=lib/report.sh
. "$E2E_DIR/lib/report.sh"

E2E_KNOWN_FILE="$E2E_DIR/known-issues.tsv"

die() {
	printf 'run.sh: %s\n' "$1" >&2
	exit "${2:-1}"
}

usage() {
	sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

# ---- guards ----------------------------------------------------------------

# The suites call `bodega reset`, `pkg delete --remove-artifacts` and
# `userdel bodega`. The production host is bodega.cow.org and differs from the
# server guest by one label, so the names are pinned here and checked rather
# than taken from a flag. A flag would make the destructive suites one typo
# from production.
E2E_ALLOWED_HOSTS="bodega-server.oak.cow.org bodega-client.oak.cow.org"

assert_host_allowlist() {
	local h
	for h in "$E2E_SERVER_HOST" "$E2E_CLIENT_HOST"; do
		case " $E2E_ALLOWED_HOSTS " in
		*" $h "*) ;;
		*) die "refusing to run: $h is not a dev guest. Edit E2E_ALLOWED_HOSTS deliberately, never to get past this." 3 ;;
		esac
	done
}

assert_tooling() {
	if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
		die "needs bash 4 or newer (this is ${BASH_VERSION}); on macOS: brew install bash" 3
	fi
	local t
	for t in jq ssh scp git timeout; do
		command -v "$t" >/dev/null 2>&1 ||
			die "missing $t. On macOS, timeout comes from coreutils: brew install coreutils jq" 3
	done
}

assert_tree_clean() {
	[ "$ALLOW_DIRTY" = yes ] && return 0
	if [ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]; then
		die "working tree is dirty, so the commit under test would not name what ran. Commit, stash, or pass --allow-dirty." 3
	fi
}

# ---- arguments -------------------------------------------------------------

MODE=run
SUITE_FILTER=""
SHIP=yes
ALLOW_DIRTY=no
FILE_RUN_ID=""
E2E_DRY_RUN=no
DEADLINE_MIN=0

while [ $# -gt 0 ]; do
	case "$1" in
	--self-test) MODE=selftest ;;
	--list) MODE=list ;;
	--report)
		MODE=report
		FILE_RUN_ID="${2:?--report needs a run id}"
		shift
		;;
	--file)
		MODE="file"
		FILE_RUN_ID="${2:?--file needs a run id}"
		shift
		;;
	--file-dry-run)
		MODE=filedry
		FILE_RUN_ID="${2:?--file-dry-run needs a run id}"
		shift
		;;
	--suite)
		SUITE_FILTER="${2:?--suite needs a prefix}"
		shift
		;;
	--dry-run)
		E2E_DRY_RUN=yes
		ALLOW_DIRTY=yes
		SHIP=no
		;;
	--preflight) SUITE_FILTER="00-" ;;
	--validate) MODE=validate ;;
	--deadline)
		DEADLINE_MIN="${2:?--deadline needs minutes}"
		shift
		;;
	--no-ship) SHIP=no ;;
	--allow-dirty) ALLOW_DIRTY=yes ;;
	-h | --help) usage 0 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
	shift
done

assert_tooling

case "$MODE" in
validate)
	# Static only: parse every script and confirm the suite preamble is there.
	# It reaches no guest and takes under a second, so it is the cheapest thing
	# to run before a long unattended pass.
	rc=0
	for f in "$E2E_DIR"/lib/*.sh "$E2E_DIR"/suites/*.sh "$E2E_DIR/run.sh"; do
		if bash -n "$f"; then
			printf 'ok     %s\n' "${f#"$E2E_DIR"/}"
		else
			printf 'PARSE  %s\n' "${f#"$E2E_DIR"/}"
			rc=1
		fi
	done
	for f in "$E2E_DIR"/suites/*.sh; do
		if ! grep -q 'lib/assert.sh' "$f"; then
			printf 'PREAMBLE %s does not source lib/assert.sh\n' "${f#"$E2E_DIR"/}"
			rc=1
		fi
	done
	exit "$rc"
	;;
selftest) exec "$E2E_DIR/lib/selftest.sh" ;;
list)
	for s in "$E2E_DIR"/suites/*.sh; do
		printf '%s\n' "$(basename "$s" .sh)"
	done
	exit 0
	;;
report)
	e2e_report "$E2E_DIR/results/$FILE_RUN_ID/findings.jsonl" \
		"$E2E_DIR/results/$FILE_RUN_ID/report.md" "$FILE_RUN_ID"
	printf 'rendered %s\n' "$E2E_DIR/results/$FILE_RUN_ID/report.md"
	exit 0
	;;
file | filedry)
	f="$E2E_DIR/results/$FILE_RUN_ID/findings.jsonl"
	[ -f "$f" ] || die "no findings at $f" 2
	if [ "$MODE" = filedry ]; then
		e2e_file_issues "$f" "$FILE_RUN_ID" --dry-run
	else
		e2e_file_issues "$f" "$FILE_RUN_ID"
	fi
	exit 0
	;;
esac

assert_host_allowlist
assert_tree_clean

# ---- run state -------------------------------------------------------------

E2E_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
[ "$ALLOW_DIRTY" = yes ] && E2E_COMMIT="$E2E_COMMIT-dirty"
E2E_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$E2E_COMMIT"
E2E_RUN_DIR="$E2E_DIR/results/$E2E_RUN_ID"
E2E_LOG_DIR="$E2E_RUN_DIR/logs"
E2E_FINDINGS="$E2E_RUN_DIR/findings.jsonl"
E2E_SSH_CTL_DIR="$(mktemp -d /tmp/e2e-ssh.XXXXXX)"
E2E_ARTIFACT_DIR="$E2E_RUN_DIR/artifacts"
E2E_DRY_PLAN="$E2E_RUN_DIR/dry-run-plan.txt"

mkdir -p "$E2E_LOG_DIR" "$E2E_ARTIFACT_DIR"
: >"$E2E_DRY_PLAN"
: >"$E2E_FINDINGS"

cleanup() {
	local h opts=()
	for h in "$E2E_SERVER_HOST" "$E2E_CLIENT_HOST"; do
		opts=()
		while IFS= read -r o; do opts+=("$o"); done < <(e2e_ssh_opts "$h")
		ssh -O exit "${opts[@]}" >/dev/null 2>&1 || true
	done
	rm -rf "$E2E_SSH_CTL_DIR"
}
trap cleanup EXIT

export E2E_DIR REPO_ROOT E2E_RUN_ID E2E_RUN_DIR E2E_LOG_DIR E2E_FINDINGS
export E2E_COMMIT E2E_SSH_CTL_DIR E2E_KNOWN_FILE E2E_ARTIFACT_DIR
export E2E_DRY_RUN E2E_DRY_PLAN

[ "$E2E_DRY_RUN" = yes ] && printf 'DRY RUN — no guest is contacted and nothing is measured\n'
printf 'bodega e2e  run=%s  commit=%s\n' "$E2E_RUN_ID" "$E2E_COMMIT"
printf 'server=%s  client=%s\n\n' "$E2E_SERVER_HOST" "$E2E_CLIENT_HOST"

# Defaults for a filtered run that skips 10-ship, which is what normally sets
# these. A suite reading an empty base URL builds requests against "/healthz"
# and reports a connection failure as a server defect.
: "${E2E_BASE_URL:=http://$E2E_SERVER_HOST:8080}"
: "${E2E_SERVICE_USER:=bodega}"
# Declared empty rather than left unset: the suites run under `set -u`, so a
# value one suite produces and another reads aborts the reader when the
# producer was filtered out, and an aborted suite reports no verdicts at all.
: "${E2E_APT_VERSION:=}"
export E2E_BASE_URL E2E_SERVICE_USER E2E_APT_VERSION

# ---- suite driver ----------------------------------------------------------

# A suite that dies takes its own checks down, not the run. Every later suite
# still reports, because a harness that stops at the first broken guest tells
# you about one defect per session.
E2E_SHIP="$SHIP"
export E2E_SHIP

RUN_STARTED="$(date -u +%s)"
DEADLINE_HIT=no

for suite_file in "$E2E_DIR"/suites/*.sh; do
	suite="$(basename "$suite_file" .sh)"

	# A deadline turns an overnight hang into a report. Every ssh call already
	# carries its own timeout, so this is the outer belt: it catches a suite
	# that is slow rather than stuck, which no per-command timeout can see.
	if [ "$DEADLINE_MIN" -gt 0 ] && [ "$DEADLINE_HIT" = no ]; then
		elapsed=$((($(date -u +%s) - RUN_STARTED) / 60))
		if [ "$elapsed" -ge "$DEADLINE_MIN" ]; then
			DEADLINE_HIT=yes
			printf '\ndeadline of %s minutes reached; remaining suites are blocked\n' "$DEADLINE_MIN"
		fi
	fi
	if [ "$DEADLINE_HIT" = yes ]; then
		E2E_SUITE="$suite"
		E2E_HOST=local
		e2e_block "${suite%%-*}-DEADLINE" "$suite" "run deadline of ${DEADLINE_MIN}m reached before this suite started"
		continue
	fi

	# 00-preflight is a prerequisite, not a suite you can filter away. It sets
	# the reachability flags every other suite reads, so skipping it turns a
	# filtered run into a wall of BLOCKED and a filter typo into a run that
	# measures nothing.
	case "$suite" in
	00-*) ;;
	*)
		if [ -n "$SUITE_FILTER" ]; then
			case "$suite" in
			"$SUITE_FILTER"*) ;;
			*) continue ;;
			esac
		fi
		;;
	esac

	E2E_SUITE="$suite"
	E2E_HOST="local"
	printf '\n\033[1m── %s\033[0m\n' "$suite"

	set +e
	# shellcheck disable=SC1090  # suite paths are discovered, not fixed
	. "$suite_file"
	suite_rc=$?
	set -e
	if [ "$suite_rc" -ne 0 ]; then
		e2e_record "${suite%%-*}-ABORT" FAIL "suite aborted" \
			"suite runs to completion" "exited $suite_rc" "$suite_file" "$suite_rc" ""
	fi
done

# ---- report ----------------------------------------------------------------

# Two suites sharing a check id make the known-issue map ambiguous and the
# report wrong, and nothing else in the harness would notice.
E2E_SUITE="report"
# A mapping whose check id no verdict carries is an issue the harness does not
# cover yet. Not an error: the row is how you see which open issues still have
# no check behind them, and the alternative is finding out by not finding out.
if [ -z "$SUITE_FILTER" ] && [ "$E2E_DRY_RUN" = no ]; then
	uncovered=""
	while IFS=$'\t' read -r kid kissue _; do
		case "$kid" in '' | '#'*) continue ;; esac
		jq -e --arg id "$kid" 'select(.id==$id)' "$E2E_FINDINGS" >/dev/null 2>&1 ||
			uncovered="$uncovered $kid(#$kissue)"
	done <"$E2E_KNOWN_FILE"
	if [ -n "$uncovered" ]; then
		printf '\nknown issues with no check yet:%s\n' "$uncovered"
	fi
fi

dupes="$(jq -r .id "$E2E_FINDINGS" | sort | uniq -d | tr '\n' ' ')"
if [ -n "$dupes" ]; then
	printf '\nduplicate check ids: %s\n' "$dupes" >&2
	e2e_record IDS-01 FAIL "check ids are unique across suites" "no duplicates" "$dupes" "jq -r .id findings.jsonl | uniq -d" 1 ""
fi

e2e_report "$E2E_FINDINGS" "$E2E_RUN_DIR/report.md" "$E2E_RUN_ID"

printf '\n%s\n' "─────────────────────────────────────────"
printf 'PASS %d   FAIL %d   XFAIL %d   XPASS %d   SKIP %d   BLOCKED %d   DRY %d\n' \
	"$E2E_N_PASS" "$E2E_N_FAIL" "$E2E_N_XFAIL" "$E2E_N_XPASS" "$E2E_N_SKIP" "$E2E_N_BLOCKED" "$E2E_N_DRY"
printf 'report:   %s\n' "$E2E_RUN_DIR/report.md"
printf 'findings: %s\n' "$E2E_FINDINGS"
if [ "$E2E_DRY_RUN" = yes ]; then
	printf 'commands it would run: %s (%d)\n' "$E2E_DRY_PLAN" "$(wc -l <"$E2E_DRY_PLAN" | tr -d ' ')"
fi
if [ "$E2E_N_FAIL" -gt 0 ]; then
	printf 'file them: %s --file %s\n' "$0" "$E2E_RUN_ID"
fi

[ "$E2E_N_FAIL" -eq 0 ] && [ "$E2E_N_BLOCKED" -eq 0 ]
