# shellcheck shell=bash
#
# Verdict recording for the e2e harness. Every check funnels through
# e2e_record, which is the only writer of findings.jsonl.
#
# A would-be FAIL that known-issues.tsv maps to an open issue becomes XFAIL,
# and a would-be PASS with the same mapping becomes XPASS. Without that a
# re-run re-files every issue already on the tracker, and the report drowns in
# failures nobody intends to act on this week.

# Sourcing is idempotent: run.sh loads the libs once, and each suite loads them
# again so a suite can be linted and run on its own. A second load must not
# reset the counters.
[ -n "${E2E_LIB_ASSERT:-}" ] && return 0
E2E_LIB_ASSERT=1

E2E_VERDICTS="PASS FAIL SKIP BLOCKED XFAIL XPASS DRY"

# Counters, read by the runner's summary line.
E2E_N_PASS=0
E2E_N_FAIL=0
E2E_N_SKIP=0
E2E_N_BLOCKED=0
E2E_N_XFAIL=0
E2E_N_XPASS=0
E2E_N_DRY=0

# e2e_known <check-id> -> prints the issue number, or nothing.
e2e_known() {
	[ -f "${E2E_KNOWN_FILE:-}" ] || return 0
	awk -v id="$1" '$0 !~ /^#/ && $1 == id { print $2; exit }' "$E2E_KNOWN_FILE"
}

# e2e_record <id> <verdict> <title> <expected> <actual> <cmd> <rc> <ref>
#
# Writes one JSON object. jq builds it so that a newline or a quote in captured
# output cannot break the record: hand-rolled JSON here would corrupt the file
# on the first multi-line stderr, which is most of them.
e2e_record() {
	local id="$1" verdict="$2" title="$3" expected="$4" actual="$5"
	local cmd="$6" rc="$7" ref="${8:-}"
	local issue

	case " $E2E_VERDICTS " in
	*" $verdict "*) ;;
	*)
		printf 'e2e: unknown verdict %s for %s\n' "$verdict" "$id" >&2
		return 2
		;;
	esac

	# In a dry run nothing was measured, so nothing may be reported as measured.
	# Coercing here rather than at each call site means a suite cannot report a
	# pass it did not earn, however it is written.
	if [ "${E2E_DRY_RUN:-no}" = yes ]; then
		actual="would have run"
		verdict=DRY
	fi

	issue="$(e2e_known "$id")"
	if [ -n "$issue" ]; then
		case "$verdict" in
		FAIL) verdict=XFAIL ;;
		PASS) verdict=XPASS ;;
		esac
	fi

	case "$verdict" in
	PASS) E2E_N_PASS=$((E2E_N_PASS + 1)) ;;
	FAIL) E2E_N_FAIL=$((E2E_N_FAIL + 1)) ;;
	SKIP) E2E_N_SKIP=$((E2E_N_SKIP + 1)) ;;
	BLOCKED) E2E_N_BLOCKED=$((E2E_N_BLOCKED + 1)) ;;
	XFAIL) E2E_N_XFAIL=$((E2E_N_XFAIL + 1)) ;;
	XPASS) E2E_N_XPASS=$((E2E_N_XPASS + 1)) ;;
	DRY) E2E_N_DRY=$((E2E_N_DRY + 1)) ;;
	esac

	jq -cn \
		--arg id "$id" \
		--arg suite "${E2E_SUITE:-unknown}" \
		--arg title "$title" \
		--arg host "${E2E_HOST:-local}" \
		--arg verdict "$verdict" \
		--arg expected "$expected" \
		--arg actual "$actual" \
		--arg cmd "$cmd" \
		--arg ref "$ref" \
		--arg issue "$issue" \
		--arg commit "${E2E_COMMIT:-unknown}" \
		--arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		--argjson rc "${rc:-0}" \
		'{id:$id,suite:$suite,title:$title,host:$host,verdict:$verdict,
		  expected:$expected,actual:$actual,cmd:$cmd,rc:$rc,ref:$ref,
		  issue:(if $issue == "" then null else ($issue|tonumber) end),
		  commit:$commit,ts:$ts}' >>"$E2E_FINDINGS"

	e2e_progress "$verdict" "$id" "$title"
}

# One line per check on the terminal, so a long run is watchable.
e2e_progress() {
	local verdict="$1" id="$2" title="$3" color=""
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		case "$verdict" in
		PASS | XFAIL) color=$'\033[32m' ;;
		FAIL | XPASS) color=$'\033[31m' ;;
		SKIP | BLOCKED) color=$'\033[33m' ;;
		DRY) color=$'\033[36m' ;;
		esac
		printf '%s%-8s\033[0m %-14s %s\n' "$color" "$verdict" "$id" "$title"
	else
		printf '%-8s %-14s %s\n' "$verdict" "$id" "$title"
	fi
}

# check_eq <id> <title> <expected> <actual> [ref] [cmd] [rc]
check_eq() {
	local id="$1" title="$2" expected="$3" actual="$4" ref="${5:-}" cmd="${6:-}" rc="${7:-0}"
	if [ "$expected" = "$actual" ]; then
		e2e_record "$id" PASS "$title" "$expected" "$actual" "$cmd" "$rc" "$ref"
	else
		e2e_record "$id" FAIL "$title" "$expected" "$actual" "$cmd" "$rc" "$ref"
	fi
}

# check_ne <id> <title> <unwanted> <actual> [ref] [cmd] [rc]
check_ne() {
	local id="$1" title="$2" unwanted="$3" actual="$4" ref="${5:-}" cmd="${6:-}" rc="${7:-0}"
	if [ "$unwanted" != "$actual" ]; then
		e2e_record "$id" PASS "$title" "not $unwanted" "$actual" "$cmd" "$rc" "$ref"
	else
		e2e_record "$id" FAIL "$title" "not $unwanted" "$actual" "$cmd" "$rc" "$ref"
	fi
}

# check_contains <id> <title> <needle> <haystack> [ref] [cmd] [rc]
check_contains() {
	local id="$1" title="$2" needle="$3" haystack="$4" ref="${5:-}" cmd="${6:-}" rc="${7:-0}"
	case "$haystack" in
	*"$needle"*)
		e2e_record "$id" PASS "$title" "contains: $needle" "$(e2e_excerpt "$haystack")" "$cmd" "$rc" "$ref"
		;;
	*)
		e2e_record "$id" FAIL "$title" "contains: $needle" "$(e2e_excerpt "$haystack")" "$cmd" "$rc" "$ref"
		;;
	esac
}

# check_lacks <id> <title> <needle> <haystack> [ref] [cmd] [rc]
check_lacks() {
	local id="$1" title="$2" needle="$3" haystack="$4" ref="${5:-}" cmd="${6:-}" rc="${7:-0}"
	case "$haystack" in
	*"$needle"*)
		e2e_record "$id" FAIL "$title" "lacks: $needle" "$(e2e_excerpt "$haystack")" "$cmd" "$rc" "$ref"
		;;
	*)
		e2e_record "$id" PASS "$title" "lacks: $needle" "$(e2e_excerpt "$haystack")" "$cmd" "$rc" "$ref"
		;;
	esac
}

# check_matches <id> <title> <ere> <actual> [ref] [cmd] [rc]
check_matches() {
	local id="$1" title="$2" re="$3" actual="$4" ref="${5:-}" cmd="${6:-}" rc="${7:-0}"
	if printf '%s' "$actual" | grep -Eq -- "$re"; then
		e2e_record "$id" PASS "$title" "matches: $re" "$(e2e_excerpt "$actual")" "$cmd" "$rc" "$ref"
	else
		e2e_record "$id" FAIL "$title" "matches: $re" "$(e2e_excerpt "$actual")" "$cmd" "$rc" "$ref"
	fi
}

e2e_skip() {
	e2e_record "$1" SKIP "$2" "" "${3:-}" "" 0 "${4:-}"
}

e2e_block() {
	e2e_record "$1" BLOCKED "$2" "" "${3:-}" "" 0 "${4:-}"
}

# Keep a record readable: the full output is in logs/, the finding carries a
# excerpt. A 4 MB apt-get transcript inlined into every record makes the
# findings file unreadable and the report useless.
E2E_EXCERPT_BYTES="${E2E_EXCERPT_BYTES:-800}"
e2e_excerpt() {
	local s="$1"
	if [ "${#s}" -le "$E2E_EXCERPT_BYTES" ]; then
		printf '%s' "$s"
	else
		printf '%s… [%d bytes total]' "${s:0:$E2E_EXCERPT_BYTES}" "${#s}"
	fi
}
