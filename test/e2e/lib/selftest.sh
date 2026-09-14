#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# Tests the harness itself, with no guest reachable. `make check` runs this, so
# a broken verdict path fails the merge gate rather than silently turning every
# check in a real run into a PASS.
#
# It does not use assert.sh to check assert.sh: a bug that makes every verdict
# PASS would make such a suite pass too. The assertions here are hand-rolled.

set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=assert.sh
. "$E2E_DIR/lib/assert.sh"
# shellcheck source=remote.sh
. "$E2E_DIR/lib/remote.sh"
# shellcheck source=report.sh
. "$E2E_DIR/lib/report.sh"

fails=0
cases=0

t_ok() {
	cases=$((cases + 1))
	if [ "$2" = "$3" ]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n       want: %s\n       got:  %s\n' "$1" "$2" "$3"
		fails=$((fails + 1))
	fi
}

work="$(mktemp -d "${TMPDIR:-/tmp}/e2e-selftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT

E2E_FINDINGS="$work/findings.jsonl"
E2E_KNOWN_FILE="$work/known.tsv"
E2E_LOG_DIR=""
E2E_SUITE="selftest"
E2E_HOST="local"
E2E_COMMIT="deadbee"
: >"$E2E_FINDINGS"
: >"$E2E_KNOWN_FILE"

# verdict_of <check-id> — the verdict recorded for that id.
verdict_of() { jq -r --arg id "$1" 'select(.id==$id) | .verdict' "$E2E_FINDINGS" | tail -1; }
field_of() { jq -rs --arg id "$1" --arg f "$2" 'map(select(.id==$id)) | last | .[$f]' "$E2E_FINDINGS"; }

# ---- verdict branches ------------------------------------------------------

check_eq SELF-01 "equal values pass" abc abc
t_ok "check_eq match -> PASS" PASS "$(verdict_of SELF-01)"

check_eq SELF-02 "different values fail" abc xyz
t_ok "check_eq mismatch -> FAIL" FAIL "$(verdict_of SELF-02)"

check_ne SELF-03 "unwanted absent" 404 200
t_ok "check_ne differs -> PASS" PASS "$(verdict_of SELF-03)"

check_ne SELF-04 "unwanted present" 404 404
t_ok "check_ne equal -> FAIL" FAIL "$(verdict_of SELF-04)"

check_contains SELF-05 "needle present" "cargo" "apt git cargo npm"
t_ok "check_contains hit -> PASS" PASS "$(verdict_of SELF-05)"

check_contains SELF-06 "needle absent" "cargo" "apt git npm"
t_ok "check_contains miss -> FAIL" FAIL "$(verdict_of SELF-06)"

check_lacks SELF-07 "forbidden absent" "secret" "nothing to see"
t_ok "check_lacks miss -> PASS" PASS "$(verdict_of SELF-07)"

check_lacks SELF-08 "forbidden present" "secret" "the secret token"
t_ok "check_lacks hit -> FAIL" FAIL "$(verdict_of SELF-08)"

check_matches SELF-09 "regex matches" '^bodega v?[0-9]' "bodega v0.1.0"
t_ok "check_matches hit -> PASS" PASS "$(verdict_of SELF-09)"

check_matches SELF-10 "regex misses" '^bodega v?[0-9]' "bodega dev"
t_ok "check_matches miss -> FAIL" FAIL "$(verdict_of SELF-10)"

e2e_skip SELF-11 "skipped by design" "helm not installed"
t_ok "e2e_skip -> SKIP" SKIP "$(verdict_of SELF-11)"

e2e_block SELF-12 "blocked by a prior failure" "SHIP-03 failed"
t_ok "e2e_block -> BLOCKED" BLOCKED "$(verdict_of SELF-12)"

# ---- known-issue mapping ---------------------------------------------------

printf '%s\t%s\t%s\n' SELF-20 319 "npm version-manifest route" >>"$E2E_KNOWN_FILE"
printf '%s\t%s\t%s\n' SELF-21 320 "tests read host paths" >>"$E2E_KNOWN_FILE"

check_eq SELF-20 "a mapped failure is expected" want got
t_ok "mapped FAIL -> XFAIL" XFAIL "$(verdict_of SELF-20)"
t_ok "XFAIL carries the issue number" 319 "$(field_of SELF-20 issue)"

check_eq SELF-21 "a mapped pass means it was fixed" same same
t_ok "mapped PASS -> XPASS" XPASS "$(verdict_of SELF-21)"

check_eq SELF-22 "an unmapped pass stays a pass" same same
t_ok "unmapped PASS -> PASS" PASS "$(verdict_of SELF-22)"
t_ok "unmapped check has a null issue" null "$(field_of SELF-22 issue)"

# A comment line in the TSV must not match an id.
printf '#%s\t%s\n' SELF-23 999 >>"$E2E_KNOWN_FILE"
check_eq SELF-23 "a commented mapping does not apply" a b
t_ok "commented mapping ignored" FAIL "$(verdict_of SELF-23)"

# ---- record integrity ------------------------------------------------------

nasty=$'line one\nline "two" \\ backslash\ttab\n$(whoami) `id`'
check_contains SELF-30 "output with quotes and newlines survives" "line one" "$nasty"
t_ok "hostile output stays valid JSON" PASS "$(verdict_of SELF-30)"
t_ok "hostile output round-trips" "$nasty" "$(field_of SELF-30 actual)"

t_ok "every record is one valid JSON object" ok \
	"$(jq -e -s 'all(type=="object")' "$E2E_FINDINGS" >/dev/null && echo ok || echo broken)"

long="$(head -c 3000 </dev/zero | tr '\0' 'x')"
check_contains SELF-31 "long output is excerpted" "x" "$long"
t_ok "excerpt is truncated" truncated \
	"$([ "${#long}" -gt "$(printf '%s' "$(field_of SELF-31 actual)" | wc -c | tr -d ' ')" ] && echo truncated || echo whole)"

t_ok "commit is stamped on every record" deadbee "$(field_of SELF-01 commit)"

# ---- guards ----------------------------------------------------------------

set +e
e2e_record SELF-40 NONSENSE "bogus verdict" "" "" "" 0 "" 2>/dev/null
rc=$?
set -e
t_ok "an unknown verdict is refused" 2 "$rc"

t_ok "server alias resolves" "bodega-server.oak.cow.org" "$(e2e_host_for server)"
t_ok "client alias resolves" "bodega-client.oak.cow.org" "$(e2e_host_for client)"

set +e
e2e_host_for prod >/dev/null 2>&1
rc=$?
set -e
t_ok "an unknown alias is refused" 2 "$rc"

set +e
e2e_host_for bodega.cow.org >/dev/null 2>&1
rc=$?
set -e
t_ok "the production hostname is not an alias" 2 "$rc"

# ---- counters --------------------------------------------------------------

t_ok "PASS counter agrees with the file" \
	"$(jq -rs '[.[]|select(.verdict=="PASS")]|length' "$E2E_FINDINGS")" "$E2E_N_PASS"
t_ok "FAIL counter agrees with the file" \
	"$(jq -rs '[.[]|select(.verdict=="FAIL")]|length' "$E2E_FINDINGS")" "$E2E_N_FAIL"

# ---- report ----------------------------------------------------------------

e2e_report "$E2E_FINDINGS" "$work/report.md" selftest-run
t_ok "report renders" yes "$([ -s "$work/report.md" ] && echo yes || echo no)"
t_ok "report names a failing check" yes \
	"$(grep -q 'SELF-02' "$work/report.md" && echo yes || echo no)"
t_ok "report has an XPASS section" yes \
	"$(grep -q 'Fixed (XPASS)' "$work/report.md" && echo yes || echo no)"
t_ok "report has a blocked section" yes \
	"$(grep -q '## Blocked' "$work/report.md" && echo yes || echo no)"

E2E_SEVERITY=M
# Captured to a variable rather than piped into grep -q: under `set -o pipefail`
# grep's early exit SIGPIPEs the producer, and the whole substitution reports
# failure for a match. The same shape would misread any suite that pipes a
# command's output into a short-circuiting reader.
dryrun="$(e2e_file_issues "$E2E_FINDINGS" selftest-run --dry-run)"
t_ok "issue filing dry-run names each failure" yes \
	"$(case "$dryrun" in *'would file: [SELF-02]'*) echo yes ;; *) echo no ;; esac)"
t_ok "issue filing dry-run skips mapped failures" yes \
	"$(case "$dryrun" in *SELF-20*) echo no ;; *) echo yes ;; esac)"

# ---- verdict ---------------------------------------------------------------

printf '\n%d case(s), %d failure(s)\n' "$cases" "$fails"
[ "$fails" -eq 0 ]
