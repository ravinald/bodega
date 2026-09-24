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

E2E_SERVER_HOST="server.example.com"
E2E_CLIENT_HOST="client.example.com"
t_ok "server alias resolves" "server.example.com" "$(e2e_host_for server)"
t_ok "client alias resolves" "client.example.com" "$(e2e_host_for client)"

set +e
e2e_host_for prod >/dev/null 2>&1
rc=$?
set -e
t_ok "an unknown alias is refused" 2 "$rc"

set +e
e2e_host_for bodega.example.com >/dev/null 2>&1
rc=$?
set -e
t_ok "a hostname is not an alias" 2 "$rc"

E2E_FREEBSD_HOST="freebsd.example.com"
E2E_FREEBSD_SERVER_HOST="freebsd-server.example.com"
t_ok "freebsd alias resolves E2E_FREEBSD_HOST" "freebsd.example.com" "$(e2e_host_for freebsd)"
t_ok "freebsd-server alias resolves its own variable" "freebsd-server.example.com" "$(e2e_host_for freebsd-server)"

# freebsd-client was the FreeBSD client's alias before freebsd replaced it. A
# suite still naming it must fail closed, not reach whatever it used to mean.
set +e
e2e_host_for freebsd-client >/dev/null 2>&1
rc=$?
set -e
t_ok "the retired freebsd-client alias is refused" 2 "$rc"

# run.sh's guards, driven end to end. ssh and every resolver are stubbed to
# leave a mark, so a guard that lets the run reach a host shows up as a mark
# rather than as whatever that host happens to answer.
mkdir -p "$work/bin"
for tool in ssh scp dig host getent dscacheutil; do
	printf '#!/bin/sh\ntouch "%s/contacted"\nexit 1\n' "$work" >"$work/bin/$tool"
	chmod +x "$work/bin/$tool"
done

# run_guard <expected-substring> [VAR=value ...] — runs run.sh --dry-run with
# only the named hosts configured and echoes "<rc>|<matched>|<contacted>".
run_guard() {
	local want="$1" out rc
	shift
	rm -f "$work/contacted"
	set +e
	out="$(env -u E2E_SERVER_HOST -u E2E_CLIENT_HOST -u E2E_FREEBSD_HOST \
		-u E2E_FREEBSD_SERVER_HOST -u E2E_FREEBSD_CLIENT_HOST -u E2E_ALLOWED_HOSTS \
		-u E2E_LIB_REMOTE -u E2E_LIB_ASSERT -u E2E_LIB_REPORT \
		E2E_HOSTS_ENV=/dev/null PATH="$work/bin:$PATH" "$@" \
		bash "$E2E_DIR/run.sh" --dry-run 2>&1)"
	rc=$?
	set -e
	printf '%s|%s|%s' "$rc" \
		"$(case "$out" in *"$want"*) echo matched ;; *) echo "missing: $out" ;; esac)" \
		"$([ -e "$work/contacted" ] && echo contacted || echo untouched)"
}

three=(E2E_SERVER_HOST=s.example E2E_CLIENT_HOST=c.example E2E_FREEBSD_SERVER_HOST=fs.example)
t_ok "an unset E2E_FREEBSD_HOST refuses by name before contact" "3|matched|untouched" \
	"$(run_guard "E2E_FREEBSD_HOST is unset" "${three[@]}" \
		E2E_ALLOWED_HOSTS="s.example c.example fs.example")"
t_ok "the retired variable name is refused with the rename" "3|matched|untouched" \
	"$(run_guard "the freebsd-client alias is now freebsd" "${three[@]}" \
		E2E_FREEBSD_CLIENT_HOST=f.example E2E_ALLOWED_HOSTS="s.example c.example fs.example f.example")"
t_ok "an unlisted freebsd host is refused before contact" "3|matched|untouched" \
	"$(run_guard "refusing to run: prod.example is not a dev guest" "${three[@]}" \
		E2E_FREEBSD_HOST=prod.example E2E_ALLOWED_HOSTS="s.example c.example fs.example f.example")"

# A dry run walks every suite to its last check and changes nothing on this
# workstation. Suite 48 once deleted its build output and then blocked on the
# missing file, so its plan stopped before the guest was touched and still
# exited 0. It runs from a copy under a scratch repo root, so the results it
# writes and the binary it must leave alone are both inside $work.
dry_root="$work/dry-repo"
mkdir -p "$dry_root/test" "$dry_root/dist" "$work/drybin"
(cd "$E2E_DIR" && tar --exclude ./results --exclude ./hosts.env -cf - .) |
	(mkdir -p "$dry_root/test/e2e" && cd "$dry_root/test/e2e" && tar -xf -)
printf 'an earlier build\n' >"$dry_root/dist/storage-freebsd-arm64.test"
chmod +x "$dry_root/dist/storage-freebsd-arm64.test"
printf '#!/bin/sh\necho deadbee\n' >"$work/drybin/git"
# run.sh's exit trap closes each host's control socket with `ssh -O exit`,
# which reaches a local socket and never a guest.
# shellcheck disable=SC2016  # $a expands in the stub, not here
printf '#!/bin/sh\nfor a; do [ "$a" = -O ] && exit 1; done\ntouch "%s/contacted"\nexit 1\n' \
	"$work" >"$work/drybin/ssh"
# Preflight resolves each name on this workstation even in a dry run. A lookup
# is not contact with a guest, so here it fails quietly instead of marking.
for tool in dig host getent dscacheutil; do
	printf '#!/bin/sh\nexit 1\n' >"$work/drybin/$tool"
	chmod +x "$work/drybin/$tool"
done
chmod +x "$work/drybin/git" "$work/drybin/ssh"
rm -f "$work/contacted"
set +e
env -u E2E_LIB_REMOTE -u E2E_LIB_ASSERT -u E2E_LIB_REPORT -u E2E_FREEBSD_CLIENT_HOST \
	E2E_HOSTS_ENV=/dev/null PATH="$work/drybin:$work/bin:$PATH" \
	E2E_SERVER_HOST=s.example E2E_CLIENT_HOST=c.example \
	E2E_FREEBSD_HOST=f.example E2E_FREEBSD_SERVER_HOST=fs.example \
	E2E_ALLOWED_HOSTS="s.example c.example f.example fs.example" \
	bash "$dry_root/test/e2e/run.sh" --dry-run --suite 48- >/dev/null 2>&1
dry_rc=$?
set -e
dry_dir="$(find "$dry_root/test/e2e/results" -mindepth 1 -maxdepth 1 -type d | head -1)"
dry_plan="$(cat "$dry_dir/dry-run-plan.txt" 2>/dev/null || true)"
dry_ids="$(jq -r 'select(.suite=="48-freebsd-server") | .id' "$dry_dir/findings.jsonl" 2>/dev/null || true)"
t_ok "a dry run of suite 48 exits 0" 0 "$dry_rc"
# A dry run records a block as DRY, so the id is what shows the suite stopped.
t_ok "a dry run of suite 48 blocks nothing" none \
	"$(printf '%s\n' "$dry_ids" | awk '/^FSRV-BLOCK-/ {b = b $0 " "} END {print (b ? b : "none")}')"
t_ok "a dry run of suite 48 reaches all 32 cells" 32 \
	"$(printf '%s\n' "$dry_ids" | awk '/^FSRV-(ZFS|UFS)-(USER|ROOT)-0[1-8]$/' | wc -l | tr -d ' ')"
t_ok "a dry run of suite 48 reaches its last check" yes \
	"$(printf '%s\n' "$dry_ids" | awk '$0 == "FSRV-05" {f = 1} END {print (f ? "yes" : "no")}')"
for want in 'local: rm -f' 'local: env GOOS=freebsd' 'mdconfig -a -t swap' \
	'storage.test -test.run' 'umount'; do
	t_ok "the suite 48 plan lists $want" yes \
		"$(case "$dry_plan" in *"$want"*) echo yes ;; *) echo no ;; esac)"
done
t_ok "a dry run leaves an existing build output alone" 'an earlier build' \
	"$(cat "$dry_root/dist/storage-freebsd-arm64.test" 2>/dev/null || echo deleted)"
t_ok "a dry run contacts no guest" untouched \
	"$([ -e "$work/contacted" ] && echo contacted || echo untouched)"

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
