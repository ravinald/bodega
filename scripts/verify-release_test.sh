#!/usr/bin/env bash
#
# Offline tests for verify-release.sh. Stub gh and cosign executables sit
# first on PATH and record every call, so each case asserts both the exit
# code and what the script asked the verifiers to check.
#
# The configuration checks match workflow and document text that holds a
# literal $ or backtick, so single quotes are the point there.
# shellcheck disable=SC2016

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT=$ROOT/scripts/verify-release.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

STUBS=$WORK/bin
mkdir -p "$STUBS"

cat >"$STUBS/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$STUB_LOG"
case "$1 $2" in
"release list") printf '%s\n' "${STUB_RELEASE_LIST:-[]}" ;;
"release download")
	while [ $# -gt 0 ]; do
		[ "$1" = --dir ] && cp "$STUB_RELEASE_SRC"/* "$2"/
		shift
	done
	;;
"release edit") ;;
"attestation verify")
	if [ "$3" = "${STUB_GH_REFUSE:-}" ]; then
		echo "Error: no attestations found for subject $3" >&2
		exit 1
	fi
	;;
*)
	echo "gh stub: unexpected call: $*" >&2
	exit 99
	;;
esac
EOF

cat >"$STUBS/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'cosign %s\n' "$*" >>"$STUB_LOG"
case "${STUB_COSIGN_FAIL:-} $*" in
"bundle "*--bundle*)
	echo "Error: bundle does not verify" >&2
	exit 1
	;;
"legacy "*--signature*)
	echo "Error: signature does not verify" >&2
	exit 1
	;;
esac
echo "Verified OK"
EOF
chmod +x "$STUBS/gh" "$STUBS/cosign"

export PATH="$STUBS:$PATH"
export STUB_LOG=$WORK/calls.log

if command -v sha256sum >/dev/null 2>&1; then
	sha() { sha256sum "$1" | awk '{print $1}'; }
else
	sha() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

ASSETS=(bodega_9.9.9_linux_amd64.tar.gz bodega_9.9.9_amd64.deb bodega_9.9.9_linux_amd64.tar.gz.sbom.json)
IDENTITY=https://github.com/ravinald/bodega/.github/workflows/release-build.yml@refs/tags/v9.9.9
ISSUER=https://token.actions.githubusercontent.com

good_set() {
	rm -rf "$1"
	mkdir -p "$1"
	local a
	for a in "${ASSETS[@]}"; do
		printf 'contents of %s\n' "$a" >"$1/$a"
		printf '%s  %s\n' "$(sha "$1/$a")" "$a" >>"$1/checksums-sha256.txt"
	done
	echo bundle >"$1/checksums-sha256.txt.sigstore.json"
	echo sig >"$1/checksums-sha256.txt.sig"
	echo pem >"$1/checksums-sha256.txt.pem"
}

failures=0
current=

case_start() {
	current=$1
	: >"$STUB_LOG"
	unset STUB_GH_REFUSE STUB_COSIGN_FAIL STUB_RELEASE_LIST STUB_RELEASE_SRC
	rm -f "$STUBS/sha256sum"
}

run() {
	rc=0
	out=$("$@" 2>&1) || rc=$?
}

check() {
	local what=$1
	shift
	if "$@"; then
		return 0
	fi
	echo "FAIL [$current] $what"
	printf '%s\n' "--- output:" "$out" "--- calls:" "$(cat "$STUB_LOG")" "---" | sed 's/^/    /'
	failures=$((failures + 1))
}

exit_is() { check "exit $1, got $rc" test "$rc" -eq "$1"; }
says() { check "output contains '$1'" grep -qF -- "$1" <<<"$out"; }
lacks() { ! grep -qF -- "$1" <<<"$2"; }
never_says() { check "output lacks '$1'" lacks "$1" "$out"; }
calls() { grep -c -- "$1" "$STUB_LOG" || true; }
calls_are() { check "$2 calls matching '$1', got $(calls "$1")" test "$(calls "$1")" -eq "$2"; }

D=$WORK/release

case_start "a: good set"
good_set "$D"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 0
says "verified v9.9.9: 3 files verified, 0 failed"
want_cosign="cosign verify-blob --bundle checksums-sha256.txt.sigstore.json --certificate-identity $IDENTITY --certificate-oidc-issuer $ISSUER checksums-sha256.txt
cosign verify-blob --certificate checksums-sha256.txt.pem --signature checksums-sha256.txt.sig --certificate-identity $IDENTITY --certificate-oidc-issuer $ISSUER checksums-sha256.txt"
check "exactly the two verify-blob calls, bundle first" test "$(grep '^cosign' "$STUB_LOG")" = "$want_cosign"
want_gh=
for a in "${ASSETS[@]}"; do
	want_gh+="gh attestation verify $a --repo ravinald/bodega --signer-workflow ravinald/bodega/.github/workflows/release-build.yml --source-ref refs/tags/v9.9.9 --deny-self-hosted-runners"$'\n'
done
check "one attestation verify per listed file, exact flags" test "$(grep '^gh' "$STUB_LOG")"$'\n' = "$want_gh"
for a in "${ASSETS[@]}"; do says "ok    $a"; done

case_start "b: asset changed after checksumming"
good_set "$D"
echo tampered >>"$D/bodega_9.9.9_amd64.deb"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "FAIL  bodega_9.9.9_amd64.deb: SHA-256 mismatch"
says "must not be published or installed"
says "SECURITY.md"
never_says "verified"

case_start "c: one attestation refused"
good_set "$D"
export STUB_GH_REFUSE=bodega_9.9.9_amd64.deb
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "FAIL  bodega_9.9.9_amd64.deb: attestation did not verify"
says "no attestations found for subject bodega_9.9.9_amd64.deb"
for a in "${ASSETS[@]}"; do calls_are "^gh attestation verify $a " 1; done
says "ok    bodega_9.9.9_linux_amd64.tar.gz"
never_says "verified"

case_start "d1: bundle signature fails"
good_set "$D"
export STUB_COSIGN_FAIL=bundle
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "FAIL  checksums-sha256.txt: signature (Sigstore bundle"
says "ok    checksums-sha256.txt: signature (legacy"

case_start "d2: legacy signature fails"
good_set "$D"
export STUB_COSIGN_FAIL=legacy
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "FAIL  checksums-sha256.txt: signature (legacy checksums-sha256.txt.sig/checksums-sha256.txt.pem)"
says "ok    checksums-sha256.txt: signature (Sigstore bundle"

case_start "e: listed file missing"
good_set "$D"
rm "$D/bodega_9.9.9_amd64.deb"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "FAIL  bodega_9.9.9_amd64.deb: listed in checksums-sha256.txt but missing"

case_start "f: unlisted extra file"
good_set "$D"
echo extra >"$D/extra.tar.gz"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "FAIL  extra.tar.gz: present but not listed"

for evil in ../evil sub/evil; do
	case_start "g: checksum line naming $evil"
	good_set "$D"
	printf '%s  %s\n' "$(sha "$D/${ASSETS[0]}")" "$evil" >>"$D/checksums-sha256.txt"
	run "$SCRIPT" v9.9.9 --dir "$D"
	exit_is 1
	says "checksums-sha256.txt line 4: '$evil' is not a plain file name"
	calls_are "attestation verify" 0
done

case_start "g2: checksum line that does not parse"
good_set "$D"
echo "DEADBEEF  bodega.tar.gz" >>"$D/checksums-sha256.txt"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "checksums-sha256.txt line 4: not"
calls_are "attestation verify" 0

case_start "h: empty checksum file"
good_set "$D"
rm "$D"/bodega_*
: >"$D/checksums-sha256.txt"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "lists no files"
never_says "verified"

case_start "i: tag with shell metacharacters"
run "$SCRIPT" 'v1.0.0;id'
exit_is 2
says "'v1.0.0;id' is not a release tag"
check "neither stub invoked" test ! -s "$STUB_LOG"

case_start "i2: unknown flag"
run "$SCRIPT" v9.9.9 --frobnicate
exit_is 2
says "unknown flag '--frobnicate'"
check "neither stub invoked" test ! -s "$STUB_LOG"

case_start "i3: missing tools"
mkdir -p "$WORK/only-gh"
cp "$STUBS/gh" "$WORK/only-gh/gh"
run env PATH="$WORK/only-gh" "$BASH" "$SCRIPT" v9.9.9
exit_is 2
says "cosign is not on PATH"
run env PATH="$WORK/empty" "$BASH" "$SCRIPT" v9.9.9
exit_is 2
says "gh is not on PATH"
mkdir -p "$WORK/no-sha"
cp "$STUBS/gh" "$STUBS/cosign" "$WORK/no-sha/"
run env PATH="$WORK/no-sha" "$BASH" "$SCRIPT" v9.9.9
exit_is 2
says "neither sha256sum nor shasum is on PATH"
check "neither stub invoked" test ! -s "$STUB_LOG"

case_start "j: --latest with no release"
export STUB_RELEASE_LIST='[]'
run "$SCRIPT" --latest
exit_is 3
says "no release yet: ravinald/bodega has no published release; nothing was checked"
check "no verifier called" test "$(calls 'verify')" -eq 0
check "the no-release line is all it prints" test "$out" = "no release yet: ravinald/bodega has no published release; nothing was checked"
calls_are "^gh release list --repo ravinald/bodega --exclude-drafts --limit 1 --json tagName$" 1

case_start "k: --latest resolves and downloads v9.9.9"
good_set "$D"
export STUB_RELEASE_LIST='[{"tagName":"v9.9.9"}]' STUB_RELEASE_SRC=$D
run "$SCRIPT" --latest
exit_is 0
says "verified v9.9.9: 3 files verified, 0 failed"
calls_are "^gh release download v9.9.9 --repo ravinald/bodega --dir " 1
calls_are "--source-ref refs/tags/v9.9.9 " 3

case_start "l: no Sigstore bundle"
good_set "$D"
rm "$D/checksums-sha256.txt.sigstore.json"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "FAIL  checksums-sha256.txt.sigstore.json: missing from the release"
calls_are "--bundle" 0

case_start "help"
run "$SCRIPT" --help
exit_is 0
says "Exit codes:"
says "Needs: gh"

case_start "R5: unlisted filename contains a newline"
good_set "$D"
extra="${ASSETS[0]}"$'\n'"${ASSETS[1]}"
echo unattested >"$D/$extra"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says 'present but not listed'

case_start "R4: NUL byte in checksum line"
good_set "$D"
printf '\0' >"$D/checksums.bad"
cat "$D/checksums-sha256.txt" >>"$D/checksums.bad"
mv "$D/checksums.bad" "$D/checksums-sha256.txt"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says 'line 1:'
calls_are 'attestation verify' 0

case_start "R7: hash read failure continues"
good_set "$D"
cat >"$STUBS/sha256sum" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *bodega_9.9.9_amd64.deb* ]]; then
    echo "sha256sum: bodega_9.9.9_amd64.deb: Input/output error" >&2
    exit 1
fi
shasum -a 256 "$@"
EOF
chmod +x "$STUBS/sha256sum"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says 'FAIL  bodega_9.9.9_amd64.deb:'
says 'ok    bodega_9.9.9_linux_amd64.tar.gz.sbom.json'
says 'must not be published or installed'
calls_are 'attestation verify bodega_9.9.9_linux_amd64.tar.gz.sbom.json ' 1
rm "$STUBS/sha256sum"

case_start "R7: double failure counts files once"
good_set "$D"
echo tampered >>"$D/bodega_9.9.9_amd64.deb"
export STUB_GH_REFUSE=bodega_9.9.9_amd64.deb
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
check "one result line for a file with two failed checks" test "$(grep -c '^FAIL  bodega_9.9.9_amd64.deb:' <<<"$out")" -eq 1
says '2 files ok, 1 failed'

case_start "R1: explicit empty --dir never downloads"
run "$SCRIPT" v9.9.9 --dir ''
exit_is 2
calls_are '^gh release download' 0

case_start "R9: no-release output contains no verified word"
export STUB_RELEASE_LIST='[]'
run "$SCRIPT" --latest
exit_is 3
says 'no release yet'
never_says 'verified'

case_start "R1: --dir= with no value never downloads"
run "$SCRIPT" v9.9.9 --dir=
exit_is 2
says "--dir needs a non-empty path"
check "neither stub invoked" test ! -s "$STUB_LOG"

case_start "R7: hash failure and digest mismatch keep both reasons"
good_set "$D"
echo tampered >>"$D/bodega_9.9.9_amd64.deb"
export STUB_GH_REFUSE=bodega_9.9.9_amd64.deb
run "$SCRIPT" v9.9.9 --dir "$D"
says "FAIL  bodega_9.9.9_amd64.deb: SHA-256 mismatch"
says "; attestation did not verify"
says "no attestations found for subject bodega_9.9.9_amd64.deb"

case_start "R4: control character in a listed name"
good_set "$D"
printf '%s  %s\n' "$(sha "$D/${ASSETS[0]}")" $'evil\rname' >>"$D/checksums-sha256.txt"
run "$SCRIPT" v9.9.9 --dir "$D"
exit_is 1
says "checksums-sha256.txt line 4: 'evil?name' is not a plain file name"
calls_are "attestation verify" 0

# The release configuration and workflows are checked as files: the script
# cannot gate a release whose draft setting, publish guard or cosign pin is
# gone, and nothing else in the tree reads them.

# Prints the YAML block opened by the first line matching $2, through the last
# line indented deeper than it.
section() {
	awk -v re="$2" '
		!on && $0 ~ re { on = 1; match($0, /^ */); base = RLENGTH; print; next }
		on && /^ *$/ { print; next }
		on { match($0, /^ */); if (RLENGTH <= base) exit; print }
	' "$1"
}

# Prints the `run: |` body of the step named $2, dedented.
run_block() {
	awk -v want="- name: $2" '
		!found && index($0, want) { found = 1; next }
		found && !body && /run: \|$/ { body = 1; match($0, /^ */); base = RLENGTH; next }
		body && /^ *$/ { print ""; next }
		body {
			match($0, /^ */)
			if (RLENGTH <= base) exit
			if (!ind) ind = RLENGTH
			print substr($0, ind + 1)
		}
	' "$1"
}

# Prints a job's permissions as "scope: level" lines, comments dropped.
job_permissions() {
	awk '
		/^    permissions:/ { on = 1; next }
		on && !/^      / { exit }
		on { sub(/ *#.*/, ""); sub(/^ +/, ""); if ($0 != "") print }
	' <<<"$1"
}

# Prints the lines of the GoReleaser signs entry whose id is $1.
sign_entry() {
	section "$ROOT/.goreleaser.yaml" '^signs:$' | awk -v id="  - id: $1" '
		$0 == id { on = 1; print; next }
		on && /^  - / { exit }
		on { print }
	'
}

has_line() { grep -qxF -- "$1" <<<"$2"; }
lacks_line() { ! grep -qF -- "$1" <<<"$2"; }
before() {
	local a b
	a=$(grep -nF -- "$1" <<<"$3" | head -n 1 | cut -d: -f1)
	b=$(grep -nF -- "$2" <<<"$3" | head -n 1 | cut -d: -f1)
	[ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

WF=$ROOT/.github/workflows
CHECKOUT_PIN=$(grep -o 'actions/checkout@[0-9a-f]\{40\}' "$WF/release-build.yml" | head -n 1)
COSIGN_PIN=$(grep -o 'sigstore/cosign-installer@[0-9a-f]\{40\}' "$WF/release-build.yml" | head -n 1)

# Runs a workflow step's run block the way GitHub's bash shell does, from a
# directory whose scripts/verify-release.sh is the real script.
run_step() {
	local wd=$WORK/step
	rm -rf "$wd"
	mkdir -p "$wd/scripts" "$wd/tmp"
	ln -s "$SCRIPT" "$wd/scripts/verify-release.sh"
	: >"$wd/summary"
	rc=0
	out=$(cd "$wd" && RUNNER_TEMP=$wd/tmp GITHUB_STEP_SUMMARY=$wd/summary \
		bash --noprofile --norc -eo pipefail -c "$1" 2>&1) || rc=$?
	summary_text=$(cat "$wd/summary")
}

case_start "R11: GoReleaser leaves the release a draft and replaces a failed one"
rel=$(section "$ROOT/.goreleaser.yaml" '^release:$')
check "release.draft is true" has_line "  draft: true" "$rel"
check "release.replace_existing_draft is true" has_line "  replace_existing_draft: true" "$rel"

case_start "R20: two signs entries over the checksum file"
check "exactly two signs entries" test "$(section "$ROOT/.goreleaser.yaml" '^signs:$' | grep -c '^  - id: ')" -eq 2
bundle=$(sign_entry checksum-bundle)
for l in "    cmd: cosign" "    signature: '\${artifact}.sigstore.json'" "      - sign-blob" \
	"      - '--bundle=\${signature}'" "      - '\${artifact}'" "      - '--yes'" "    artifacts: checksum"; do
	check "bundle entry has '$l'" has_line "$l" "$bundle"
done
check "bundle entry has no certificate" lacks_line "certificate" "$bundle"
check "bundle entry passes no service URL" lacks_line "--oidc-issuer" "$bundle"
legacy=$(sign_entry checksum-legacy)
for l in "    cmd: cosign" "    signature: '\${artifact}.sig'" "    certificate: '\${artifact}.pem'" \
	"      - sign-blob" "      - '--new-bundle-format=false'" "      - '--use-signing-config=false'" \
	"      - '--output-certificate=\${certificate}'" "      - '--output-signature=\${signature}'" \
	"      - '\${artifact}'" "      - '--yes'" "    artifacts: checksum"; do
	check "legacy entry has '$l'" has_line "$l" "$legacy"
done

case_start "R21: every cosign installer pins cosign v3.0.6"
for f in release-build.yml release.yml release-verify.yml; do
	pinned=$(awk '
		/uses: sigstore\/cosign-installer@/ { n++; getline w; getline r
			if (w ~ /^ +with:$/ && r ~ /^ +cosign-release: .v3\.0\.6.$/) ok++ }
		END { print n + 0, ok + 0 }
	' "$WF/$f")
	check "$f: one cosign installer, pinned to cosign v3.0.6 (installers, pinned: $pinned)" test "$pinned" = "1 1"
	check "$f: cosign installer pin matches release-build.yml" grep -qF "$COSIGN_PIN" "$WF/$f"
done

case_start "R12: release.yml publishes the draft only after the script passes"
pub=$(section "$WF/release.yml" '^  publish:$')
check "publish job needs build" has_line "    needs: build" "$pub"
check "publish permissions are contents: write and attestations: read" \
	test "$(job_permissions "$pub")" = $'contents: write\nattestations: read'
check "publish job holds no id-token" lacks_line "id-token" "$pub"
check "publish checks out with release-build.yml's checkout pin" grep -qF "$CHECKOUT_PIN" <<<"$pub"
check "publish checks out without persisted credentials" has_line "          persist-credentials: false" "$pub"
check "the tag reaches the step through env" has_line '          TAG: ${{ github.ref_name }}' "$pub"
block=$(run_block "$WF/release.yml" "Verify the draft, then publish it")
check "publish run block is not empty" test -n "$block"
check "publish run block interpolates no expression" lacks_line '${{' "$block"
good_set "$D"
export STUB_RELEASE_SRC=$D
TAG=v9.9.9 run_step "$block"
exit_is 0
calls_are "^gh release download v9.9.9 --repo ravinald/bodega --dir " 1
calls_are "^gh release edit v9.9.9 --repo ravinald/bodega --draft=false$" 1
check "verified before publishing" before "gh attestation verify" "gh release edit" "$(cat "$STUB_LOG")"

case_start "R12: a draft that fails verification stays unpublished"
good_set "$D"
echo tampered >>"$D/bodega_9.9.9_amd64.deb"
export STUB_RELEASE_SRC=$D
TAG=v9.9.9 run_step "$block"
check "step fails, got $rc" test "$rc" -ne 0
calls_are "^gh release edit" 0
says "FAIL  bodega_9.9.9_amd64.deb"
says "::error::release v9.9.9 was not published"
says "per-file ok/FAIL lines above"

case_start "R13: release-verify.yml runs daily and on dispatch, read-only"
nightly=$(cat "$WF/release-verify.yml")
cron=$(sed -n "s/^ *- cron: '\(.*\)'$/\1/p" <<<"$nightly")
check "one daily cron, got '$cron'" grep -qE '^[0-9]{1,2} [0-9]{1,2} \* \* \*$' <<<"$cron"
check "workflow_dispatch trigger" has_line "  workflow_dispatch:" "$nightly"
check "top-level permissions are empty" has_line "permissions: {}" "$nightly"
verify_job=$(section "$WF/release-verify.yml" '^  verify:$')
check "job permissions are contents: read and attestations: read" \
	test "$(job_permissions "$verify_job")" = $'contents: read\nattestations: read'
check "checks out main" has_line "          ref: main" "$verify_job"
check "checks out with release-build.yml's checkout pin" grep -qF "$CHECKOUT_PIN" <<<"$verify_job"
block=$(run_block "$WF/release-verify.yml" "Verify the newest release")
check "nightly run block runs --latest" grep -qF "scripts/verify-release.sh --latest" <<<"$block"

case_start "R13: nightly skip when there is no release"
export STUB_RELEASE_LIST='[]'
run_step "$block"
exit_is 0
check "summary is the skip line, got '$summary_text'" test "$summary_text" = "skipped: no release yet"
says "::notice::"
never_says "verified"

case_start "R13: nightly verified release"
good_set "$D"
export STUB_RELEASE_LIST='[{"tagName":"v9.9.9"}]' STUB_RELEASE_SRC=$D
run_step "$block"
exit_is 0
check "summary says verified v9.9.9, got '$summary_text'" grep -qF "verified v9.9.9" <<<"$summary_text"

case_start "R13: nightly failure fails the job"
good_set "$D"
echo tampered >>"$D/bodega_9.9.9_amd64.deb"
export STUB_RELEASE_LIST='[{"tagName":"v9.9.9"}]' STUB_RELEASE_SRC=$D
run_step "$block"
exit_is 1
check "summary does not say verified" lacks "verified" "$summary_text"

md_section() {
	awk -v h="## $2" '$0 == h { on = 1; next } on && /^## / { exit } on { print }' "$1"
}

case_start "R15: SECURITY.md describes the gate and the manual commands in order"
sec=$(md_section "$ROOT/SECURITY.md" "Verifying a release")
for phrase in "scripts/verify-release.sh" "draft" "release.yml" "release-verify.yml" "daily" \
	'git checkout "$VERSION"' 'scripts/verify-release.sh "$VERSION"' \
	'`0` every check passed' '`1` a check failed' '`2` a usage' '`3` `--latest` found no published release'; do
	check "Verifying a release mentions '$phrase'" grep -qF -- "$phrase" <<<"$sec"
done
check "bundle, then the legacy pair, then gh attestation verify" \
	before "--bundle checksums-sha256.txt.sigstore.json" "--certificate checksums-sha256.txt.pem" "$sec"
check "the legacy pair comes before gh attestation verify" \
	before "--certificate checksums-sha256.txt.pem" "gh attestation verify" "$sec"

case_start "R19: docs/slsa.md describes the gate and keeps its open items"
slsa=$(md_section "$ROOT/docs/slsa.md" "bodega's own releases")
for phrase in "draft" "\`release.yml\` publishes it only after \`scripts/verify-release.sh\` has passed" \
	"\`release-verify.yml\` re-checks the newest published release daily" \
	"- **No release has been cut,**" "- **The \`release\` environment carries no protection rule yet.**"; do
	check "bodega's own releases mentions '$phrase'" grep -qF -- "$phrase" <<<"$slsa"
done

case_start "R10: make harness lints and runs both release scripts"
mk=$(awk '/^harness:$/ { on = 1; next } on && !/^\t/ { exit } on { print }' "$ROOT/Makefile")
check "RELEASE_SHELL names both scripts" grep -qxF \
	"RELEASE_SHELL := scripts/verify-release.sh scripts/verify-release_test.sh" "$ROOT/Makefile"
for l in $'\tshellcheck -x $(RELEASE_SHELL)' $'\tshfmt -d $(RELEASE_SHELL)' $'\tscripts/verify-release_test.sh'; do
	check "harness runs '${l#$'\t'}'" has_line "$l" "$mk"
done

case_start "R9: good set under the system Bash"
good_set "$D"
run /bin/bash "$SCRIPT" v9.9.9 --dir "$D"
exit_is 0
says 'verified v9.9.9: 3 files verified, 0 failed'
for a in "${ASSETS[@]}"; do
	calls_are "^gh attestation verify $a " 1
done

if [ "$failures" -ne 0 ]; then
	echo "verify-release_test: $failures check(s) failed"
	exit 1
fi
echo "verify-release_test: all cases passed"
