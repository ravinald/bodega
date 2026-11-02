#!/usr/bin/env bash
#
# Offline tests for verify-release.sh. Stub gh and cosign executables sit
# first on PATH and record every call, so each case asserts both the exit
# code and what the script asked the verifiers to check.

set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify-release.sh"
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
check "neither stub invoked" test ! -s "$STUB_LOG"

case_start "j: --latest with no release"
export STUB_RELEASE_LIST='[]'
run "$SCRIPT" --latest
exit_is 3
says "no release yet: ravinald/bodega has no published release; nothing was verified"
check "no verifier called" test "$(calls 'verify')" -eq 0
check "the no-release line is all it prints" test "$out" = "no release yet: ravinald/bodega has no published release; nothing was verified"
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

if [ "$failures" -ne 0 ]; then
	echo "verify-release_test: $failures check(s) failed"
	exit 1
fi
echo "verify-release_test: all cases passed"
