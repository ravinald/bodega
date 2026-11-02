#!/usr/bin/env bash
#
# Verifies every asset of a bodega release against the signature and the
# provenance release-build.yml produced for it. release.yml runs this against a
# draft and publishes only on exit 0; release-verify.yml runs it daily against
# the newest published release.

set -euo pipefail

REPO=ravinald/bodega
SIGNER_WORKFLOW=.github/workflows/release-build.yml
OIDC_ISSUER=https://token.actions.githubusercontent.com
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
LINE_RE='^([0-9a-f]{64})( \*|  )(.+)$'

CHECKSUMS=checksums-sha256.txt
BUNDLE=$CHECKSUMS.sigstore.json
SIG=$CHECKSUMS.sig
PEM=$CHECKSUMS.pem

usage() {
	cat <<EOF
usage: verify-release.sh {tag} [--dir {path}]
       verify-release.sh --latest [--dir {path}]

Verifies a $REPO release: the cosign signature on $CHECKSUMS in both
formats (the Sigstore bundle $BUNDLE and the
$SIG/$PEM pair), the SHA-256 of every file it lists, and the
GitHub artifact attestation of each of those files, issued to
$SIGNER_WORKFLOW at refs/tags/{tag}.

  {tag}        a release tag such as v1.2.3 or v1.2.3-rc.1
  --latest     the newest published release, prereleases included
  --dir {path} verify the files already in {path} and download nothing;
               without it every asset is downloaded into a temporary
               directory that is removed on exit

Every file is checked; one failure does not stop the rest.

Exit codes:
  0  every check passed
  1  a check failed: do not publish or install the release
  2  usage or input error, or a required tool is missing
  3  --latest found no published release

Needs: gh (signed in, with attestation read access), cosign, and
sha256sum or shasum.
EOF
}

die_usage() {
	echo "verify-release: $1" >&2
	echo "run 'verify-release.sh --help' for usage" >&2
	exit 2
}

tag=
latest=no
dir=
while [ $# -gt 0 ]; do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	--latest) latest=yes ;;
	--dir)
		[ $# -ge 2 ] || die_usage "--dir needs a path"
		dir=$2
		shift
		;;
	--dir=*) dir=${1#--dir=} ;;
	-*) die_usage "unknown flag '$1'" ;;
	*)
		[ -z "$tag" ] || die_usage "one tag only; got '$tag' and '$1'"
		tag=$1
		;;
	esac
	shift
done

if [ "$latest" = yes ] && [ -n "$tag" ]; then
	die_usage "give a tag or --latest, not both"
fi
if [ "$latest" = no ] && [ -z "$tag" ]; then
	die_usage "no tag given; pass a release tag such as v1.2.3, or --latest"
fi
if [ -n "$tag" ] && ! [[ $tag =~ $TAG_RE ]]; then
	die_usage "'$tag' is not a release tag; expected vMAJOR.MINOR.PATCH with an optional -prerelease suffix"
fi
if [ -n "$dir" ] && ! [ -d "$dir" ]; then
	die_usage "--dir '$dir' is not a directory"
fi

for tool in gh cosign; do
	command -v "$tool" >/dev/null 2>&1 ||
		die_usage "$tool is not on PATH; install it (https://cli.github.com, https://docs.sigstore.dev/cosign/system_config/installation/) and retry"
done
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum -- "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 -- "$1" | awk '{print $1}'; }
else
	die_usage "neither sha256sum nor shasum is on PATH; install coreutils or perl's shasum and retry"
fi

if [ "$latest" = yes ]; then
	if ! listing=$(gh release list --repo "$REPO" --exclude-drafts --limit 1 --json tagName); then
		echo "verify-release: gh release list failed for $REPO; check 'gh auth status' and the network" >&2
		exit 1
	fi
	if ! [[ $listing =~ \"tagName\":[[:space:]]*\"([^\"]*)\" ]]; then
		echo "no release yet: $REPO has no published release; nothing was verified"
		exit 3
	fi
	tag=${BASH_REMATCH[1]}
	[[ $tag =~ $TAG_RE ]] ||
		die_usage "the newest release of $REPO carries the tag '$tag', which is not a release tag"
fi

if [ -z "$dir" ]; then
	dir=$(mktemp -d)
	trap 'rm -rf "$dir"' EXIT
	if ! gh release download "$tag" --repo "$REPO" --dir "$dir"; then
		echo "verify-release: could not download the assets of $tag from $REPO; check the tag exists and 'gh auth status'" >&2
		exit 1
	fi
fi
cd "$dir"

verified=0
failed=0

pass() {
	echo "ok    $1"
}

fail() {
	echo "FAIL  $1"
	failed=$((failed + 1))
}

summary() {
	if [ "$failed" -eq 0 ] && [ "$verified" -gt 0 ]; then
		echo "verified $tag: $verified files verified, 0 failed"
		exit 0
	fi
	echo "FAILED $tag: $verified files ok, $failed failed. This release must not be published or installed; report it as SECURITY.md describes."
	exit 1
}

for required in "$CHECKSUMS" "$BUNDLE" "$SIG" "$PEM"; do
	[ -f "$required" ] || fail "$required: missing from the release"
done
[ -f "$CHECKSUMS" ] || summary

identity="https://github.com/$REPO/$SIGNER_WORKFLOW@refs/tags/$tag"

if [ -f "$BUNDLE" ]; then
	if out=$(cosign verify-blob --bundle "$BUNDLE" \
		--certificate-identity "$identity" \
		--certificate-oidc-issuer "$OIDC_ISSUER" \
		"$CHECKSUMS" 2>&1); then
		pass "$CHECKSUMS: signature (Sigstore bundle $BUNDLE)"
	else
		fail "$CHECKSUMS: signature (Sigstore bundle $BUNDLE) did not verify for $identity"
		printf '%s\n' "$out" | sed 's/^/      /'
	fi
fi
if [ -f "$SIG" ] && [ -f "$PEM" ]; then
	if out=$(cosign verify-blob --certificate "$PEM" --signature "$SIG" \
		--certificate-identity "$identity" \
		--certificate-oidc-issuer "$OIDC_ISSUER" \
		"$CHECKSUMS" 2>&1); then
		pass "$CHECKSUMS: signature (legacy $SIG/$PEM)"
	else
		fail "$CHECKSUMS: signature (legacy $SIG/$PEM) did not verify for $identity"
		printf '%s\n' "$out" | sed 's/^/      /'
	fi
fi

# Parsed in full before any file is touched: a name this rejects never reaches
# the hash or gh, and nothing downstream has to treat a name as a path.
names=()
digests=()
listed=$'\n'
lineno=0
bad=0
while IFS= read -r line || [ -n "$line" ]; do
	lineno=$((lineno + 1))
	if ! [[ $line =~ $LINE_RE ]]; then
		fail "$CHECKSUMS line $lineno: not '{64 lowercase hex}  {file name}'"
		bad=1
		continue
	fi
	digest=${BASH_REMATCH[1]}
	name=${BASH_REMATCH[3]}
	case $name in
	*/* | . | .. | -*)
		fail "$CHECKSUMS line $lineno: '$name' is not a plain file name"
		bad=1
		continue
		;;
	esac
	case $listed in
	*$'\n'"$name"$'\n'*)
		fail "$CHECKSUMS line $lineno: '$name' is listed twice"
		bad=1
		continue
		;;
	esac
	names+=("$name")
	digests+=("$digest")
	listed+="$name"$'\n'
done <"$CHECKSUMS"

if [ "$bad" -ne 0 ]; then
	summary
fi
if [ "${#names[@]}" -eq 0 ]; then
	fail "$CHECKSUMS: lists no files, so nothing is attested"
	summary
fi

shopt -s nullglob dotglob
for entry in *; do
	case $entry in
	"$CHECKSUMS" | "$BUNDLE" | "$SIG" | "$PEM") continue ;;
	esac
	case $listed in
	*$'\n'"$entry"$'\n'*) ;;
	*) fail "$entry: present but not listed in $CHECKSUMS, so nothing attests it" ;;
	esac
done
shopt -u nullglob dotglob

for i in "${!names[@]}"; do
	name=${names[$i]}
	want=${digests[$i]}
	if ! [ -e "$name" ]; then
		fail "$name: listed in $CHECKSUMS but missing"
		continue
	fi
	if [ -L "$name" ] || ! [ -f "$name" ]; then
		fail "$name: not a regular file"
		continue
	fi
	got=$(sha256 "$name")
	file_ok=yes
	if [ "$got" != "$want" ]; then
		fail "$name: SHA-256 mismatch: $CHECKSUMS lists $want, file is $got"
		file_ok=no
	fi
	if ! out=$(gh attestation verify "$name" --repo "$REPO" \
		--signer-workflow "$REPO/$SIGNER_WORKFLOW" \
		--source-ref "refs/tags/$tag" \
		--deny-self-hosted-runners 2>&1); then
		fail "$name: attestation did not verify for $SIGNER_WORKFLOW at refs/tags/$tag"
		printf '%s\n' "$out" | sed 's/^/      /'
		file_ok=no
	fi
	if [ "$file_ok" = yes ]; then
		pass "$name"
		verified=$((verified + 1))
	fi
done

summary
