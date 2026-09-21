# shellcheck shell=bash
#
# A pkg repository small enough to copy in a test run, in both layouts the real
# ones publish.
#
# pkg.freebsd.org is not a fixture: its FreeBSD:14:amd64 latest/ measures
# 38,325 packages and 182.8 GB, base_latest/ 535 and 1.2 GB, and a hosted entry
# takes the whole repository. So the guest builds two repositories of one
# package each, in the two layouts a repopath is spelled in — All/Hashed/ and a
# leading ./Hashed/ — plus a package at the repository root, the third
# arrangement the type has to serve and the one no upstream fixture covers.
#
# The archives are built the way upstream builds them, a zstd tarball carrying
# the signature and the public key beside the document, because that is what
# the catalogue reader has to walk past untouched. Nothing here signs anything:
# what is measured is that the bytes come back unchanged.
#
# The upstream is a static file server on the guest's loopback, run as a
# transient unit so a run that dies leaves no listener behind. Stopping it is
# also the offline check, since a hosted entry that still answers is one
# answering out of the store.

[ -n "${E2E_LIB_FREEBSD:-}" ] && return 0
E2E_LIB_FREEBSD=1

E2E_FREEBSD_ROOT="${E2E_FREEBSD_ROOT:-/srv/bodega-e2e-freebsd}"
E2E_FREEBSD_PORT="${E2E_FREEBSD_PORT:-8099}"
# Loopback on the guest: the builder fetches from the host it runs on, and an
# address nothing else can reach cannot be mistaken for a real upstream.
E2E_FREEBSD_URL="${E2E_FREEBSD_URL:-http://127.0.0.1:${E2E_FREEBSD_PORT}}"
E2E_FREEBSD_UNIT="bodega-e2e-freebsd-upstream"
export E2E_FREEBSD_ROOT E2E_FREEBSD_PORT E2E_FREEBSD_URL

# The two repopaths as a client composes them. The leading "./" of the
# base_latest spelling is gone here because every HTTP client normalizes it out
# before the request leaves.
# shellcheck disable=SC2016 # the "$" is a character in a pkg filename, not an expansion
E2E_FREEBSD_LATEST_PATH='All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg'
# shellcheck disable=SC2016 # as above
E2E_FREEBSD_BASE_PATH='Hashed/FreeBSD-telnet-14.snap20260920075547~2$ea5o6tyi.pkg'
export E2E_FREEBSD_LATEST_PATH E2E_FREEBSD_BASE_PATH

# e2e_freebsd_fixture_build <alias>
e2e_freebsd_fixture_build() {
	local alias="$1" script
	script="$(
		cat <<'FBFIXTURE'
set -eu
root="${1:?repository root}"
rm -rf "$root"
mkdir -p "$root/latest/All/Hashed" "$root/base_latest/Hashed"

hashed='All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg'
based='Hashed/FreeBSD-telnet-14.snap20260920075547~2$ea5o6tyi.pkg'

printf 'the All/Hashed layout package\n' >"$root/latest/$hashed"
printf 'the Hashed layout package\n' >"$root/base_latest/$based"
printf 'the repository-root layout package\n' >"$root/base_latest/root.pkg"

build() {
	dir="$1"
	shift
	tmp="$(mktemp -d)"
	: >"$tmp/packagesite.yaml"
	records=''
	for rel in "$@"; do
		name="$(basename "$rel" .pkg)"
		printf '{"name":"%s","origin":"e2e/fixture","version":"1.0","repopath":"%s"}\n' \
			"$name" "$rel" >>"$tmp/packagesite.yaml"
		records="$records{\"name\":\"$name\",\"origin\":\"e2e/fixture\",\"version\":\"1.0\",\"repopath\":\"$rel\"},"
	done
	# Both archives name the same packages. A repository publishes both, so a
	# client that reads either one has to find the bytes it names.
	printf '{"groups":[],"expired_packages":[],"packages":[%s]}' "${records%,}" >"$tmp/data"

	tr '\0' 's' </dev/zero | head -c 256 >"$tmp/packagesite.yaml.sig"
	tr '\0' 'p' </dev/zero | head -c 451 >"$tmp/packagesite.yaml.pub"
	cp "$tmp/packagesite.yaml.sig" "$tmp/data.sig"
	cp "$tmp/packagesite.yaml.pub" "$tmp/data.pub"

	# Byte-identical on every rebuild. tar takes the member mtimes and the
	# owner from the scratch directory otherwise, so two runs of this fixture
	# produce two different archives — and `bodega build fetch` skips a
	# repository it has already mirrored, so the second run compares a freshly
	# built upstream against the first run's mirror and reports bodega for
	# changing bytes it never touched.
	tarflags="--mtime=@0 --sort=name --owner=0 --group=0 --numeric-owner"
	# shellcheck disable=SC2086  # tarflags is a deliberate word list
	tar --zstd $tarflags -cf "$dir/packagesite.pkg" -C "$tmp" \
		packagesite.yaml.sig packagesite.yaml.pub packagesite.yaml
	# shellcheck disable=SC2086  # see above
	tar --zstd $tarflags -cf "$dir/data.pkg" -C "$tmp" data.sig data.pub data
	printf 'version = 2;\npacking_format = "tzst";\nmanifests = "packagesite.yaml";\ndata = "data";\n' \
		>"$dir/meta.conf"
	rm -rf "$tmp"
}

build "$root/latest" "$hashed"
# One repository carries the "./" spelling and the repository-root package
# together: both reach the same catalogue reader, and a separate repository per
# layout would prove nothing the pair does not.
build "$root/base_latest" "./$based" 'root.pkg'
chmod -R a+rX "$root"
find "$root" -type f | sort
FBFIXTURE
	)"
	e2e_on "$alias" "cat > /tmp/e2e-freebsd-fixture.sh <<'E2EFBFIXTURE'
$script
E2EFBFIXTURE" || return 1
	e2e_on "$alias" "sudo sh /tmp/e2e-freebsd-fixture.sh '$E2E_FREEBSD_ROOT'"
}

# e2e_freebsd_upstream_start <alias>
#
# Polled rather than slept on: a listener that takes two seconds and a unit
# that never starts are different findings, and a fixed sleep reports both the
# same way.
e2e_freebsd_upstream_start() {
	local alias="$1" waited=0
	e2e_on "$alias" "sudo systemctl reset-failed $E2E_FREEBSD_UNIT 2>/dev/null; \
		sudo systemd-run --unit=$E2E_FREEBSD_UNIT --collect \
			/usr/bin/python3 -m http.server $E2E_FREEBSD_PORT \
			--bind 127.0.0.1 --directory '$E2E_FREEBSD_ROOT'" || return 1
	while [ "$waited" -lt 15 ]; do
		if e2e_on "$alias" "curl -sf -o /dev/null --max-time 5 '$E2E_FREEBSD_URL/latest/meta.conf'" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	return 1
}

# e2e_freebsd_upstream_stop <alias>
e2e_freebsd_upstream_stop() {
	e2e_on "$1" "sudo systemctl stop $E2E_FREEBSD_UNIT 2>/dev/null; \
		sudo systemctl reset-failed $E2E_FREEBSD_UNIT 2>/dev/null; true"
}
