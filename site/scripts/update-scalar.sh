#!/bin/sh
# Vendors one exact @scalar/api-reference release into site/static/scalar.
#
# The tarball is fetched from registry.npmjs.org and refused unless its sha512
# is the dist.integrity the registry's metadata reports for that version. The
# metadata and the tarball come from one origin, so that check catches a
# truncated or substituted download, not a registry that lies in both places.
# What holds afterwards is the sha256 recorded in scalar.json, which the site's
# tests compare with the committed bundle.
#
# No package client runs here: an installed npm would execute lifecycle
# scripts and resolve dependencies this site never asked for.
set -eu

package=@scalar/api-reference
registry=https://registry.npmjs.org
bundle=package/dist/browser/standalone.js

usage() {
	echo "usage: update-scalar.sh VERSION    one exact release, for example 1.76.0" >&2
	exit 2
}

fail() {
	echo "update-scalar: $*" >&2
	exit 1
}

[ $# -eq 1 ] || usage
version=$1
case $version in
*[!0-9.]* | "" | .* | *. | *..*) fail "version \"$version\" is not an exact release: give three dotted numbers such as 1.76.0, never a tag or a range" ;;
esac
case $version in
*.*.*.*) fail "version \"$version\" is not an exact release: give three dotted numbers such as 1.76.0" ;;
*.*.*) ;;
*) fail "version \"$version\" is not an exact release: give three dotted numbers such as 1.76.0" ;;
esac

for tool in curl openssl tar python3; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed, and this script needs it"
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
dest=$script_dir/../static/scalar
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsS --proto '=https' --tlsv1.2 --max-time 60 -o "$work/meta.json" "$registry/$package/$version" ||
	fail "could not read $registry/$package/$version: check the version exists and the registry is reachable"

# -I keeps Python from importing anything out of the working directory.
python3 -I - "$work/meta.json" "$version" "$registry" "$bundle" >"$work/dist" <<'EOF' || fail "the registry metadata for $version is not usable; see the line above"
import json, sys
meta = json.load(open(sys.argv[1]))
if meta.get("version") != sys.argv[2]:
    sys.exit("update-scalar: the registry answered for version %r, not %r" % (meta.get("version"), sys.argv[2]))
dist = meta.get("dist") or {}
integrity, tarball = dist.get("integrity", ""), dist.get("tarball", "")
if not integrity.startswith("sha512-") or " " in integrity:
    sys.exit("update-scalar: dist.integrity is %r, and only a single sha512 digest is accepted" % integrity)
if not tarball.startswith(sys.argv[3] + "/"):
    sys.exit("update-scalar: dist.tarball is %r, which is not under %s" % (tarball, sys.argv[3]))
# The standalone bundle is the file the package itself names for a browser.
if "package/" + str(meta.get("browser", "")).removeprefix("./") != sys.argv[4]:
    sys.exit("update-scalar: the package's browser entry is %r, not %s; read its README before vendoring it" % (meta.get("browser"), sys.argv[4]))
license = meta.get("license")
if not isinstance(license, str) or not license.replace("-", "").replace(".", "").isalnum():
    sys.exit("update-scalar: the package's license is %r, not one SPDX identifier" % (license,))
print(integrity)
print(tarball)
print(license)
EOF
integrity=$(sed -n 1p "$work/dist")
tarball=$(sed -n 2p "$work/dist")
license=$(sed -n 3p "$work/dist")

curl -fsS --proto '=https' --tlsv1.2 --max-time 300 -o "$work/package.tgz" "$tarball" ||
	fail "could not download $tarball"

got=sha512-$(openssl dgst -sha512 -binary "$work/package.tgz" | openssl base64 -A)
[ "$got" = "$integrity" ] ||
	fail "the tarball's digest is $got, and the registry reports $integrity for $version; nothing was written. Run it again, and if it repeats, do not vendor this release"

mkdir "$work/x"
tar -xzf "$work/package.tgz" -C "$work/x" "$bundle" ||
	fail "$package $version carries no $bundle; the package layout changed, so read its README before vendoring it"

mkdir -p "$dest"
cp "$work/x/$bundle" "$dest/standalone.js"
sha256=$(openssl dgst -sha256 -r "$dest/standalone.js" | cut -d' ' -f1)
cat >"$dest/scalar.json" <<EOF
{
  "package": "$package",
  "version": "$version",
  "license": "$license",
  "integrity": "$integrity",
  "file": "standalone.js",
  "sha256": "$sha256"
}
EOF
echo "vendored $package $version into site/static/scalar (standalone.js sha256 $sha256)"
