# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The FreeBSD client, on a FreeBSD root. Every other freebsd check in this
# harness reads bytes back with curl or drives the portable pkg build on the
# Linux client, so each can pass against a fixture and still be wrong about
# what pkg and the ports framework accept. These are the two that cannot:
# `pkg install` through the stanza `bodega doctor --write-pkg-repo` wrote, and
# `make fetch` plus `make checksum` in a ports tree bodega served.
#
# The server is the Linux server guest. The FreeBSD server guest is for
# internal/storage's FreeBSD paths, which run at publication time and which no
# client request reaches.
#
# This suite mutates the freebsd guest: it installs a bodega binary, appends to
# /etc/hosts, and installs and removes one package. It restores the pkg
# repository configuration it wrote and checks the restore.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"
# shellcheck source=../lib/fixtures.sh
. "${E2E_DIR:?}/lib/fixtures.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block FBSD-BLOCK "the FreeBSD client" "the server guest is unreachable"
	return 0
fi

# Preflight gates on the Linux pair only, so a powered-off FreeBSD guest blocks
# this suite rather than the run.
E2E_HOST=freebsd
if e2e_on freebsd true 2>/dev/null; then
	e2e_record FBSD-00 PASS "the freebsd guest answers ssh" "reachable" "reachable" "ssh $E2E_FREEBSD_HOST true" 0 ""
else
	e2e_record FBSD-00 FAIL "the freebsd guest answers ssh" "reachable" "$E2E_ERR" "ssh $E2E_FREEBSD_HOST true" "$E2E_RC" "test/e2e/README.md"
	e2e_block FBSD-BLOCK-HOST "the FreeBSD client" "the freebsd guest ($E2E_FREEBSD_HOST) is unreachable; power it on"
	return 0
fi

# Off /tmp for the same reason as $E2E_CLIENT_ROOT: a ports tree is what fills
# a small /tmp, and a full filesystem reads as a fetch failure.
FBSD_ROOT="${E2E_FREEBSD_CLIENT_ROOT:-/var/tmp/bodega-e2e-freebsd}"

# ---- ship ------------------------------------------------------------------
#
# `doctor --write-pkg-repo` runs on the host it configures, so the client needs
# a FreeBSD build of the commit under test. Both FreeBSD guests are arm64.

E2E_HOST=local
FBSD_BIN="$REPO_ROOT/dist/bodega-freebsd-arm64"
if [ "${E2E_SHIP:-yes}" = yes ]; then
	e2e_local make -C "$REPO_ROOT" cross CROSS_TARGETS=freebsd/arm64 || true
	check_eq FBSD-01 "make cross builds the freebsd/arm64 binary" 0 "$E2E_RC" \
		"Makefile" "make cross CROSS_TARGETS=freebsd/arm64" "$E2E_RC"
	E2E_HOST=freebsd
	if e2e_put freebsd "$FBSD_BIN" /tmp/bodega-under-test &&
		e2e_on freebsd "sudo install -o root -g wheel -m 0755 /tmp/bodega-under-test /usr/local/bin/bodega"; then
		e2e_record FBSD-02 PASS "the freebsd guest takes the new binary" "installed" "installed" "install /usr/local/bin/bodega" 0 ""
	else
		e2e_record FBSD-02 FAIL "the freebsd guest takes the new binary" "installed" "$E2E_ERR" "install /usr/local/bin/bodega" "$E2E_RC" ""
	fi
else
	e2e_skip FBSD-01 "make cross builds the freebsd/arm64 binary" "--no-ship"
	e2e_skip FBSD-02 "the freebsd guest takes the new binary" "--no-ship"
fi

E2E_HOST=freebsd
e2e_on freebsd "bodega --version" || true
check_contains FBSD-03 "the freebsd guest runs the commit under test" \
	"$E2E_COMMIT" "$E2E_OUT" "Makefile" "bodega --version"

# The guests resolve through public DNS, and public_url names the server by
# its internal name. Same tag as the Linux pair, so one sed clears both.
e2e_on freebsd "sudo sed -i '' '/# bodega-e2e\$/d' /etc/hosts && \
	printf '%s %s # bodega-e2e\n' '$E2E_SERVER_ADDR' '$E2E_SERVER_HOST' | sudo tee -a /etc/hosts >/dev/null" || true
e2e_on freebsd "curl -sS -o /dev/null -w '%{http_code}' --max-time 10 '$E2E_BASE_URL/healthz'" || true
check_eq FBSD-04 "the freebsd guest reaches the server by name" "200" "$E2E_OUT" \
	"test/e2e/suites/10-ship-install.sh" "curl $E2E_BASE_URL/healthz" "$E2E_RC"

# ---- pkg -------------------------------------------------------------------
#
# A proxy-mode entry for the client's own ABI against pkg.freebsd.org. Proxy
# rather than hosted because a hosted latest/ is 182 GB, and proxy still
# carries FreeBSD's signature to the client untouched: pkg verifies the
# catalogue against /usr/share/keys/pkg, so a byte bodega changed fails here.
#
# Its own repository name rather than a version under the fixture's latest/,
# so the cleanup is one delete and the stanza's tag names this suite.

e2e_on freebsd "pkg config abi" || true
fbsd_abi="$E2E_OUT"
check_matches FBSD-PKG-00 "the freebsd guest reports its pkg ABI" '^FreeBSD:[0-9]+:[a-z0-9]+$' \
	"${fbsd_abi:-none}" "cmd/bodega/cmd_doctor.go" "pkg config abi"

E2E_HOST=server
e2e_on server "cat > /tmp/e2e-fx-fbsd-client.json <<'E2EFIXTURE'
{
  \"config_version\": 1,
  \"name\": \"e2e-latest\",
  \"type\": \"freebsd\",
  \"description\": \"e2e: proxy of pkg.freebsd.org for the FreeBSD client guest's ABI\",
  \"versions\": [
    {
      \"version\": \"$fbsd_abi\",
      \"url\": \"https://pkg.freebsd.org/$fbsd_abi/latest\",
      \"mode\": \"proxy\"
    }
  ]
}
E2EFIXTURE" || true
e2e_bodega server "pkg import --merge /tmp/e2e-fx-fbsd-client.json" || true
check_eq FBSD-PKG-01 "the server takes a proxy entry for the client's ABI" 0 "$E2E_RC" \
	"docs/usage.md#mirroring-a-freebsd-pkg-repository" "bodega pkg import e2e-fx-fbsd-client.json" "$E2E_RC"
e2e_reload server || true

# tree was installed by hand during F21's measurement and may still be there;
# a package already installed proves nothing about where it came from.
E2E_HOST=freebsd
e2e_on freebsd "sudo pkg delete -y tree >/dev/null 2>&1; true" || true
e2e_on freebsd "sudo bodega doctor --write-pkg-repo --url '$E2E_BASE_URL' --allow-plaintext" || true
check_eq FBSD-PKG-02 "doctor --write-pkg-repo writes the stanza on a FreeBSD host" 0 "$E2E_RC" \
	"cmd/bodega/cmd_doctor.go" "bodega doctor --write-pkg-repo --url $E2E_BASE_URL" "$E2E_RC"

# The override is the half that fails silently: a wrong tag leaves the upstream
# repository enabled beside bodega's and pkg update says nothing about it.
e2e_on freebsd "pkg -vv | awk '/^  FreeBSD-ports:/{r=1} r && /enabled/{v=\$NF; gsub(/[^a-z]/, \"\", v); print v; exit}'" || true
check_eq FBSD-PKG-03 "the stanza turns the upstream FreeBSD-ports repository off" "no" "$E2E_OUT" \
	"internal/pkgrepos" "pkg -vv" "$E2E_RC"

e2e_on freebsd "sudo pkg update -f 2>&1 | tail -3" || true
check_contains FBSD-PKG-04 "pkg update accepts the catalogue bodega served" \
	"bodega-e2e-latest repository update completed" "$E2E_OUT" \
	"internal/server/freebsd.go:57" "pkg update -f"

e2e_on freebsd "sudo pkg install -y -r bodega-e2e-latest tree 2>&1 | tail -3" || true
check_eq FBSD-PKG-05 "pkg install onto a FreeBSD root succeeds through bodega" 0 "$E2E_RC" \
	"internal/server/freebsd.go:57" "pkg install -r bodega-e2e-latest tree" "$E2E_RC"

e2e_on freebsd "pkg query '%n %R' tree" || true
check_eq FBSD-PKG-06 "the installed package names bodega's repository as its origin" \
	"tree bodega-e2e-latest" "$E2E_OUT" "internal/server/freebsd.go:57" "pkg query '%n %R' tree"

e2e_on freebsd "sudo pkg delete -y tree >/dev/null && sudo rm -f /usr/local/etc/pkg/repos/bodega.conf && \
	pkg -vv | awk '/^  FreeBSD-ports:/{r=1} r && /enabled/{v=\$NF; gsub(/[^a-z]/, \"\", v); print v; exit}'" || true
check_eq FBSD-PKG-07 "removing the stanza gives the host its upstream repository back" "yes" "$E2E_OUT" \
	"test/e2e/suites/47-freebsd-client.sh" "rm bodega.conf; pkg -vv" "$E2E_RC"

E2E_HOST=server
e2e_bodega server "pkg delete freebsd e2e-latest" || true
e2e_reload server || true
unset fbsd_abi

# ---- ports -----------------------------------------------------------------
#
# The tree comes from bodega (the ports-txz binary entry 45-clients builds) and
# the distfile comes from bodega too, through an open binary_upstreams
# namespace over FreeBSD's distfile cache. That proves a binary namespace can
# serve a distfile, and nothing more: internal/server/binary.go pins whatever
# its first fetch returned and reads no distinfo, RESTRICTED or NO_CDROM. The
# distfiles type, which does, is driven by 49-freebsd-distfiles.
#
# pkg.freebsd.org rather than distcache.FreeBSD.org, which the ports framework
# uses over plain http: its https answers with a certificate for another name,
# and a binary_upstreams URL must be https.
#
# The port sets DIST_SUBDIR to something other than its own name, because the
# subdirectory is the part of the distfile path an override most easily drops.
# Its one distfile is 2.4 KB.
FBSD_PORT=databases/sqlite-ext-pcre
FBSD_SUBDIR=sqlite-ext
FBSD_PORTS="$FBSD_ROOT/usr/ports"
fbsd_make="make -C $FBSD_PORTS/$FBSD_PORT PORTSDIR=$FBSD_PORTS DISTDIR=$FBSD_ROOT/distfiles WRKDIRPREFIX=$FBSD_ROOT/wrk"
ports_sha="$(printf '%s' "$(e2e_fixture ports-txz)" | jq -r '.versions[0].sha256')"

# The tarball is read from storage, and a binary_upstreams entry turns that
# read off for every /binaries/ path its key does not name. Emptied first, so a
# run that aborted with the namespace in place does not 404 the tree.
E2E_HOST=server
e2e_config_set server '.binary_upstreams = {}' || true
e2e_restart server || true
e2e_on server "cat > /tmp/e2e-fx-ports-txz.json <<'E2EFIXTURE'
$(e2e_fixture ports-txz)
E2EFIXTURE" || true
e2e_bodega server "pkg import --merge /tmp/e2e-fx-ports-txz.json && sudo bodega build upload binary freebsd-ports" || true

E2E_HOST=freebsd
e2e_on freebsd "rm -rf $FBSD_ROOT && mkdir -p $FBSD_ROOT/distfiles $FBSD_ROOT/wrk && \
	curl -sS -o $FBSD_ROOT/ports.txz '$E2E_BASE_URL/binaries/freebsd-ports/15.1-RELEASE/ports.txz' && \
	sha256 -q $FBSD_ROOT/ports.txz" || true
check_eq FBSD-PORTS-01 "the freebsd guest receives the ports tree the release MANIFEST names" \
	"$ports_sha" "$E2E_OUT" "internal/server/binary.go:31" \
	"curl $E2E_BASE_URL/binaries/freebsd-ports/15.1-RELEASE/ports.txz | sha256" "$E2E_RC"

# The framework and the one port, not the 1 GB tree: make fetch reads Mk/,
# Templates/, Keywords/ and the port's own directory, and nothing else.
e2e_on freebsd "tar -xf $FBSD_ROOT/ports.txz -C $FBSD_ROOT \
	usr/ports/Mk usr/ports/Templates usr/ports/Keywords usr/ports/$FBSD_PORT && \
	$fbsd_make -V DIST_SUBDIR" || true
check_eq FBSD-PORTS-02 "the tree's own Mk/ evaluates the port on a FreeBSD root" \
	"$FBSD_SUBDIR" "$E2E_OUT" "docs/usage.md#serving-the-freebsd-ports-tree" \
	"make -C $FBSD_PORT -V DIST_SUBDIR" "$E2E_RC"

E2E_HOST=server
e2e_config_set server '.binary_upstreams = {"distfiles": {"url": "https://pkg.freebsd.org/ports-distfiles/", "mode": "open"}}' || true
e2e_restart server || true

# fetch tries the override first and falls through to the port's own
# MASTER_SITES on any failure, printing an "Attempting to fetch" line per site.
# One attempt, naming bodega, is what says every byte came through bodega; a
# passing fetch alone does not.
E2E_HOST=freebsd
e2e_on freebsd "$fbsd_make MASTER_SITE_OVERRIDE='$E2E_BASE_URL/binaries/distfiles/\${DIST_SUBDIR}/' fetch 2>&1 | \
	awk -v p='$E2E_BASE_URL/binaries/distfiles/$FBSD_SUBDIR/' \
	'/Attempting to fetch/{n++; u=\$NF} END{print n+0, (index(u, p) == 1 ? \"bodega\" : u)}'" || true
fbsd_fetch="$E2E_OUT"
check_eq FBSD-PORTS-03 "make fetch succeeds against bodega" 0 "$E2E_RC" \
	"internal/server/binary.go" "make fetch MASTER_SITE_OVERRIDE=$E2E_BASE_URL/binaries/distfiles/..." "$E2E_RC"
check_eq FBSD-PORTS-04 "make fetch takes the distfile from bodega on the first and only attempt" \
	"1 bodega" "$fbsd_fetch" "internal/server/binary.go" "make fetch | grep 'Attempting to fetch'"

e2e_on freebsd "$fbsd_make checksum 2>&1 | tail -1" || true
check_contains FBSD-PORTS-05 "make checksum accepts the bytes against the tree's own distinfo" \
	"Checksum OK" "$E2E_OUT" "docs/usage.md#distfiles" "make checksum"

E2E_HOST=server
e2e_config_set server '.binary_upstreams = {}' || true
e2e_restart server || true
e2e_config_get server '.binary_upstreams | length' || true
check_eq FBSD-PORTS-06 "the distfiles namespace is removed again" "0" "$E2E_OUT" \
	"test/e2e/suites/47-freebsd-client.sh" "jq .binary_upstreams config.json"

E2E_HOST=freebsd
e2e_on freebsd "rm -rf $FBSD_ROOT" || true

unset FBSD_ROOT FBSD_BIN FBSD_PORT FBSD_SUBDIR FBSD_PORTS fbsd_make fbsd_fetch ports_sha
