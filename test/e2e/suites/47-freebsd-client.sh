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
# /etc/hosts, installs and removes one package twice, and trusts bodega's pkg
# fingerprint while a profile binds it. It saves /usr/local/etc/pkg's bodega
# stanza and fingerprint directory before its first write, restores them on
# the way out (early exit included), and checks the restore against the saved
# state rather than against a stock default.

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

# ---- the guest's pkg configuration ------------------------------------------
#
# The two paths this suite writes, saved before the first write and restored
# from that copy: present bytes come back byte for byte, absence comes back as
# absence, and the unrelated fingerprints beside bodega's are never touched.
# The helper runs on the guest because it is FreeBSD's tar, stat and sha256
# that have to agree with what pkg reads.
#
# A clean guest proves nothing about restoring, so the suite first seeds one
# pre-existing stanza (only where none is) and one revoked fingerprint, runs
# against that, checks it came back, and then restores the guest as found.

FBSD_PKGCONF=/tmp/bodega-e2e-pkgconf.sh
fbsd_pkgconf_local="$(mktemp "${TMPDIR:-/tmp}/e2e-pkgconf.XXXXXX")"
cat >"$fbsd_pkgconf_local" <<'E2EPKGCONF'
#!/bin/sh
# save <slot> | restore <slot> | drop | seed | state
set -eu
root="${FBSD_PKGCONF_ROOT:-}"
dir="$root/var/tmp/bodega-e2e-pkgconf"
paths="usr/local/etc/pkg/repos/bodega.conf usr/local/etc/pkg/fingerprints/bodega"
parents="usr/local/etc/pkg/repos usr/local/etc/pkg/fingerprints usr/local/etc/pkg"
slot="$dir/${2:-none}"
case "$1" in
save)
	rm -rf "$slot"
	mkdir -p "$slot"
	: >"$slot/present"
	: >"$slot/parents"
	for p in $parents; do
		if [ -d "$root/$p" ]; then echo "$p" >>"$slot/parents"; fi
	done
	for p in $paths; do
		if [ -e "$root/$p" ] || [ -L "$root/$p" ]; then echo "$p" >>"$slot/present"; fi
	done
	if [ -s "$slot/present" ]; then
		# shellcheck disable=SC2046 # one word per saved path
		tar -cpf "$slot/saved.tar" -C "${root:-/}" $(cat "$slot/present")
	fi
	: >"$slot/complete"
	;;
restore)
	# Nothing is removed without a complete copy to put back.
	if [ ! -f "$slot/complete" ]; then
		echo "no complete save at $slot, so nothing was removed" >&2
		exit 1
	fi
	for p in $paths; do rm -rf "$root/$p"; done
	if [ -s "$slot/present" ]; then tar -xpf "$slot/saved.tar" -C "${root:-/}"; fi
	for p in $parents; do
		grep -qx "$p" "$slot/parents" || rmdir "$root/$p" 2>/dev/null || true
	done
	;;
drop)
	rm -rf "$dir"
	;;
seed)
	mkdir -p "$root/usr/local/etc/pkg/repos" "$root/usr/local/etc/pkg/fingerprints/bodega/revoked"
	if [ ! -e "$root/usr/local/etc/pkg/repos/bodega.conf" ]; then
		printf '# bodega e2e: a stanza that predates suite 47, which it must restore\n' \
			>"$root/usr/local/etc/pkg/repos/bodega.conf"
	fi
	printf 'function: "sha256";\nfingerprint: "%064d";\n' 0 \
		>"$root/usr/local/etc/pkg/fingerprints/bodega/revoked/bodega-e2e-sentinel"
	;;
state)
	p=usr/local/etc/pkg
	if [ ! -e "$root/$p" ]; then
		echo "$p absent"
		exit 0
	fi
	find "$root/$p" | sort | while IFS= read -r f; do
		m="$(stat -f '%Sp %Su:%Sg' "$f")"
		if [ -f "$f" ]; then m="$m $(sha256 -q "$f")"; fi
		echo "${f#"$root"/} $m"
	done
	;;
*)
	echo "usage: $0 save <slot> | restore <slot> | drop | seed | state" >&2
	exit 2
	;;
esac
E2EPKGCONF

E2E_HOST=freebsd
e2e_put freebsd "$fbsd_pkgconf_local" "$FBSD_PKGCONF" || true
rm -f "$fbsd_pkgconf_local"
e2e_on freebsd "sudo sh $FBSD_PKGCONF state" || true
fbsd_conf_found="$E2E_OUT"
e2e_on freebsd "sudo sh $FBSD_PKGCONF save found" || true
check_eq FBSD-CONF-00 "the guest's pkg configuration is saved before the suite writes it" 0 "$E2E_RC" \
	"test/e2e/suites/47-freebsd-client.sh" "sh $FBSD_PKGCONF save found" "$E2E_RC"

# From here on, leaving by any road restores the guest as found and takes the
# guest's address off whichever identity this suite bound it to. cleanup is
# run.sh's own exit trap, which this one wraps rather than replaces.
FBSD_CIDR="${E2E_FREEBSD_ADDR:-127.0.0.1}/32"
fbsd_pkgconf_on_exit() {
	e2e_on freebsd "sudo sh $FBSD_PKGCONF restore found" >/dev/null 2>&1 || true
	e2e_bodega server "identity unbind cidr $FBSD_CIDR" >/dev/null 2>&1 || true
	cleanup
}
trap fbsd_pkgconf_on_exit EXIT
trap 'exit 130' INT TERM

e2e_on freebsd "sudo sh $FBSD_PKGCONF seed && sudo sh $FBSD_PKGCONF save seeded && sudo sh $FBSD_PKGCONF state" || true
fbsd_conf_seeded="$E2E_OUT"
check_contains FBSD-CONF-01 "the guest carries a pre-existing bodega fingerprint for the suite to restore" \
	"fingerprints/bodega/revoked/bodega-e2e-sentinel" "$fbsd_conf_seeded" \
	"test/e2e/suites/47-freebsd-client.sh" "sh $FBSD_PKGCONF seed; save seeded"

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

# doctor reads its plan from /client/, which answers only a host an identity
# binding names. The guest is bound for the write and unbound straight after,
# so the profile section below meets the address unbound. Unbound first, so an
# aborted run's leftover does not fail the bind.
E2E_HOST=server
e2e_bodega server "identity unbind cidr $FBSD_CIDR" >/dev/null 2>&1 || true
e2e_bodega server "identity bind cidr $FBSD_CIDR e2e-fbsd-client --comment 'e2e run'" || true
check_eq FBSD-PKG-BIND "the freebsd guest's address binds to an identity for doctor" 0 "$E2E_RC" \
	"cmd/bodega/cmd_identity.go:59" "bodega identity bind cidr $FBSD_CIDR e2e-fbsd-client" "$E2E_RC"
e2e_reload server || true

E2E_HOST=freebsd
e2e_on freebsd "sudo bodega doctor --write-pkg-repo --url '$E2E_BASE_URL' --allow-plaintext" || true
check_eq FBSD-PKG-02 "doctor --write-pkg-repo writes the stanza on a FreeBSD host" 0 "$E2E_RC" \
	"cmd/bodega/cmd_doctor.go" "bodega doctor --write-pkg-repo --url $E2E_BASE_URL" "$E2E_RC"

E2E_HOST=server
e2e_bodega server "identity unbind cidr $FBSD_CIDR" || true
e2e_reload server || true
E2E_HOST=freebsd

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

# ---- pkg under a profile ---------------------------------------------------
#
# The same proxied repository, read by a host bound to a profile that lists two
# packages. The catalogue the host reads is filtered for that profile and
# re-signed with bodega's pkg key, so the guest trusts bodega's fingerprint for
# this stanza and not /usr/share/keys/pkg. tree and pv are listed; nano is the
# third, present upstream and refused here.
#
# The guest is bound by its address, which is the binding a pkg host carries:
# pkg sends no bodega credential.

FBSD_PROFILE=e2e-fbsd
fbsd_repo_url="$E2E_BASE_URL/freebsd/$fbsd_abi/e2e-latest"

# The third package's repopath, read off the published catalogue while the
# guest is still unbound and may read it: the hand-composed fetch below is of a
# real object, not a path the gate would refuse for being malformed.
E2E_HOST=freebsd
e2e_on freebsd "curl -sS --max-time 120 '$fbsd_repo_url/packagesite.pkg' | tar -xOf - packagesite.yaml | \
	grep '\"name\":\"nano\"' | head -1 | sed -E 's/.*\"repopath\":\"([^\"]*)\".*/\1/'" || true
fbsd_third="$E2E_OUT"
check_matches FBSD-PROF-00 "the published catalogue names the third package's object" '^All/.*nano-.*\.pkg$' \
	"${fbsd_third:-none}" "internal/server/freebsd.go" "curl packagesite.pkg | tar -xOf - packagesite.yaml | grep nano"

# bodega signs a filtered catalogue with its pkg key or refuses to serve one,
# so the server needs a key. One an earlier run generated is kept. It goes
# under the storage root, which e2e_bodega hands to the service user: the
# default path is /etc/bodega, where root would own a 0600 key the service
# cannot read.
E2E_HOST=server
e2e_bodega server "freebsd key show >/dev/null 2>&1 || sudo bodega freebsd key generate --path /var/lib/bodega/pkg-signing.key" || true
e2e_reload server || true
e2e_bodega server "freebsd key export --fingerprint" || true
fbsd_fpr="$E2E_OUT"
e2e_on server "sleep 2; curl -s --max-time 10 '$E2E_BASE_URL/api/v1/status' | jq -r '.freebsd.signed'" || true
check_eq FBSD-PROF-01 "the server loaded a pkg signing key to re-sign a filtered catalogue with" \
	"true" "$E2E_OUT" "internal/server/freebsd_catalog.go" "bodega freebsd key generate; GET /api/v1/status | jq .freebsd.signed" "$E2E_RC"

e2e_bodega server "profile create $FBSD_PROFILE --description 'e2e run'" >/dev/null 2>&1 || true
e2e_bodega server "profile add $FBSD_PROFILE freebsd tree && sudo bodega profile add $FBSD_PROFILE freebsd pv && \
	sudo bodega profile set $FBSD_PROFILE freebsd --membership closed --expansion block" || true
check_eq FBSD-PROF-02 "a profile takes freebsd rules keyed by package name" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go" "bodega profile add $FBSD_PROFILE freebsd tree; ... set --membership closed --expansion block" "$E2E_RC"

# warn is stored like any other shape and filtered by the whole predicate; set
# back to block so the checks below see the two listed packages alone.
e2e_bodega server "profile set $FBSD_PROFILE freebsd --membership closed --expansion warn" || true
fbsd_warn="$E2E_OUT"
e2e_bodega server "profile set $FBSD_PROFILE freebsd --membership closed --expansion block" || true
check_contains FBSD-PROF-03 "a freebsd rule under warn is stored, and set says unlisted packages stay in the catalogue" \
	"drops only versions" "$fbsd_warn" "cmd/bodega/cmd_profile.go" \
	"bodega profile set $FBSD_PROFILE freebsd --expansion warn"

e2e_bodega server "profile unbind e2e-fbsd-host" >/dev/null 2>&1 || true
e2e_bodega server "identity unbind cidr $FBSD_CIDR" >/dev/null 2>&1 || true
e2e_bodega server "identity bind cidr $FBSD_CIDR e2e-fbsd-host --comment 'e2e run' && \
	sudo bodega profile bind $FBSD_PROFILE e2e-fbsd-host --force" || true
check_eq FBSD-PROF-04 "the freebsd guest's address binds to the profile" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go" "bodega identity bind cidr $FBSD_CIDR; bodega profile bind $FBSD_PROFILE" "$E2E_RC"
e2e_reload server || true
sleep 3

E2E_HOST=freebsd
e2e_on freebsd "sudo mkdir -p /usr/local/etc/pkg/fingerprints/bodega/trusted /usr/local/etc/pkg/fingerprints/bodega/revoked && \
	printf '%s\n' '$fbsd_fpr' | sudo tee /usr/local/etc/pkg/fingerprints/bodega/trusted/bodega >/dev/null && \
	sudo bodega doctor --write-pkg-repo --url '$E2E_BASE_URL' --allow-plaintext >/dev/null && \
	grep -E '^  (url|fingerprints):' /usr/local/etc/pkg/repos/bodega.conf" || true
check_contains FBSD-PROF-05 "doctor --write-pkg-repo points a bound host at its profile's catalogue" \
	"/freebsd-profile/$FBSD_PROFILE/\${ABI}/e2e-latest" "$E2E_OUT" \
	"internal/server/freebsd_status.go" "bodega doctor --write-pkg-repo; grep url bodega.conf"
check_contains FBSD-PROF-06 "the stanza trusts bodega's key rather than FreeBSD's" \
	"/usr/local/etc/pkg/fingerprints/bodega" "$E2E_OUT" \
	"internal/pkgrepos" "grep fingerprints bodega.conf"

e2e_on freebsd "sudo pkg update -f 2>&1 | tail -3" || true
check_contains FBSD-PROF-07 "pkg update verifies the filtered catalogue against bodega's key" \
	"bodega-e2e-latest repository update completed" "$E2E_OUT" \
	"internal/server/freebsd_profile.go" "pkg update -f"

e2e_on freebsd "pkg search -r bodega-e2e-latest -q -x '.*' | sed -E 's/-[^-]+\$//' | sort | tr '\n' ' '" || true
check_eq FBSD-PROF-08 "pkg search finds the two listed packages and nothing else" "pv tree " "$E2E_OUT" \
	"internal/server/freebsd_profile.go" "pkg search -r bodega-e2e-latest -x '.*'"

e2e_on freebsd "sudo pkg install -y -r bodega-e2e-latest tree 2>&1 | tail -2 && pkg query '%n %R' tree" || true
check_contains FBSD-PROF-09 "a listed package installs through the filtered catalogue" \
	"tree bodega-e2e-latest" "$E2E_OUT" "internal/server/freebsd_profile.go" "pkg install -r bodega-e2e-latest tree"

e2e_on freebsd "sudo pkg install -y -r bodega-e2e-latest nano 2>&1 | tail -2" || true
fbsd_install_rc="$E2E_RC"
check_contains FBSD-PROF-10 "pkg install of an unlisted package fails at the catalogue" \
	"No packages available to install matching 'nano'" "$E2E_OUT" \
	"internal/server/freebsd_profile.go" "pkg install -r bodega-e2e-latest nano" "$fbsd_install_rc"
check_ne FBSD-PROF-11 "the failed install exits non-zero" 0 "$fbsd_install_rc" \
	"internal/server/freebsd_profile.go" "pkg install -r bodega-e2e-latest nano" "$fbsd_install_rc"

e2e_on freebsd "curl -sS --max-time 60 -w '\n%{http_code}' '$fbsd_repo_url/$fbsd_third'" || true
check_contains FBSD-PROF-12 "a hand-composed fetch of the unlisted package is refused in the profile's vocabulary" \
	"membership: profile \"$FBSD_PROFILE\" does not list freebsd/nano" "$E2E_OUT" \
	"internal/server/freebsd_profile.go" "curl $fbsd_repo_url/$fbsd_third" "$E2E_RC"
check_matches FBSD-PROF-13 "the refusal is a 403" '403$' "$E2E_OUT" \
	"internal/server/freebsd_profile.go" "curl -w %{http_code} $fbsd_repo_url/$fbsd_third" "$E2E_RC"

e2e_on freebsd "curl -sS --max-time 60 -o /dev/null -w '%{http_code}' '$fbsd_repo_url/packagesite.pkg'" || true
check_eq FBSD-PROF-14 "the bound host is refused the unfiltered catalogue" "403" "$E2E_OUT" \
	"internal/server/freebsd_profile.go" "curl $fbsd_repo_url/packagesite.pkg" "$E2E_RC"

# Restore: the package off the guest, then its pkg configuration from the
# seeded copy, compared against that copy's state, then from the copy taken
# before the suite wrote anything, compared the same way. Then the binding off
# the server. The profile stays, as 55-profile's does, because there is no
# profile delete.
e2e_on freebsd "sudo pkg delete -y tree >/dev/null 2>&1; sudo sh $FBSD_PKGCONF restore seeded && sudo sh $FBSD_PKGCONF state" || true
check_eq FBSD-PROF-15 "a pre-existing stanza and fingerprint directory come back byte for byte" \
	"$fbsd_conf_seeded" "$E2E_OUT" "test/e2e/suites/47-freebsd-client.sh" "sh $FBSD_PKGCONF restore seeded; state" "$E2E_RC"
e2e_on freebsd "sudo sh $FBSD_PKGCONF restore found && sudo sh $FBSD_PKGCONF state" || true
check_eq FBSD-PROF-16 "the guest's pkg configuration is restored as the suite found it" \
	"$fbsd_conf_found" "$E2E_OUT" "test/e2e/suites/47-freebsd-client.sh" "sh $FBSD_PKGCONF restore found; state" "$E2E_RC"
trap cleanup EXIT
trap - INT TERM
e2e_on freebsd "sudo sh $FBSD_PKGCONF drop; rm -f $FBSD_PKGCONF" || true

E2E_HOST=server
e2e_bodega server "profile unbind e2e-fbsd-host" || true
e2e_bodega server "identity unbind cidr $FBSD_CIDR" || true
e2e_bodega server "pkg delete freebsd e2e-latest" || true
e2e_reload server || true
unset fbsd_abi FBSD_PROFILE FBSD_CIDR fbsd_repo_url fbsd_third fbsd_fpr fbsd_install_rc fbsd_warn \
	FBSD_PKGCONF fbsd_pkgconf_local fbsd_conf_found fbsd_conf_seeded

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
