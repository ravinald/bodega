# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The distfiles type, driven from a FreeBSD root. 47-freebsd-client fetches a
# distfile through a binary namespace, which pins whatever its first fetch
# returned; this suite drives /distfiles/ (internal/server/distfiles.go) and
# 'bodega build fetch distfiles' (internal/builder/distfiles.go), the two
# deliveries that hold a distfile to the port's distinfo and honor RESTRICTED
# and NO_CDROM against a declared client environment.
#
# Every check below the client-check assertion depends on it. A client whose
# check names "unsupported" falls through to the port's own sites, so make
# fetch still succeeds and a passing fetch alone says nothing about this route.
#
# This suite mutates both ends. The server gets a ports tree at /usr/ports,
# distfiles_* keys in config.json and a distfiles manifest entry, all removed
# at the end, and whatever 47 cached under binaries/distfiles is moved aside
# in storage and put back. The freebsd guest gets two read-only nullfs mounts,
# over the scratch tree and over /usr/share/mk, and a fetch user with no sudo
# grant; the mounts are lifted and the user removed at the end, and both are
# checked.

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
	e2e_block FDIST-BLOCK "the FreeBSD distfiles route" "the server guest is unreachable"
	return 0
fi

E2E_HOST=freebsd
if e2e_on freebsd true 2>/dev/null; then
	e2e_record FDIST-00 PASS "the freebsd guest answers ssh" "reachable" "reachable" "ssh $E2E_FREEBSD_HOST true" 0 ""
else
	e2e_record FDIST-00 FAIL "the freebsd guest answers ssh" "reachable" "$E2E_ERR" "ssh $E2E_FREEBSD_HOST true" "$E2E_RC" "test/e2e/README.md"
	e2e_block FDIST-BLOCK-HOST "the FreeBSD distfiles route" "the freebsd guest ($E2E_FREEBSD_HOST) is unreachable; power it on"
	return 0
fi

# fd_sh <script> — run a POSIX sh script on the freebsd guest. ravi's login
# shell there is tcsh, which has no $(...) and reads 2>&1 differently, so
# anything past a plain command line goes through sh on stdin.
fd_sh() {
	e2e_on freebsd "sh -s" <<<"set -o pipefail
$1"
}

# fd_wait_index <environment> — poll until the server has read the tree, and
# leave the status of a name no distinfo lists in E2E_OUT. A cold read of the
# full tree takes the better part of a minute and answers 503 until it lands.
fd_wait_index() {
	e2e_on server "i=0; while :; do c=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
		'http://127.0.0.1:8080/distfiles/@$1/bodega-e2e/not-in-any-distinfo.tar.gz'); \
		[ \"\$c\" != 503 ] && [ \"\$c\" != 000 ] || [ \$i -ge 90 ] && break; sleep 2; i=\$((i+1)); done; echo \$c"
}

# Off /tmp: a ports tree is what fills a small /tmp, and a full filesystem
# reads as a fetch failure. Apart from 47's root, so a mount an aborted run
# left here never sits under a tree 47 removes.
FD_ROOT="${E2E_FREEBSD_DISTFILES_ROOT:-/var/tmp/bodega-e2e-distfiles}"
FD_PORTS="$FD_ROOT/usr/ports"
FD_DISTDIR="$FD_ROOT/distfiles"
FD_WRK="$FD_ROOT/wrk"
FD_MIRROR="$FD_ROOT/mirror"
FD_SYSMK=/usr/share/mk

# The port sets DIST_SUBDIR to something other than its own name, because the
# subdirectory is the part of the distfile path an override most easily
# drops; its one distfile is 2.4 KB. games/adom is the restricted one: 15.1's
# tree sets NO_CDROM in its Makefile, where the reader can read it without
# evaluating anything, and internal/builder/distfiles_test.go models the same
# port.
FD_PORT=databases/sqlite-ext-pcre
FD_SUBDIR=sqlite-ext
FD_RPORT=games/adom

# The server's tree sits at /usr/ports rather than in a scratch directory.
# java/bootstrap-openjdk8/Makefile.update sets PORTSDIR=/usr/ports in one
# branch of an .if, the reader reads every branch, and anywhere else that
# include leaves the tree: the port goes unplaced and every distfile in the
# tree is refused on its account. The Linux server has no ports tree of its
# own, and the stamp keeps this suite from removing one it did not write.
FD_SERVER_TREE=/usr/ports
FD_STAMP="$FD_SERVER_TREE/.bodega-e2e-49"
FD_SERVER_ROOT=/var/tmp/bodega-e2e-distfiles-server

# make runs as an account the suite creates, because a make that can sudo can
# lift the read-only mounts stableView reads, and stableView cannot see a
# grant (docs/usage.md#the-client-check). ravi's grant is passwordless. The
# comment field marks the account as this suite's, so cleanup never removes
# one it did not create.
FD_USER=bodega-e2e-fetch
FD_USER_MARK="bodega e2e suite 49 fetch user"
fd_user_drop="[ \"\$(sudo -n pw usershow -n $FD_USER 2>/dev/null | cut -d: -f8)\" = '$FD_USER_MARK' ] \
	&& sudo -n pw userdel -n $FD_USER; true"
fd_as="sudo -n -u $FD_USER env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin HOME=/nonexistent"

ports_sha="$(printf '%s' "$(e2e_fixture ports-txz)" | jq -r '.versions[0].sha256')"
ports_url="$E2E_BASE_URL/binaries/freebsd-ports/15.1-RELEASE/ports.txz"
fd_make="$fd_as __MAKE_CONF=$FD_ROOT/make.conf make -C $FD_PORTS/$FD_PORT WRKDIRPREFIX=$FD_WRK"
fd_make_http="$fd_make DISTDIR=$FD_DISTDIR"

# The declaration a stock 15.1 arm64 client needs, measured against this
# tree: without the variables and absent files below, 140 ports read
# something only the client holds and their distinfo cannot be placed, which
# refuses every distfile. DISTDIR and WRKDIRPREFIX are added because this
# suite passes them on the command line, and a command-line variable outside
# the declaration and the framework's own list names the client
# "unsupported". PORTSDIR cannot be declared at all, so it goes in make.conf,
# where an undeclared variable is not checked.
fd_decl_files='{"/usr/local/etc/aspell.ver": ["absent"], "/var/db/wanted-ports.conf": ["absent"], "/tmp/PERL5_DEFAULT": ["absent"], "/Makefile.common": ["absent"], "/usr/share/mk/Makefile.local": ["absent"]}'
# shellcheck disable=SC2016 # ${PORTSDIR} is a make variable the client expands.
fd_decl_stock='"LOCALBASE": ["/usr/local"], "ARCH": ["aarch64"], "USESDIR": ["${PORTSDIR}/Mk/Uses"], "NODEJS_VERSION": ["24"], "LLVM_DEFAULT": ["19"], "PKGNAMESUFFIX": [], "WANTEDPORTSCFG": [], "CFENGINE_VERSION": [], "CFGFILE": [], "KRB5_VERSION": [], "LLVM_SUFFIX": [], "WANT_PGSQL_VER": [], "XPDF_VERSION": [], "OPTIONS_DEFINE": []'
fd_decl_http="{$fd_decl_stock, \"DISTDIR\": [\"$FD_DISTDIR\"], \"WRKDIRPREFIX\": [\"$FD_WRK\"]}"
# The DISTDIR delivery names its directory from ${BODEGA_DISTFILES_ENV}, and a
# declared variable is compared while that digest expands, so make exits 2
# with "Variable DISTDIR is recursive". It gets the same declaration without
# DISTDIR, and a digest of its own.
fd_decl_distdir="{$fd_decl_stock, \"WRKDIRPREFIX\": [\"$FD_WRK\"]}"

# ---- server ----------------------------------------------------------------
#
# A binary namespace answering /binaries/distfiles/ is how 47 fetches a
# distfile, and a fallthrough to one would read as a hit here.

E2E_HOST=server
e2e_config_set server '.binary_upstreams = {}' || true
e2e_restart server || true

fd_storage=/var/lib/bodega
e2e_config_get server '.storage_path // "/var/lib/bodega"' || true
[ -n "$E2E_OUT" ] && fd_storage="$E2E_OUT"

# 47 leaves the tarball in storage; a filtered run, or a store reset since,
# does not.
e2e_http server /binaries/freebsd-ports/15.1-RELEASE/ports.txz || true
if [ "$E2E_OUT" != 200 ]; then
	e2e_on server "cat > /tmp/e2e-fx-ports-txz.json <<'E2EFIXTURE'
$(e2e_fixture ports-txz)
E2EFIXTURE" || true
	e2e_bodega server "pkg import --merge /tmp/e2e-fx-ports-txz.json && sudo bodega build upload binary freebsd-ports" || true
fi

# The server reads distinfo from the tarball the guest builds from, byte for
# byte: a name the two trees pin differently is refused by one side or the
# other, and a suite that skews them proves neither.
e2e_on server "if [ -e $FD_SERVER_TREE ] && [ ! -e $FD_STAMP ]; then echo 'foreign tree'; exit 3; fi; \
	sudo rm -rf $FD_SERVER_ROOT $FD_SERVER_TREE && mkdir -p $FD_SERVER_ROOT && \
	curl -sSf -o $FD_SERVER_ROOT/ports.txz '$ports_url' && \
	sudo tar -xf $FD_SERVER_ROOT/ports.txz -C / usr/ports && sudo touch $FD_STAMP && \
	sha256sum $FD_SERVER_ROOT/ports.txz | cut -d' ' -f1" || true
check_eq FDIST-01 "the server's ports tree comes from the tarball the release MANIFEST names" \
	"$ports_sha" "$E2E_OUT" "docs/usage.md#mirroring-ports-distfiles" \
	"curl $ports_url | sha256; tar -xf -C / usr/ports" "$E2E_RC"

e2e_on server "awk -F'[()]' '/^SHA256/{print \$2; exit}' $FD_SERVER_TREE/$FD_PORT/distinfo" || true
fd_name="$E2E_OUT"
e2e_on server "awk -F'[()]' '/^SHA256/{print \$2; exit}' $FD_SERVER_TREE/$FD_RPORT/distinfo" || true
fd_rname="$E2E_OUT"
check_matches FDIST-02 "the tree pins the port's distfile under its DIST_SUBDIR" "^$FD_SUBDIR/[^/]+\$" \
	"${fd_name:-none}" "$FD_SERVER_TREE/$FD_PORT/distinfo" "awk distinfo"

e2e_bodega server "pkg delete distfiles '$fd_name' >/dev/null 2>&1; sudo rm -rf $fd_storage/distfiles" || true
e2e_config_set server ".distfiles_ports_tree = \"$FD_SERVER_TREE\" \
	| .distfiles_upstream = \"http://distcache.FreeBSD.org/ports-distfiles/\" \
	| .distfiles_environment_variables = $fd_decl_http \
	| .distfiles_environment_files = $fd_decl_files" || true
e2e_restart server || true

e2e_body server /distfiles/@environment.mk || true
fd_check="$E2E_OUT"
fd_digest="$(printf '%s\n' "$fd_check" | sed -n '1s/^# bodega distfiles client check for environment \([0-9a-f]*\)\.$/\1/p')"
check_matches FDIST-03 "the server serves a client check naming its environment" '^[0-9a-f]{64}$' \
	"${fd_digest:-none}" "internal/server/distfiles.go:277" "curl /distfiles/@environment.mk"

fd_wait_index "$fd_digest" || true
check_eq FDIST-04 "the server finishes reading the tree and answers a name no distinfo lists" "404" \
	"$E2E_OUT" "internal/server/distfiles.go:193" "curl /distfiles/@<env>/bodega-e2e/..." "$E2E_RC"

# An empty binary_upstreams still reads storage (internal/server/binary.go),
# so an object 47's open namespace cached there answers the name. It moves
# aside under the storage root rather than to /tmp, which the unit keeps
# private, and cleanup puts it back. A stash an aborted run left is restored
# before anything moves, and one that would overwrite a live tree stays put.
fd_bin="$fd_storage/binaries/distfiles"
fd_bin_stash="$fd_storage/.bodega-e2e-49-binaries-distfiles"
e2e_on server "if sudo test -e $fd_bin_stash; then \
	if sudo test -e $fd_bin; then echo conflict; exit 3; fi; sudo mv $fd_bin_stash $fd_bin; fi; \
	if sudo test -e $fd_bin; then sudo mv $fd_bin $fd_bin_stash && echo moved; else echo none; fi" || true
fd_bin_moved="$E2E_OUT"
e2e_http server "/binaries/distfiles/$fd_name" || true
check_ne FDIST-05 "no binary namespace answers the distfile" "200" "$E2E_OUT" \
	"internal/server/binary.go" "mv $fd_bin aside ($fd_bin_moved); curl /binaries/distfiles/$fd_name"

# ---- client ----------------------------------------------------------------
#
# A mount left by an aborted run is lifted first, or the rm below fails on a
# read-only tree and the extract lands on top of the old one.

E2E_HOST=freebsd
# The guests resolve through public DNS and public_url names the server by
# its internal name; same tag as 47, so one sed clears both.
fd_sh "sudo -n sed -i '' '/# bodega-e2e\$/d' /etc/hosts &&
printf '%s %s # bodega-e2e\\n' '$E2E_SERVER_ADDR' '$E2E_SERVER_HOST' | sudo -n tee -a /etc/hosts >/dev/null &&
curl -sS -o /dev/null -w '%{http_code}' --max-time 10 '$E2E_BASE_URL/healthz'" || true
check_eq FDIST-06 "the freebsd guest reaches the server by name" "200" "$E2E_OUT" \
	"test/e2e/suites/10-ship-install.sh" "curl $E2E_BASE_URL/healthz" "$E2E_RC"

fd_sh "$fd_user_drop
sudo -n pw useradd -n $FD_USER -c '$FD_USER_MARK' -d /nonexistent -s /usr/sbin/nologin &&
sudo -n pw usershow -n $FD_USER | cut -d: -f8" || true
check_eq FDIST-07 "a fetch user for make is created" "$FD_USER_MARK" "$E2E_OUT" \
	"test/e2e/suites/49-freebsd-distfiles.sh" "pw useradd -n $FD_USER" "$E2E_RC"

# Asked from both sides: sudoers lists nothing for the user, and the user's
# own sudo and doas both refuse.
fd_sh "sudo -n -l -U $FD_USER | grep -q 'is not allowed to run sudo' && echo sudoers:none || echo sudoers:granted
$fd_as sudo -n true >/dev/null 2>&1 && echo sudo:granted || echo sudo:refused
if [ -x /usr/local/bin/doas ]; then $fd_as /usr/local/bin/doas -n true >/dev/null 2>&1 && echo doas:granted || echo doas:refused; else echo doas:absent; fi" || true
check_eq FDIST-08 "the fetch user holds no grant that could lift the mounts" \
	"sudoers:none|sudo:refused|doas:absent" "$(printf '%s' "$E2E_OUT" | tr '\n' '|')" \
	"docs/usage.md#the-client-check" "sudo -l -U $FD_USER; sudo -u $FD_USER sudo -n true" "$E2E_RC"

fd_unmount="for p in $FD_PORTS $FD_SYSMK; do \
	/sbin/mount -p | awk -v p=\"\$p\" '\$2 == p && \$3 == \"nullfs\" {f=1} END {exit !f}' && sudo -n umount \"\$p\"; \
done; true"
fd_sh "$fd_unmount
sudo -n rm -rf $FD_ROOT && mkdir -p $FD_DISTDIR $FD_WRK $FD_MIRROR &&
sudo -n chown $FD_USER $FD_DISTDIR $FD_WRK &&
curl -sS -o $FD_ROOT/ports.txz '$ports_url' &&
tar -xf $FD_ROOT/ports.txz -C $FD_ROOT usr/ports/Mk usr/ports/Templates usr/ports/Keywords \
	usr/ports/$FD_PORT usr/ports/$FD_RPORT &&
sha256 -q $FD_ROOT/ports.txz" || true
check_eq FDIST-10 "the freebsd guest builds from the same tarball" "$ports_sha" "$E2E_OUT" \
	"docs/usage.md#mirroring-ports-distfiles" "curl $ports_url | sha256" "$E2E_RC"

e2e_on server "sha256sum $FD_SERVER_TREE/$FD_PORT/distinfo $FD_SERVER_TREE/$FD_RPORT/distinfo | cut -d' ' -f1 | tr '\n' ' '" || true
fd_server_pins="$E2E_OUT"
fd_sh "sha256 -q $FD_PORTS/$FD_PORT/distinfo $FD_PORTS/$FD_RPORT/distinfo | tr '\n' ' '" || true
check_eq FDIST-11 "both ends read the same distinfo for both ports" "$fd_server_pins" "$E2E_OUT" \
	"docs/usage.md#mirroring-ports-distfiles" "sha256 distinfo, on each end" "$E2E_RC"

# make.conf is written here and shipped, because its make variables would be
# expanded by any shell asked to write it. __MAKE_CONF points make at it, so
# the guest's /etc/make.conf is never touched and an aborted run leaves the
# host's own make as it was.
fd_conf="$(mktemp "${TMPDIR:-/tmp}/e2e-make-conf.XXXXXX")"
fd_check_file="$(mktemp "${TMPDIR:-/tmp}/e2e-check.XXXXXX")"
printf '%s\n' "$fd_check" >"$fd_check_file"
cat >"$fd_conf" <<EOF
PORTSDIR=	$FD_PORTS
MASTER_SITE_OVERRIDE?=	$E2E_BASE_URL/distfiles/@\${BODEGA_DISTFILES_ENV}/\${DIST_SUBDIR}/
.include "$FD_ROOT/bodega-distfiles.mk"
EOF
e2e_put freebsd "$fd_check_file" "$FD_ROOT/bodega-distfiles.mk" || true
e2e_put freebsd "$fd_conf" "$FD_ROOT/make.conf" || true
fd_sh "chmod 0644 $FD_ROOT/bodega-distfiles.mk $FD_ROOT/make.conf" || true

# The client check refuses a tree or /usr/share/mk that make could change
# while it reads a port: a nullfs over itself, read-only, leaves no second
# name for the files, and make runs as the fetch user, who can lift neither.
# The tree is root's, as the client check's documentation asks, so the mount
# is not the only thing between the fetch user and its files.
fd_sh "sudo -n chown -R root:wheel $FD_PORTS && sudo -n mount -t nullfs -o ro $FD_PORTS $FD_PORTS && sudo -n mount -t nullfs -o ro $FD_SYSMK $FD_SYSMK &&
/sbin/mount -p | awk '(\$2 == \"$FD_PORTS\" || \$2 == \"$FD_SYSMK\") && \$1 == \$2 && \$3 == \"nullfs\" && \$4 ~ /(^|,)ro(,|\$)/ {n++} END {print n+0}'" || true
check_eq FDIST-12 "the tree and /usr/share/mk sit on read-only nullfs mounts" "2" "$E2E_OUT" \
	"internal/distinfo/environment.go:372" "mount -t nullfs -o ro; mount -p" "$E2E_RC"

# The assertion everything below depends on.
fd_sh "$fd_make_http -V BODEGA_DISTFILES_ENV -V BODEGA_DISTFILES_DRIFT" || true
fd_env="$(printf '%s\n' "$E2E_OUT" | sed -n 1p)"
# The drift list keeps a separator for every term that expanded to nothing.
fd_drift="$(printf '%s\n' "$E2E_OUT" | awk 'NR == 2 {$1 = $1; print}')"
check_eq FDIST-13 "the guest's check names the environment the server admitted against" \
	"$fd_digest" "$fd_env${fd_drift:+ (drift: $fd_drift)}" "internal/distinfo/environment.go:239" \
	"make -V BODEGA_DISTFILES_ENV -V BODEGA_DISTFILES_DRIFT" "$E2E_RC"

if [ "${E2E_DRY_RUN:-no}" = yes ] || { [ -n "$fd_digest" ] && [ "$fd_env" = "$fd_digest" ]; }; then
	# ---- HTTP delivery -----------------------------------------------------
	#
	# One attempt, naming bodega's /distfiles/ route under this environment, is
	# what says the bytes came through it: do-fetch.sh prints a line per site
	# and moves on to the port's own sites after any failure.
	fd_route="$E2E_BASE_URL/distfiles/@$fd_digest"
	fd_sh "$fd_make_http fetch 2>&1 | \
		awk -v p='$fd_route/$FD_SUBDIR/' '/Attempting to fetch/{n++; u=\$NF} END{print n+0, (index(u, p) == 1 ? \"bodega\" : u)}'" || true
	fd_fetch="$E2E_OUT"
	check_eq FDIST-20 "make fetch succeeds against the distfiles route" 0 "$E2E_RC" \
		"docs/usage.md#client-side-http" "make fetch MASTER_SITE_OVERRIDE=$fd_route/..." "$E2E_RC"
	check_eq FDIST-21 "make fetch takes the distfile from /distfiles/ on the first and only attempt" \
		"1 bodega" "$fd_fetch" "internal/server/distfiles.go:105" "make fetch | grep 'Attempting to fetch'"
	fd_sh "$fd_make_http checksum 2>&1 | tail -1" || true
	check_contains FDIST-22 "make checksum accepts the bytes the route admitted" \
		"Checksum OK" "$E2E_OUT" "docs/usage.md#mirroring-ports-distfiles" "make checksum"

	# ---- restricted ----------------------------------------------------------
	#
	# Read on the guest under the declared environment first: a 451 for a port
	# whose terms the reader could not read would pass the status check for
	# the wrong reason.
	fd_sh "$fd_as __MAKE_CONF=$FD_ROOT/make.conf make -C $FD_PORTS/$FD_RPORT WRKDIRPREFIX=$FD_WRK DISTDIR=$FD_DISTDIR \
		-V BODEGA_DISTFILES_ENV -V NO_CDROM -V '\${RESTRICTED:Uunset}'" || true
	check_eq FDIST-30 "the guest reads games/adom's terms under the declared environment" \
		"$fd_digest|Copy of CD must be sent to author|unset" "$(printf '%s' "$E2E_OUT" | tr '\n' '|')" \
		"$FD_RPORT/Makefile" "make -C $FD_RPORT -V NO_CDROM" "$E2E_RC"
	fd_sh "curl -sS -w '\n%{http_code}' --max-time 60 '$fd_route/$fd_rname'" || true
	fd_rstatus="$(printf '%s\n' "$E2E_OUT" | tail -1)"
	fd_rbody="$(printf '%s\n' "$E2E_OUT" | sed '$d')"
	check_eq FDIST-31 "a NO_CDROM distfile is refused with 451" "451" "$fd_rstatus" \
		"internal/server/distfiles.go:180" "curl $fd_route/$fd_rname" "$E2E_RC"
	check_contains FDIST-32 "the refusal names the port's own term" "$FD_RPORT sets NO_CDROM" "$fd_rbody" \
		"internal/server/distfiles.go:186" "curl $fd_route/$fd_rname"
	check_lacks FDIST-33 "the refusal does not name the upstream" "distcache.FreeBSD.org" "$fd_rbody" \
		"internal/server/distfiles.go:186" "curl $fd_route/$fd_rname"
	check_lacks FDIST-34 "the refusal names no path on the server" "$FD_SERVER_TREE" "$fd_rbody" \
		"internal/server/distfiles.go:186" "curl $fd_route/$fd_rname"
	check_lacks FDIST-35 "the refusal does not name the server's storage" "$fd_storage" "$fd_rbody" \
		"internal/server/distfiles.go:186" "curl $fd_route/$fd_rname"

	# ---- a repinned name -----------------------------------------------------
	#
	# The server's tree pins the name to other bytes of the same size, so the
	# declared length passes and the digest is what refuses. The object cached
	# above is re-hashed on the hit, disagrees, and the refetch disagrees too.
	# The guest's tree is untouched, so a refusal here is the server's.
	E2E_HOST=server
	e2e_on server "sudo cp $FD_SERVER_TREE/$FD_PORT/distinfo $FD_SERVER_ROOT/distinfo.orig && \
		sudo sed -i 's/^SHA256 (\\(.*\\)) = [0-9a-f]*\$/SHA256 (\\1) = $(printf '%064d' 0)/' $FD_SERVER_TREE/$FD_PORT/distinfo" || true
	e2e_restart server || true
	fd_wait_index "$fd_digest" || true
	E2E_HOST=freebsd
	fd_sh "curl -sS -w '\n%{http_code}' --max-time 60 '$fd_route/$fd_name'" || true
	fd_pstatus="$(printf '%s\n' "$E2E_OUT" | tail -1)"
	fd_pbody="$(printf '%s\n' "$E2E_OUT" | sed '$d')"
	check_eq FDIST-40 "the server refuses bytes its distinfo no longer pins" "502" "$fd_pstatus" \
		"internal/server/distfiles.go:251" "curl $fd_route/$fd_name after repinning it on the server" "$E2E_RC"
	check_contains FDIST-41 "the refusal says the bytes disagree with distinfo" \
		"do not match the ports tree's distinfo" "$fd_pbody" "internal/server/distfiles.go:359" "curl $fd_route/$fd_name"
	E2E_HOST=server
	e2e_on server "sudo install -m 0644 $FD_SERVER_ROOT/distinfo.orig $FD_SERVER_TREE/$FD_PORT/distinfo" || true
else
	e2e_block FDIST-BLOCK-ENV "the HTTP delivery, the restricted refusal and the repinned name" \
		"the guest's check named '${fd_env:-nothing}' rather than the admitted environment, so nothing it fetches proves this route"
fi

# ---- DISTDIR delivery --------------------------------------------------------
#
# The builder writes <distfiles_root>/distfiles/@<environment>/ and the check
# beside it; the guest reads a copy, picks the directory its own check names,
# and has nothing to fetch.

E2E_HOST=server
e2e_config_set server ".distfiles_environment_variables = $fd_decl_distdir" || true
e2e_restart server || true
e2e_bodega server "pkg create distfiles '$fd_name' >/dev/null 2>&1; sudo bodega build fetch distfiles 2>&1" || true
fd_art="$(printf '%s\n' "$E2E_OUT" | sed -n "s|^ *artifact: \(.*/distfiles/@[0-9a-f]*\)/$fd_name\$|\1|p" | tail -1)"
check_ne FDIST-50 "build fetch distfiles writes the distfile into an environment's DISTDIR" "" "$fd_art" \
	"internal/builder/distfiles.go" "bodega build fetch distfiles" "$E2E_RC"
fd_digest2="${fd_art##*/@}"
fd_distroot="${fd_art%/@*}"
e2e_body server /distfiles/@environment.mk || true
check_eq FDIST-51 "the builder keys the DISTDIR by the digest the server serves" \
	"$(printf '%s\n' "$E2E_OUT" | sed -n '1s/^# bodega distfiles client check for environment \([0-9a-f]*\)\.$/\1/p')" \
	"$fd_digest2" "internal/builder/distfiles.go" "ls <distfiles_root>/distfiles; curl /distfiles/@environment.mk"

# Server to guest through this workstation, because the guests hold no key
# for each other. The copy carries @environment.mk beside the directories, so
# the guest includes the check the builder wrote rather than the server's.
fd_copy_rc=0
if [ "${E2E_DRY_RUN:-no}" != yes ] && [ -n "$fd_distroot" ]; then
	fd_sopts=()
	while IFS= read -r o; do fd_sopts+=("$o"); done < <(e2e_ssh_opts "$(e2e_host_for server)")
	fd_fopts=()
	while IFS= read -r o; do fd_fopts+=("$o"); done < <(e2e_ssh_opts "$(e2e_host_for freebsd)")
	ssh "${fd_sopts[@]}" -- "sudo tar -C '$fd_distroot' -cf - ." |
		ssh "${fd_fopts[@]}" -- "tar -xf - -C $FD_MIRROR" || fd_copy_rc=$?
fi

cat >"$fd_conf" <<EOF
PORTSDIR=	$FD_PORTS
DISTDIR=	$FD_MIRROR/@\${BODEGA_DISTFILES_ENV}
.include "$FD_MIRROR/@environment.mk"
EOF
E2E_HOST=freebsd
e2e_put freebsd "$fd_conf" "$FD_ROOT/make.conf" || true
fd_sh "$fd_make -V BODEGA_DISTFILES_ENV -V BODEGA_DISTFILES_DRIFT" || true
fd_env2="$(printf '%s\n' "$E2E_OUT" | sed -n 1p)"
fd_drift2="$(printf '%s\n' "$E2E_OUT" | awk 'NR == 2 {$1 = $1; print}')"
check_eq FDIST-52 "the guest's check, read from the builder's copy, names the DISTDIR's environment" \
	"$fd_digest2" "$fd_env2${fd_drift2:+ (drift: $fd_drift2)}" "docs/usage.md#client-side-distdir" \
	"tar | tar $FD_MIRROR (rc $fd_copy_rc); make -V BODEGA_DISTFILES_ENV" "$E2E_RC"

fd_sh "{ $fd_make fetch 2>&1 && $fd_make checksum 2>&1; } | \
	awk '/Attempting to fetch/{n++} /Checksum OK/{ok=1} END{print n+0, (ok ? \"ok\" : \"no-checksum\")}'" || true
check_eq FDIST-53 "make fetch and make checksum pass from the DISTDIR with no fetch attempted" \
	"0 ok" "$E2E_OUT" "internal/builder/distfiles.go" "make fetch; make checksum | grep -c 'Attempting to fetch'" "$E2E_RC"

# A client that drifts names a directory the builder never writes. BATCH on
# the command line is undeclared, which is enough.
fd_sh "$fd_make BATCH=yes -V BODEGA_DISTFILES_ENV -V DISTDIR | tr '\n' ' '; \
	[ -e $FD_MIRROR/@unsupported ] && echo present || echo absent" || true
check_eq FDIST-54 "a drifted client's DISTDIR is one the builder never writes" \
	"unsupported $FD_MIRROR/@unsupported absent" "$E2E_OUT" "internal/distinfo/environment.go:363" \
	"make BATCH=yes -V BODEGA_DISTFILES_ENV -V DISTDIR" "$E2E_RC"

# ---- cleanup -----------------------------------------------------------------

fd_sh "$fd_unmount
/sbin/mount -p | awk '\$2 == \"$FD_PORTS\" || \$2 == \"$FD_SYSMK\" {n++} END {print n+0}'" || true
check_eq FDIST-90 "both nullfs mounts are lifted again" "0" "$E2E_OUT" \
	"test/e2e/suites/49-freebsd-distfiles.sh" "umount; mount -p" "$E2E_RC"
fd_sh "sudo -n rm -rf $FD_ROOT; $fd_user_drop
sudo -n pw usershow -n $FD_USER >/dev/null 2>&1 && echo present || echo absent" || true
check_eq FDIST-92 "the fetch user is removed again" "absent" "$E2E_OUT" \
	"test/e2e/suites/49-freebsd-distfiles.sh" "pw userdel -n $FD_USER" "$E2E_RC"

E2E_HOST=server
e2e_bodega server "pkg delete distfiles '$fd_name'" || true
e2e_on server "sudo rm -rf $fd_storage/distfiles $FD_SERVER_ROOT ${fd_distroot:-/nonexistent-e2e}; \
	[ -e $FD_STAMP ] && sudo rm -rf $FD_SERVER_TREE; true" || true
e2e_config_set server 'del(.distfiles_ports_tree, .distfiles_upstream, .distfiles_environment_variables, .distfiles_environment_files)' || true
e2e_restart server || true
e2e_config_get server '[.distfiles_ports_tree, .distfiles_environment_variables] | map(select(. != null)) | length' || true
check_eq FDIST-91 "the distfiles configuration is removed again" "0" "$E2E_OUT" \
	"test/e2e/suites/49-freebsd-distfiles.sh" "jq distfiles_* config.json"

e2e_on server "if sudo test -e $fd_bin_stash; then \
	if sudo test -e $fd_bin; then echo conflict; exit 3; fi; sudo mv $fd_bin_stash $fd_bin && echo moved; else echo none; fi" || true
check_eq FDIST-93 "what 47 cached under binaries/distfiles is put back" "$([ "${fd_bin_moved:-none}" = none ] && echo none || echo moved)" "$E2E_OUT" \
	"test/e2e/suites/49-freebsd-distfiles.sh" "mv $fd_bin_stash $fd_bin" "$E2E_RC"

rm -f "$fd_conf" "$fd_check_file"
unset FD_ROOT FD_PORTS FD_DISTDIR FD_WRK FD_MIRROR FD_SYSMK FD_PORT FD_SUBDIR FD_RPORT FD_SERVER_TREE \
	FD_STAMP FD_SERVER_ROOT FD_USER FD_USER_MARK fd_user_drop fd_as fd_bin fd_bin_stash fd_bin_moved ports_sha ports_url fd_make fd_make_http fd_decl_files fd_decl_stock fd_decl_http \
	fd_decl_distdir fd_storage fd_name fd_rname fd_check fd_digest fd_unmount fd_server_pins fd_conf \
	fd_check_file fd_env fd_drift fd_route fd_fetch fd_rstatus fd_rbody fd_pstatus fd_pbody fd_art fd_digest2 \
	fd_distroot fd_copy_rc fd_sopts fd_fopts fd_env2 fd_drift2
