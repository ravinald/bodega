# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# internal/storage's FreeBSD syscalls, run against the kernel they call.
# acl_freebsd.go and xattr_freebsd.go compile into no binary either Linux guest
# runs, and the conformance tests every platform runs check the encoders
# against a reading of the interface rather than against the interface. This
# suite ships the package's test binary to freebsd-server and runs the tests in
# internal/storage/guest_freebsd_test.go, plus the two publication tests that
# set a FreeBSD ACL, in four cells:
#
#   ZFS (the guest's root, NFSv4 ACLs)        x  an unprivileged user and root
#   UFS on a memory disk mounted -o acls      x  an unprivileged user and root
#
# Both filesystems because each keeps a different ACL type and each reaches a
# different branch of clearACL and listXattr. Both users because the system
# extended-attribute namespace needs PRIV_VFS_EXTATTR_SYSTEM: the unprivileged
# cell is the one where listXattr skips EPERM, and the root cell is the only
# one where UFS lists an ACL as system.posix1e.* for aclXattrs to leave out.
#
# A skipped test is a FAIL here. The guest tests fail rather than skip when the
# filesystem is not the one named, and a test that went missing from the run
# is a FAIL too, so a renamed test cannot quietly stop being run.
#
# Two more cells run test/e2e/guest on a scratch ZFS dataset created with
# aclmode=passthrough and aclinherit=passthrough, again as the user and as
# root: a named entry inherited from a parent directory survives publication,
# and a published deny entry denies a read made as the principal it names. The
# guest's own datasets carry the defaults, discard and restricted, under which
# neither was ever driven.
#
# This suite mutates freebsd-server: it creates and destroys a swap-backed
# memory disk and a ZFS dataset, and writes under /var/tmp. It checks that
# both are gone.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"

# Preflight gates on the Linux pair only, and nothing here needs it.
E2E_HOST=freebsd-server
if e2e_on freebsd-server true 2>/dev/null; then
	e2e_record FSRV-00 PASS "freebsd-server answers ssh" "reachable" "reachable" "ssh $E2E_FREEBSD_SERVER_HOST true" 0 ""
else
	e2e_record FSRV-00 FAIL "freebsd-server answers ssh" "reachable" "$E2E_ERR" "ssh $E2E_FREEBSD_SERVER_HOST true" "$E2E_RC" "test/e2e/README.md"
	e2e_block FSRV-BLOCK-HOST "internal/storage on FreeBSD" "freebsd-server ($E2E_FREEBSD_SERVER_HOST) is unreachable; power it on"
	return 0
fi

# Off /tmp, which on these guests is its own dataset: the ZFS cell has to land
# on the filesystem it names, and the Go test refuses one that is not ZFS.
FSRV_ROOT="${E2E_FREEBSD_STORAGE_ROOT:-/var/tmp/bodega-e2e-storage}"
FSRV_MD="${E2E_FREEBSD_MD_UNIT:-48}"
FSRV_BIN="$REPO_ROOT/dist/storage-freebsd-arm64.test"
FSRV_GUEST_BIN="$REPO_ROOT/dist/guest-freebsd-arm64.test"

# Order is the check id: FSRV-<FS>-<WHO>-01 is the first name here.
FSRV_TESTS=(
	TestFreeBSDGuestStructACLMatchesSysACLH
	TestFreeBSDGuestKernelTakesTheStructACLThisPackageBuilds
	TestFreeBSDGuestClearACLToleratesEINVALOnlyWhereNoPOSIX1eIsKept
	TestFreeBSDGuestRestrictStagedLeavesNoNamedEntry
	TestFreeBSDGuestExtattrListIsLengthPrefixedAndUnqualified
	TestFreeBSDGuestListXattrLeavesTheACLToTheACLCalls
	TestLocalPublishKeepsTheAccessACLOfTheObjectItReplaces
	TestLocalPublishDropsAnACLTheObjectNeverHad
)
FSRV_PT_TESTS=(
	TestZFSPassthroughPublishKeepsANamedInheritedEntry
	TestZFSPassthroughPublishedDenyEntryDeniesItsPrincipal
)

# ---- ship ------------------------------------------------------------------
#
# The test binary rather than a bodega binary: what runs here is the package's
# own assertions against unexported functions, which no CLI command reaches.

E2E_HOST=local
fsrv_build_rc=0
e2e_local rm -f "$FSRV_BIN" || fsrv_build_rc=$E2E_RC
e2e_local env GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 \
	go test -C "$REPO_ROOT" -c -o "$FSRV_BIN" ./internal/storage || fsrv_build_rc=$E2E_RC
check_eq FSRV-01 "the internal/storage test binary builds for freebsd/arm64" 0 "$fsrv_build_rc" \
	"internal/storage/guest_freebsd_test.go" "GOOS=freebsd GOARCH=arm64 go test -c ./internal/storage" "$fsrv_build_rc"
fsrv_guest_rc=0
e2e_local rm -f "$FSRV_GUEST_BIN" || fsrv_guest_rc=$E2E_RC
e2e_local env GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 \
	go test -C "$REPO_ROOT" -c -o "$FSRV_GUEST_BIN" ./test/e2e/guest || fsrv_guest_rc=$E2E_RC
check_eq FSRV-06 "the test/e2e/guest test binary builds for freebsd/arm64" 0 "$fsrv_guest_rc" \
	"test/e2e/guest/publish_freebsd_test.go" "GOOS=freebsd GOARCH=arm64 go test -c ./test/e2e/guest" "$fsrv_guest_rc"
fsrv_build_rc=$((fsrv_build_rc + fsrv_guest_rc))
# A binary left by an earlier build would run the code as it was then, and
# every cell below would grade that instead of this tree. A dry run built
# nothing and deleted nothing, so there is no binary to hold it to.
if [ "${E2E_DRY_RUN:-no}" != yes ] && { [ "$fsrv_build_rc" -ne 0 ] || [ ! -x "$FSRV_BIN" ] || [ ! -x "$FSRV_GUEST_BIN" ]; }; then
	e2e_block FSRV-BLOCK-BUILD "internal/storage on FreeBSD" "a freebsd/arm64 test binary did not build: $(e2e_excerpt "$E2E_ERR")"
	return 0
fi

# The passthrough dataset is a child of whichever dataset holds the storage
# root's parent, so no pool name is assumed. Its name is fixed rather than
# configurable because the teardown destroys it.
E2E_HOST=freebsd-server
e2e_on freebsd-server "zfs list -H -o name '${FSRV_ROOT%/*}'" || true
FSRV_PT_DATASET="$E2E_OUT/bodega-e2e-passthrough"
FSRV_PT_MNT="$FSRV_ROOT/zfspt"

# A memory disk or dataset left by a run that died is torn down first, so the
# newfs below formats this run's disk and not a stale mount under it.
e2e_on freebsd-server "sudo zfs destroy -f '$FSRV_PT_DATASET' 2>/dev/null; \
	sudo umount '$FSRV_ROOT/ufs' 2>/dev/null; sudo mdconfig -d -u $FSRV_MD 2>/dev/null; \
	sudo rm -rf '$FSRV_ROOT' && sudo mkdir -p '$FSRV_ROOT/zfs' '$FSRV_ROOT/ufs' && \
	sudo mdconfig -a -t swap -s 64m -u $FSRV_MD && sudo newfs -U /dev/md$FSRV_MD >/dev/null && \
	sudo mount -o acls /dev/md$FSRV_MD '$FSRV_ROOT/ufs' && \
	sudo chown \"\$(id -un)\" '$FSRV_ROOT' '$FSRV_ROOT/zfs' '$FSRV_ROOT/ufs' && \
	mount -p | awk -v m='$FSRV_ROOT/ufs' '\$2 == m {print \$3, \$4}'" || true
check_eq FSRV-02 "a UFS memory disk is mounted with POSIX.1e ACLs" "ufs rw,acls" "$E2E_OUT" \
	"test/e2e/suites/48-freebsd-server.sh" "mdconfig -a -t swap; newfs -U; mount -o acls" "$E2E_RC"

e2e_on freebsd-server "sudo zfs create -o aclmode=passthrough -o aclinherit=passthrough \
	-o mountpoint='$FSRV_PT_MNT' '$FSRV_PT_DATASET' && sudo chown \"\$(id -un)\" '$FSRV_PT_MNT' && \
	zfs get -H -o value aclmode,aclinherit,mountpoint '$FSRV_PT_DATASET' | paste -sd ' ' -" || true
check_eq FSRV-07 "a scratch ZFS dataset is mounted with aclmode and aclinherit passthrough" \
	"passthrough passthrough $FSRV_PT_MNT" "$E2E_OUT" \
	"test/e2e/suites/48-freebsd-server.sh" "zfs create -o aclmode=passthrough -o aclinherit=passthrough $FSRV_PT_DATASET" "$E2E_RC"

if e2e_put freebsd-server "$FSRV_BIN" /tmp/bodega-storage.test &&
	e2e_put freebsd-server "$FSRV_GUEST_BIN" /tmp/bodega-guest.test &&
	e2e_on freebsd-server "install -m 0755 /tmp/bodega-storage.test '$FSRV_ROOT/storage.test' && \
		install -m 0755 /tmp/bodega-guest.test '$FSRV_ROOT/guest.test' && rm -f /tmp/bodega-storage.test /tmp/bodega-guest.test"; then
	e2e_record FSRV-03 PASS "freebsd-server takes the test binaries" "installed" "installed" "install $FSRV_ROOT/storage.test $FSRV_ROOT/guest.test" 0 ""
else
	e2e_record FSRV-03 FAIL "freebsd-server takes the test binaries" "installed" "$E2E_ERR" "install $FSRV_ROOT/storage.test $FSRV_ROOT/guest.test" "$E2E_RC" ""
fi

# The unprivileged cell is only unprivileged if the ssh user is not root.
e2e_on freebsd-server "id -u" || true
check_ne FSRV-04 "the unprivileged cell runs as a user other than root" "0" "${E2E_OUT:-unknown}" \
	"test/e2e/suites/48-freebsd-server.sh" "id -u" "$E2E_RC"

# ---- the cells -------------------------------------------------------------

# fsrv_cell <cell> <who> <binary> <TMPDIR> <env> <test...> runs one binary once
# and grades each named test from its -test.v output.
fsrv_cell() {
	local cell="$1" who="$2" bin="$3" tmp="$4" env="$5"
	shift 5
	local tests=("$@") sudo="" run out rc n=0 t id title cmd ref verdict
	[ "$who" = root ] && sudo="sudo"
	run="^($(
		IFS='|'
		printf '%s' "${tests[*]}"
	))\$"
	e2e_on freebsd-server "cd '$FSRV_ROOT' && $sudo env TMPDIR='$tmp' $env \
		./$bin -test.run '$run' -test.v 2>&1" || true
	out="$E2E_OUT"
	rc="$E2E_RC"
	for t in "${tests[@]}"; do
		n=$((n + 1))
		id="$(printf 'FSRV-%s-%s-%02d' "${cell^^}" "${who^^}" "$n")"
		title="$t on $cell as $who"
		cmd="TMPDIR=$tmp $env $bin -test.run ^$t\$ -test.v"
		ref="internal/storage/guest_freebsd_test.go"
		case "$t" in
		TestLocalPublish*) ref="internal/storage/local_test.go" ;;
		TestZFSPassthrough*) ref="test/e2e/guest/publish_freebsd_test.go" ;;
		esac
		verdict="$(printf '%s\n' "$out" | awk -v t="$t" '$1 == "---" && $3 == t {print $2; exit}')"
		case "$verdict" in
		PASS:)
			e2e_record "$id" PASS "$title" "PASS" "PASS" "$cmd" "$rc" "$ref"
			;;
		SKIP:)
			e2e_record "$id" FAIL "$title" "PASS" "skipped: $(e2e_excerpt "$out")" "$cmd" "$rc" \
				"$ref; a skip is the silence that left these syscalls unexercised"
			;;
		*)
			e2e_record "$id" FAIL "$title" "PASS" "${verdict:-not run}: $(e2e_excerpt "$out")" "$cmd" "$rc" "$ref"
			;;
		esac
	done
}

for fs in zfs ufs; do
	for who in user root; do
		fsrv_cell "$fs" "$who" storage.test "$FSRV_ROOT/$fs" "BODEGA_FREEBSD_GUEST_FS=$fs" "${FSRV_TESTS[@]}"
	done
done
for who in user root; do
	fsrv_cell zfspt "$who" guest.test "$FSRV_PT_MNT" "BODEGA_FREEBSD_GUEST_ZFS_ACL=passthrough/passthrough" "${FSRV_PT_TESTS[@]}"
done
unset fs who
unset -f fsrv_cell

# ---- restore ---------------------------------------------------------------

E2E_HOST=freebsd-server
e2e_on freebsd-server "sudo zfs destroy '$FSRV_PT_DATASET'; zfs list -H -o name '$FSRV_PT_DATASET' 2>/dev/null || echo gone" || true
check_eq FSRV-08 "the passthrough dataset is destroyed again" "gone" "$E2E_OUT" \
	"test/e2e/suites/48-freebsd-server.sh" "zfs destroy $FSRV_PT_DATASET" "$E2E_RC"
e2e_on freebsd-server "sudo umount '$FSRV_ROOT/ufs'; sudo mdconfig -d -u $FSRV_MD; sudo rm -rf '$FSRV_ROOT'; \
	sudo mdconfig -l | awk -v u=md$FSRV_MD '{for (i = 1; i <= NF; i++) if (\$i == u) f = 1} END {print (f ? \"present\" : \"gone\")}'" || true
check_eq FSRV-05 "the memory disk is destroyed again" "gone" "$E2E_OUT" \
	"test/e2e/suites/48-freebsd-server.sh" "umount; mdconfig -d -u $FSRV_MD; mdconfig -l" "$E2E_RC"

unset FSRV_ROOT FSRV_MD FSRV_BIN FSRV_GUEST_BIN FSRV_TESTS FSRV_PT_TESTS FSRV_PT_DATASET FSRV_PT_MNT fsrv_build_rc fsrv_guest_rc
