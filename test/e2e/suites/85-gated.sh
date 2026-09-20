# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The Go test harnesses CI never runs. Five of them sit behind environment
# variables and one behind a build tag, and every one exists because the thing
# it measures has no macOS equivalent and no reproduction on a two-core runner:
# flock, systemd, GNU stat, SQLite write-lock contention under -race.
#
# This is the only suite that needs a toolchain, so it runs on the server guest,
# which carries one for exactly this reason.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block GAT-BLOCK "the gated Go suites" "the server guest is unreachable"
	return 0
fi

E2E_HOST=server
GO=/usr/local/go/bin/go
# An absolute path, not ~: the tilde expands on the workstation before the
# command is sent, so the guest was told to mkdir a path under this machine's
# home and answered "Permission denied".
#
# /var/tmp rather than /tmp because both guests mount a 1.7G tmpfs there against
# ~20G free on /. Linking the internal/server test binary overruns it, and the
# compiler reports that as `disk quota exceeded`, which every check below then
# files as a product defect. $E2E_GATED_ROOT moves the whole tree.
#
# The two subdirectories are what GAT-02 removes, never $GATED_ROOT itself: the
# override is an environment variable, and `rm -rf` on one of those is how a
# harness deletes a home directory.
GATED_ROOT="${E2E_GATED_ROOT:-/var/tmp/bodega-e2e-gated}"
WORK="$GATED_ROOT/tree"
# t.TempDir() resolves through TMPDIR, so the scratch the tests write has to
# move with the build: internal/policy/osvlive_test.go unpacks the OSV archives
# through it and internal/server/sink_load_test.go writes its spool there.
GOTMP="$GATED_ROOT/tmp"

e2e_on server "test -x $GO" || true
if [ "$E2E_RC" -ne 0 ]; then
	e2e_skip GAT-00 "the gated Go suites" "no Go toolchain at $GO on the server guest"
	return 0
fi

# git archive rather than a clone: it carries the working tree at one commit
# with no .git, so the guest cannot push and there is no second checkout to
# keep in sync.
E2E_HOST=local
# --output rather than a shell redirect: e2e_local runs the command directly,
# so a `>` in the argument list is an argument, not a redirection.
e2e_local git -C "$REPO_ROOT" archive --format=tar --output=/tmp/e2e-tree.tar HEAD || true
check_eq GAT-01 "the tree archives at HEAD" 0 "$E2E_RC" \
	"test/e2e/README.md" "git archive --format=tar HEAD" "$E2E_RC"

e2e_put server /tmp/e2e-tree.tar /tmp/e2e-tree.tar || true
E2E_HOST=server
e2e_on server "rm -rf $WORK $GOTMP && mkdir -p $WORK $GOTMP && tar -xf /tmp/e2e-tree.tar -C $WORK && test -f $WORK/go.mod" || true
check_eq GAT-02 "the tree unpacks on the server guest" 0 "$E2E_RC" \
	"test/e2e/README.md" "tar -xf /tmp/e2e-tree.tar -C $WORK" "$E2E_RC"

# Everything below compiles that tree. Without it they would each report a
# compiler error as a test failure, and the report would name seven defects
# where there is one broken prerequisite.
if [ "$E2E_RC" -ne 0 ]; then
	for id in GAT-05 GAT-06 GAT-07 GAT-08 GAT-09 GAT-10 GAT-11; do
		e2e_block "$id" "a gated Go suite" "the tree did not unpack on the server guest (GAT-02)"
	done
	unset GO GATED_ROOT WORK GOTMP id
	return 0
fi

# ---- the test that read the installed config -------------------------------
#
# #320 named two tests. The ACL half already puts BODEGA_CONFIG_FILE in force;
# this one resolved through /etc/bodega/config.json, which is root-owned on both
# guests, so it took a permission error a bare CI runner never sees.

E2E_SSH_TIMEOUT=900 e2e_on server "cd $WORK && TMPDIR=$GOTMP $GO test -count=1 -run 'TestJSONEditPopupEscClears' ./internal/tui/ 2>&1 | tail -20" || true
check_eq GAT-05 "TestJSONEditPopupEscClears passes on a host that has bodega installed" \
	0 "$E2E_RC" "test/e2e/README.md" "go test -run TestJSONEditPopupEscClears ./internal/tui/" "$E2E_RC"

# ---- contention under the runner's shape -----------------------------------
#
# Reproducing a contention flake wants the runner's shape, not the guest's:
# GitHub gives two cores and this guest has sixteen. Running the whole package
# rather than one subtest is what supplies the load.

E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && TMPDIR=$GOTMP GOMAXPROCS=2 taskset -c 0,1 $GO test -race -count=1 ./internal/audit/ 2>&1 | tail -20" || true
check_eq GAT-06 "the audit package passes under -race on two cores" 0 "$E2E_RC" \
	"docs/design.md:618" "GOMAXPROCS=2 taskset -c 0,1 go test -race ./internal/audit/" "$E2E_RC"

E2E_SSH_TIMEOUT=2400 e2e_on server "cd $WORK && TMPDIR=$GOTMP GOMAXPROCS=2 taskset -c 0,1 $GO test -race -count=1 ./internal/server/ 2>&1 | tail -20" || true
check_eq GAT-07 "the server package passes under -race on two cores" 0 "$E2E_RC" \
	"docs/design.md:641" "GOMAXPROCS=2 taskset -c 0,1 go test -race ./internal/server/" "$E2E_RC"

# ---- the env-gated harnesses ----------------------------------------------

E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && TMPDIR=$GOTMP BODEGA_SINK_LOAD=1 $GO test -count=1 -run 'SinkLoad' ./internal/server/ 2>&1 | tail -25" || true
check_eq GAT-08 "the audit sink load harness runs" 0 "$E2E_RC" \
	"internal/server/sink_load_test.go:38" "BODEGA_SINK_LOAD=1 go test -run SinkLoad ./internal/server/" "$E2E_RC"

E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && TMPDIR=$GOTMP BODEGA_PROXY_RSS=1 $GO test -count=1 -run 'TestProxyPeakRSS' ./internal/server/ 2>&1 | tail -25" || true
check_eq GAT-09 "the proxy RSS harness runs" 0 "$E2E_RC" \
	"internal/server/proxy_rss_test.go:49" "BODEGA_PROXY_RSS=1 go test -run TestProxyPeakRSS ./internal/server/" "$E2E_RC"

E2E_SSH_TIMEOUT=2400 e2e_on server "cd $WORK && TMPDIR=$GOTMP BODEGA_OSV_LIVE=1 $GO test -count=1 ./internal/policy/ 2>&1 | tail -25" || true
check_eq GAT-10 "the live OSV comparison runs against api.osv.dev" 0 "$E2E_RC" \
	"internal/policy/osvlive_test.go:21" "BODEGA_OSV_LIVE=1 go test ./internal/policy/" "$E2E_RC"

# ---- the containerized apt harness ----------------------------------------
#
# `make test-apt` is the only assertion of what a real apt does with a filtered
# index, rather than what the index says. It needs a container runtime, and
# neither guest has one: the skip is the finding.

e2e_on server "command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1" || true
if [ "$E2E_RC" -eq 0 ]; then
	E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && TMPDIR=$GOTMP $GO test -tags apt_integration -count=1 -timeout 20m -run TestRealApt ./internal/server/ 2>&1 | tail -25" || true
	check_eq GAT-11 "the real-apt integration test passes" 0 "$E2E_RC" \
		"Makefile:183" "go test -tags apt_integration -run TestRealApt ./internal/server/" "$E2E_RC"
else
	e2e_skip GAT-11 "the real-apt integration test passes" \
		"no container runtime on the server guest, so make test-apt has never run here" \
		"Makefile:183"
fi

unset GO GATED_ROOT WORK GOTMP
