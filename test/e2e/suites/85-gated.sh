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
WORK=~/bodega-e2e-work

e2e_on server "test -x $GO" || true
if [ "$E2E_RC" -ne 0 ]; then
	e2e_skip GAT-00 "the gated Go suites" "no Go toolchain at $GO on the server guest"
	return 0
fi

# git archive rather than a clone: it carries the working tree at one commit
# with no .git, so the guest cannot push and there is no second checkout to
# keep in sync.
E2E_HOST=local
e2e_local sh -c "git -C '$REPO_ROOT' archive --format=tar HEAD > /tmp/e2e-tree.tar" || true
check_eq GAT-01 "the tree archives at HEAD" 0 "$E2E_RC" \
	"docs-internal/DEV_HOSTS.md" "git archive --format=tar HEAD" "$E2E_RC"

e2e_put server /tmp/e2e-tree.tar /tmp/e2e-tree.tar || true
E2E_HOST=server
e2e_on server "rm -rf $WORK && mkdir -p $WORK && tar -xf /tmp/e2e-tree.tar -C $WORK && test -f $WORK/go.mod" || true
check_eq GAT-02 "the tree unpacks on the server guest" 0 "$E2E_RC" \
	"docs-internal/DEV_HOSTS.md" "tar -xf /tmp/e2e-tree.tar -C $WORK" "$E2E_RC"

# ---- the two tests that fail on a host with bodega installed ---------------
#
# #320: both read /etc/bodega/config.json and /var/lib/bodega/manifests instead
# of a temp directory. Both guests have those paths and both are root-owned, so
# the tests take a permission error that a bare CI runner never sees. Mapped in
# known-issues.tsv, so this reports XFAIL until the issue closes and XPASS the
# moment it does.

E2E_SSH_TIMEOUT=900 e2e_on server "cd $WORK && $GO test -count=1 -run 'TestJSONEditPopupEscClears' ./internal/tui/ 2>&1 | tail -20" || true
check_eq GAT-05 "the TUI and ACL tests pass on a host that has bodega installed" \
	0 "$E2E_RC" "docs-internal/DEV_HOSTS.md" "go test -run TestJSONEditPopupEscClears ./internal/tui/" "$E2E_RC"

# ---- contention under the runner's shape -----------------------------------
#
# Reproducing a contention flake wants the runner's shape, not the guest's:
# GitHub gives two cores and this guest has sixteen. Running the whole package
# rather than one subtest is what supplies the load.

E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && GOMAXPROCS=2 taskset -c 0,1 $GO test -race -count=1 ./internal/audit/ 2>&1 | tail -20" || true
check_eq GAT-06 "the audit package passes under -race on two cores" 0 "$E2E_RC" \
	"docs/DESIGN.md:618" "GOMAXPROCS=2 taskset -c 0,1 go test -race ./internal/audit/" "$E2E_RC"

E2E_SSH_TIMEOUT=2400 e2e_on server "cd $WORK && GOMAXPROCS=2 taskset -c 0,1 $GO test -race -count=1 ./internal/server/ 2>&1 | tail -20" || true
check_eq GAT-07 "the server package passes under -race on two cores" 0 "$E2E_RC" \
	"docs/DESIGN.md:641" "GOMAXPROCS=2 taskset -c 0,1 go test -race ./internal/server/" "$E2E_RC"

# ---- the env-gated harnesses ----------------------------------------------

E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && BODEGA_SINK_LOAD=1 $GO test -count=1 -run 'SinkLoad' ./internal/server/ 2>&1 | tail -25" || true
check_eq GAT-08 "the audit sink load harness runs" 0 "$E2E_RC" \
	"internal/server/sink_load_test.go:38" "BODEGA_SINK_LOAD=1 go test -run SinkLoad ./internal/server/" "$E2E_RC"

E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && BODEGA_PROXY_RSS=1 $GO test -count=1 -run 'ProxyRSS' ./internal/server/ 2>&1 | tail -25" || true
check_eq GAT-09 "the proxy RSS harness runs" 0 "$E2E_RC" \
	"internal/server/proxy_rss_test.go:50" "BODEGA_PROXY_RSS=1 go test -run ProxyRSS ./internal/server/" "$E2E_RC"

E2E_SSH_TIMEOUT=2400 e2e_on server "cd $WORK && BODEGA_OSV_LIVE=1 $GO test -count=1 ./internal/policy/ 2>&1 | tail -25" || true
check_eq GAT-10 "the live OSV comparison runs against api.osv.dev" 0 "$E2E_RC" \
	"internal/policy/osvlive_test.go:21" "BODEGA_OSV_LIVE=1 go test ./internal/policy/" "$E2E_RC"

# ---- the containerized apt harness ----------------------------------------
#
# `make test-apt` is the only assertion of what a real apt does with a filtered
# index, rather than what the index says. It needs a container runtime, and
# neither guest has one: the skip is the finding.

e2e_on server "command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1" || true
if [ "$E2E_RC" -eq 0 ]; then
	E2E_SSH_TIMEOUT=1800 e2e_on server "cd $WORK && $GO test -tags apt_integration -count=1 -timeout 20m -run TestRealApt ./internal/server/ 2>&1 | tail -25" || true
	check_eq GAT-11 "the real-apt integration test passes" 0 "$E2E_RC" \
		"Makefile:183" "go test -tags apt_integration -run TestRealApt ./internal/server/" "$E2E_RC"
else
	e2e_skip GAT-11 "the real-apt integration test passes" \
		"no container runtime on the server guest, so make test-apt has never run here" \
		"Makefile:183"
fi

unset GO WORK
