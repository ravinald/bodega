# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Proxy and cache, against live upstreams. A miss reaches out, stores what it
# got, and the next request is served locally.
#
# The second request is the whole point and the easiest thing to fake: a check
# that only asserts 200 twice passes against a server that proxies every time
# and caches nothing. Each type here is measured by the object appearing in
# storage, not by the response code.
#
# The switch off is the other half. With proxy_cache_enabled false, npm and
# gomod refuse an uncatalogued name rather than reaching out, cargo's crate
# download still forces past the switch, and the two namespaced upstream maps
# change what their own routes answer. Every posture set here is put back, and
# each restore is asserted rather than assumed.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block PXY-BLOCK "proxy and cache" "a guest is unreachable"
	return 0
fi

E2E_HOST=server
e2e_config_set server '.proxy_cache_enabled = true | .metadata_ttl = "1h"' || true
e2e_restart server || true
check_eq PXY-01 "the server restarts with proxy caching on" 0 "$E2E_RC" \
	"internal/server/proxy.go:281" "systemctl restart bodega" "$E2E_RC"

# A package no manifest names, so the request can only be answered upstream.
# Using a hosted entry would pass against a server with the proxy switched off.
e2e_on server "sudo rm -rf /var/lib/bodega/npm/is-number /var/lib/bodega/cargo/index /var/lib/bodega/gomod/github.com/pkg; true" || true

# ---- miss, store, hit ------------------------------------------------------

# npm: a tiny package with no dependencies.
E2E_HOST=client
e2e_http client "/npm/is-number" || true
check_eq PXY-NPM-01 "an npm packument missing locally is answered upstream" "200" "$E2E_OUT" \
	"internal/server/npm.go:99" "GET /npm/is-number"

E2E_HOST=server
e2e_on server "sudo find /var/lib/bodega/npm/is-number -type f 2>/dev/null | head -3" || true
check_contains PXY-NPM-02 "the proxied npm packument is written to storage" \
	"is-number" "${E2E_OUT:-nothing stored}" "internal/server/proxy.go:59" "find /var/lib/bodega/npm/is-number"

# The tarball the packument above published. bodega rewrites every dist.tarball
# onto its own /npm route, so this is the URL an `npm install` follows next and
# the one that used to 404: a client resolved through bodega and then failed on
# an address bodega named. The version is pinned rather than read back out of
# the packument, because a shell that parses JSON to build the next request
# fails as a parse error rather than as the route.
E2E_HOST=client
e2e_http client "/npm/is-number/-/is-number-7.0.0.tgz" || true
check_eq PXY-NPM-03 "the tarball the packument published is served" "200" "$E2E_OUT" \
	"internal/server/npm.go:82" "GET /npm/is-number/-/is-number-7.0.0.tgz"

E2E_HOST=server
e2e_on server "sudo find /var/lib/bodega/npm/is-number -name '*.tgz' -type f 2>/dev/null | head -3" || true
check_contains PXY-NPM-04 "the proxied npm tarball is written to storage" \
	".tgz" "${E2E_OUT:-nothing stored}" "internal/server/proxy.go:59" "find /var/lib/bodega/npm/is-number -name '*.tgz'"

# helm is the route that cannot be opened: a chart repository URL is recorded
# per version entry, so an uncatalogued chart names no host to fetch from. What
# it owes an operator is the reason, not a bare 404 that reads as the chart not
# existing upstream.
E2E_HOST=client
e2e_body client "/helm/charts/ingress-nginx-4.0.0.tgz" || true
check_contains PXY-HELM-01 "an uncatalogued chart is refused by name, with the command that fixes it" \
	"bodega pkg create helm ingress-nginx" "${E2E_OUT:-no body}" \
	"internal/server/helm.go:99" "GET /helm/charts/ingress-nginx-4.0.0.tgz"

# pypi is helm's twin through the same proxyVersionOrRefuse: a wheel URL is read
# out of the simple index rather than composed, so an uncatalogued distribution
# names nothing to fetch. The hint is what is measured, not the status — a bare
# 404 and a reason-bearing refusal are the same status code, and the bare one
# reads as "no such wheel upstream", which is a different problem.
E2E_HOST=client
e2e_body client "/pypi/wheels/requests-2.31.0-py3-none-any.whl" || true
check_contains PXY-PYPI-01 "an uncatalogued wheel is refused by name, with the command that fixes it" \
	"bodega pkg create pypi requests" "${E2E_OUT:-no body}" \
	"internal/server/pypi.go:258" "GET /pypi/wheels/requests-2.31.0-py3-none-any.whl"

# cargo: the sparse index entry for a crate nothing hosts.
E2E_HOST=client
e2e_http client "/cargo/an/yh/anyhow" || true
check_eq PXY-CARGO-01 "a cargo index entry missing locally is answered upstream" "200" "$E2E_OUT" \
	"internal/server/cargo.go:82" "GET /cargo/an/yh/anyhow"

E2E_HOST=server
e2e_on server "sudo find /var/lib/bodega/cargo/index -type f 2>/dev/null | head -3" || true
check_contains PXY-CARGO-02 "the proxied cargo index entry is written to storage" \
	"anyhow" "${E2E_OUT:-nothing stored}" "internal/server/proxy.go:59" "find /var/lib/bodega/cargo/index"

# gomod: a module nothing hosts. npm and cargo above answer the same shape from
# upstream, so a 404 here is a difference between types rather than the proxy
# being off, and README.md advertises the cache for gomod alongside them.
E2E_HOST=client
e2e_http client "/go/github.com/pkg/errors/@v/list" || true
check_eq PXY-GOMOD-01 "a gomod list missing locally is answered upstream" "200" "$E2E_OUT" \
	"internal/server/gomod.go:25" "GET /go/github.com/pkg/errors/@v/list"

# ---- the hit is served without reaching out --------------------------------
#
# Measured by the audit trail, which records a cache row per outcome. Timing
# would be the obvious alternative and is not evidence: a fast upstream and a
# local read are the same number of milliseconds apart as noise.

E2E_HOST=server
e2e_bodega server "audit events --type cache --limit 50" || true
check_contains PXY-02 "cache rows are recorded for the proxied fetches" \
	"cache" "$E2E_OUT" "internal/server/audit.go:92" "bodega audit events --type cache"

# Named separately so the report distinguishes "the filter found nothing" from
# "the type is never written". A trail that records serve_fetch and denied but
# no cache row cannot answer which artifacts came from upstream.
e2e_bodega server "audit events --limit 400" || true
check_contains PXY-02b "the trail carries at least one cache event of any kind" \
	"cache" "$E2E_OUT" "internal/server/audit.go:92" "bodega audit events --limit 400"

# The hit itself. Everything above is a miss, so a server that recorded misses
# and nothing else passed both checks — which is how "a cache row per outcome"
# read as satisfied while the hit path wrote nothing. The listing was fetched
# above and metadata_ttl is an hour, so this second request is served locally.
#
# The upstream the row credits is not visible here: `audit events` prints no
# details column. internal/server/proxy_audit_test.go asserts on the blob.
E2E_HOST=client
e2e_http client "/go/github.com/pkg/errors/@v/list" || true
check_eq PXY-02c-serve "the cached gomod list is served again" "200" "$E2E_OUT" \
	"internal/server/proxy.go:104" "GET /go/github.com/pkg/errors/@v/list (cached)"

E2E_HOST=server
e2e_bodega server "audit events --type cache --limit 50" || true
check_contains PXY-02c "a request the cache answered is recorded as a hit" \
	"cache_hit" "$E2E_OUT" "internal/server/proxy.go:104" "bodega audit events --type cache"

# ---- the spool caps --------------------------------------------------------
#
# A declared Content-Length over the artifact cap is refused before a byte
# moves. Set the cap absurdly low and any upstream artifact exceeds it.
#
# A gomod .zip, not an npm tarball. The npm tarball above is cached by now, and
# a request the cache answers opens no spool at all, so the probe would measure
# nothing again — for a second reason, after B58 found it measuring a route 404.
# The module below is uncatalogued and its .zip is removed first, so the request
# is a miss that reaches the spool.

e2e_config_set server '.spool_max_artifact_bytes = 1024' || true
e2e_restart server || true
E2E_HOST=server
e2e_on server "sudo rm -rf /var/lib/bodega/gomod/github.com/pkg; true" || true
E2E_HOST=client
e2e_http client "/go/github.com/pkg/errors/@v/v0.9.1.zip" || true
check_ne PXY-03 "an artifact over the spool cap is not served" "200" "$E2E_OUT" \
	"internal/server/audit.go:140" "GET an artifact larger than spool_max_artifact_bytes"

E2E_HOST=server
e2e_bodega server "audit events --type denied --limit 20" || true
check_contains PXY-04 "the spool refusal is recorded with a reason" \
	"spool" "$E2E_OUT" "internal/server/audit.go:140" "bodega audit events --type denied"

# ---- catalog mode ----------------------------------------------------------
#
# The default for a namespace is catalog: only paths an existing manifest entry
# names resolve. `open` composes an upstream URL for anything under the
# namespace, which on a public forge lets any client make bodega fetch
# arbitrary repositories.
#
# The spool cap rides along on this write. It is restored in the same jq program
# because each restart spends one of systemd's five starts per ten seconds, and
# the restore is measured below either way.

e2e_config_set server '.spool_max_artifact_bytes = 8589934592 | .git_upstreams = {"e2ecat": {"url": "https://github.com/", "mode": "catalog"}}' || true
e2e_restart server || true

# The cap proven restored, not assumed: the same artifact PXY-03 refused. A
# suite that left every artifact over 1 KiB refused would hand the rest of the
# run failures naming the wrong cause.
E2E_HOST=client
e2e_http client "/go/github.com/pkg/errors/@v/v0.9.1.zip" || true
check_eq PXY-04b "the artifact the spool cap refused is served once the cap is restored" "200" "$E2E_OUT" \
	"internal/server/audit.go:140" "GET the same artifact with spool_max_artifact_bytes restored"

e2e_http client "/git/e2ecat/google/uuid.git/info/refs?service=git-upload-pack" || true
check_ne PXY-05 "catalog mode refuses a path no manifest names" "200" "$E2E_OUT" \
	"internal/config/config.go:248" "GET an uncatalogued path under a catalog namespace"

E2E_HOST=server
e2e_bodega server "discover list" || true
check_eq PXY-06 "the refused path is available to discover" 0 "$E2E_RC" \
	"cmd/bodega/cmd_discover.go:61" "bodega discover list" "$E2E_RC"

# open mode is the other half, and the posture the config comment warns about:
# the URL is composed for any path under the namespace, so the request catalog
# refused above resolves. One key differs between the two checks.
E2E_HOST=server
e2e_config_set server '.git_upstreams = {"e2eopen": {"url": "https://github.com/", "mode": "open"}}' || true
e2e_restart server || true
E2E_HOST=client
e2e_http client "/git/e2eopen/google/uuid.git/info/refs?service=git-upload-pack" || true
check_eq PXY-05b "open mode serves a path no manifest names" "200" "$E2E_OUT" \
	"internal/config/config.go:270" "GET an uncatalogued path under an open namespace"

# Emptied here rather than left to the block below, and asserted by the request
# rather than by the restart: leaving an open proxy configured is the one damage
# this posture can do, and a restart that succeeded says nothing about which
# namespaces came back with it. The binary_upstreams entry the next block needs
# rides the same write, for the restart budget the catalog block explains.
E2E_HOST=server
e2e_config_set server '.git_upstreams = {} | .binary_upstreams = {"e2ebin": {"url": "https://example.com/", "mode": "catalog"}}' || true
e2e_restart server || true
E2E_HOST=client
e2e_http client "/git/e2eopen/google/uuid.git/info/refs?service=git-upload-pack" || true
check_ne PXY-05c "the open namespace is gone once git_upstreams is emptied" "200" "$E2E_OUT" \
	"internal/server/git.go:72" "GET the same path with git_upstreams empty"

# ---- binary_upstreams turns the storage read off ---------------------------
#
# While the map is empty, /binaries/{path...} reads storage as it always has.
# Once any entry exists, a request whose first segment names no key 404s as
# no_namespace instead of falling through — including a path that resolved a
# moment ago, which is what SRV-ART-binary asserts in 40-serve-hosted.sh.
# Asserted in both directions: a check that only saw the 404 could not tell the
# switch from a fixture that had gone missing, and the other direction is PXY-09
# under the restore. The e2ebin upstream set above is never reached, because the
# request names a different first segment.

E2E_HOST=client
e2e_http client "/binaries/hello-binary/1.0.0/LICENSE" || true
check_eq PXY-08 "one binary_upstreams entry 404s a path that served from storage" "404" "$E2E_OUT" \
	"internal/server/binary.go:38" "GET /binaries/hello-binary/1.0.0/LICENSE with a namespace configured"

# ---- restore ---------------------------------------------------------------
#
# Back to the hosted-only posture the rest of the run expects. A suite that
# left the proxy on would let a later "hosted" check pass on an upstream fetch.
# Both upstream maps are emptied here too: either one left set would answer a
# later hosted check out of a namespace this suite invented.

E2E_HOST=server
e2e_config_set server '.git_upstreams = {} | .binary_upstreams = {} | .proxy_cache_enabled = false | .metadata_ttl = "1h"' || true
e2e_restart server || true
check_eq PXY-07 "the server returns to the hosted-only posture" 0 "$E2E_RC" \
	"internal/server/proxy.go:281" "systemctl restart bodega" "$E2E_RC"

E2E_HOST=client
e2e_http client "/binaries/hello-binary/1.0.0/LICENSE" || true
check_eq PXY-09 "emptying binary_upstreams restores the storage read" "200" "$E2E_OUT" \
	"internal/server/binary.go:57" "GET /binaries/hello-binary/1.0.0/LICENSE with binary_upstreams empty"

# ---- the switch off --------------------------------------------------------
#
# The same two paths PXY-NPM-01 and PXY-GOMOD-01 answered from upstream, with
# proxy_cache_enabled false and nothing else changed, so the pair differs in one
# variable. The stored copies go first: a cached object is served whether the
# switch is on or off, so without the removal these checks measure the cache and
# pass against a server that still reaches out.

E2E_HOST=server
e2e_on server "sudo rm -rf /var/lib/bodega/npm/is-number /var/lib/bodega/gomod/github.com/pkg /var/lib/bodega/cargo/crates/anyhow-1.0.86.crate; true" || true

E2E_HOST=client
e2e_http client "/npm/is-number" || true
check_eq PXY-10 "an uncatalogued npm packument is refused with caching off" "404" "$E2E_OUT" \
	"internal/server/npm.go:154" "GET /npm/is-number with proxy_cache_enabled false"

e2e_http client "/go/github.com/pkg/errors/@v/list" || true
check_eq PXY-11 "an uncatalogued gomod list is refused with caching off" "404" "$E2E_OUT" \
	"internal/server/gomod.go:103" "GET /go/github.com/pkg/errors/@v/list with proxy_cache_enabled false"

# cargo does not refuse, and the asymmetry is intended: the crate download
# forces past the cache switch because the sparse index bodega serves publishes
# that URL, so refusing it would 404 an address bodega itself handed the client.
# npm and gomod publish nothing for an uncatalogued name with the switch off,
# which is why they refuse instead. The index route is PXY-CARGO-01's; this is
# the download.
e2e_http client "/cargo/anyhow/1.0.86/download" || true
check_eq PXY-12 "an uncatalogued cargo crate download proxies with caching off" "200" "$E2E_OUT" \
	"internal/server/cargo.go:353" "GET /cargo/anyhow/1.0.86/download with proxy_cache_enabled false"
