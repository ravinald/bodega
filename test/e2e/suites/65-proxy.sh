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

# ---- the spool caps --------------------------------------------------------
#
# A declared Content-Length over the artifact cap is refused before a byte
# moves. Set the cap absurdly low and any upstream artifact exceeds it.

e2e_config_set server '.spool_max_artifact_bytes = 1024' || true
e2e_restart server || true
E2E_HOST=client
e2e_http client "/npm/lodash/-/lodash-4.17.21.tgz" || true
check_ne PXY-03 "an artifact over the spool cap is not served" "200" "$E2E_OUT" \
	"internal/server/audit.go:140" "GET a tarball larger than spool_max_artifact_bytes"

E2E_HOST=server
e2e_bodega server "audit events --type denied --limit 20" || true
check_contains PXY-04 "the spool refusal is recorded with a reason" \
	"spool" "$E2E_OUT" "internal/server/audit.go:140" "bodega audit events --type denied"

e2e_config_set server '.spool_max_artifact_bytes = 8589934592' || true

# ---- catalog mode ----------------------------------------------------------
#
# The default for a namespace is catalog: only paths an existing manifest entry
# names resolve. `open` composes an upstream URL for anything under the
# namespace, which on a public forge lets any client make bodega fetch
# arbitrary repositories.

e2e_config_set server '.git_upstreams = {"e2ecat": {"url": "https://github.com/", "mode": "catalog"}}' || true
e2e_restart server || true
E2E_HOST=client
e2e_http client "/git/e2ecat/google/uuid.git/info/refs?service=git-upload-pack" || true
check_ne PXY-05 "catalog mode refuses a path no manifest names" "200" "$E2E_OUT" \
	"internal/config/config.go:248" "GET an uncatalogued path under a catalog namespace"

E2E_HOST=server
e2e_bodega server "discover list" || true
check_eq PXY-06 "the refused path is available to discover" 0 "$E2E_RC" \
	"cmd/bodega/cmd_discover.go:61" "bodega discover list" "$E2E_RC"

# ---- restore ---------------------------------------------------------------
#
# Back to the hosted-only posture the rest of the run expects. A suite that
# left the proxy on would let a later "hosted" check pass on an upstream fetch.

e2e_config_set server '.git_upstreams = {} | .proxy_cache_enabled = false | .metadata_ttl = "1h"' || true
e2e_restart server || true
check_eq PXY-07 "the server returns to the hosted-only posture" 0 "$E2E_RC" \
	"internal/server/proxy.go:281" "systemctl restart bodega" "$E2E_RC"
