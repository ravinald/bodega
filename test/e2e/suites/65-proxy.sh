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
#
# Everything through PXY-12 reaches the serving code through `pm == nil` — no
# manifest names the path. The proxy-mode section at the bottom drives the other
# branch. Both branches answer 200 and both derive the same artifact key, so
# neither separates them on its own: those checks assert the stored key for the
# layout it proves, and read the branch itself off the proxy gate with caching
# off. Each records in its ref what it measured.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"
# shellcheck source=../lib/fixtures.sh
. "${E2E_DIR:?}/lib/fixtures.sh"

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

# ---- proxy mode: an entry a manifest names, served from upstream ------------
#
# Every check above reaches the serving code through `pm == nil`, which means
# "no manifest names this": the URL is composed from config alone. A proxy-mode
# entry takes the other branch: internal/server/npm.go:67 and gomod.go:73 read
# packageMode(pm) == ModeProxy on an entry that exists, and cargo.go:353 folds
# the two into one forceProxy.
#
# The artifact key is not what separates them. All three routes derive it
# before the manifest lookup and from the same inputs (npm.go:39, gomod.go:24,
# cargo.go:352), so both branches write the same string. Asserting it still
# says what a status cannot: the object lands in the hosted layout, keyed by
# name and version, rather than in a slot named after the request path. What
# does separate them is the proxy gate: npm and gomod pass forceProxy true for
# an entry where the uncatalogued branch is gated on cacheEnabled(). The npm
# packument separates them too, an entry generating it rather than caching it
# (npm.go:144), and that one turns on the entry existing rather than on its
# mode. Both branches answer 200, so the status separates nothing.
#
# The posture on entry is PXY-07's restore: proxy_cache_enabled false, both
# upstream maps empty. So the switch-off half is measured first, against
# PXY-10, PXY-11 and PXY-12, which just answered the same three routes in the
# same posture with nothing catalogued. One variable differs: the manifest.

E2E_HOST=server
for t in npm cargo gomod; do
	fx="$(e2e_fixture "$t-proxy")"
	e2e_on server "cat > /tmp/e2e-pxymode-$t.json <<'E2EFIXTURE'
$fx
E2EFIXTURE" || true
	e2e_bodega server "pkg import /tmp/e2e-pxymode-$t.json" || true
	check_contains "PXY-MODE-IMPORT-$t" "a proxy-mode $t entry imports" \
		"Imported $t/$(e2e_fixture_name "$t-proxy")" "$E2E_OUT$E2E_ERR" \
		"test/e2e/lib/fixtures.sh:41" "bodega pkg import /tmp/e2e-pxymode-$t.json" "$E2E_RC"
done

# The mode itself, not just the entry. `mode` is an optional field and an
# import that dropped it would leave three hosted entries behind, under which
# every check below still answers 200 and none of them measures proxy mode.
e2e_bodega server "show pkg npm $(e2e_fixture_name npm-proxy) $(e2e_fixture_version npm-proxy)" || true
check_matches PXY-MODE-01 "the imported entry records proxy mode" \
	'Mode:[[:space:]]+proxy' "$E2E_OUT" \
	"cmd/bodega/cmd_show.go:446" "bodega show pkg npm is-number 7.0.0"

# The running server holds the manifest index in memory, so it has to be told.
# Reload rather than restart: SIGHUP re-reads exactly this, and a restart here
# would spend one of systemd's five starts per ten seconds on a reason the
# on-posture below needs one for.
e2e_reload server || true

# Whatever the stored copies above left, since a cached object is served
# whether the switch is on or off. Without this the checks below measure the
# cache and pass against a server that never consulted a manifest.
e2e_on server "sudo rm -rf /var/lib/bodega/npm/is-number /var/lib/bodega/gomod/github.com/pkg /var/lib/bodega/cargo/crates/anyhow-1.0.86.crate; true" || true

# ---- the switch off, with an entry -----------------------------------------
#
# npm and gomod disagree with their uncatalogued halves here and cargo agrees,
# and that asymmetry is the code's answer rather than this suite's assumption:
# proxyOrResolve refuses only when `!cacheEnabled() && !forceProxy`
# (internal/server/proxy.go:115), and the proxy-mode branch of npm and gomod
# passes forceProxy true where the uncatalogued branch is gated on
# cacheEnabled(). cargo's download passes it true for both, which is why PXY-12
# already serves with the switch off and PXY-MODE-05 below matches it.

E2E_HOST=client

# PXY-10 asked for this path in this posture and got 404. The difference is the
# entry: a manifest-named package has its packument generated from the entry
# rather than fetched, so the switch never enters into it.
e2e_http client "/npm/is-number" || true
check_eq PXY-MODE-02 "a proxy-mode npm packument is generated with caching off, where an uncatalogued name 404s" \
	"200" "$E2E_OUT" \
	"internal/server/npm.go:144; an entry of any mode generates the packument from the manifest, so the switch never enters it and this answers 200 with caching off; uncatalogued PXY-10 404s on the same path in the same posture" \
	"GET /npm/is-number with a proxy-mode entry and proxy_cache_enabled false"

e2e_http client "/npm/is-number/-/is-number-7.0.0.tgz" || true
check_eq PXY-MODE-03 "a proxy-mode npm tarball is fetched with caching off" \
	"200" "$E2E_OUT" \
	"internal/server/npm.go:67; the proxy-mode branch passes forceProxy true, so the fetch bypasses the cache switch and answers 200 with caching off and again with it on (PXY-MODE-06); the uncatalogued branch at npm.go:83 is gated on cacheEnabled and 404s on a miss; both derive the same NpmTarballKey at npm.go:39" \
	"GET the tarball with a proxy-mode entry and proxy_cache_enabled false"

# PXY-11's module, in PXY-11's posture, with an entry. PXY-11 got 404.
e2e_http client "/go/github.com/pkg/errors/@v/v0.9.1.info" || true
check_eq PXY-MODE-04 "a proxy-mode gomod file is fetched with caching off, where an uncatalogued module 404s" \
	"200" "$E2E_OUT" \
	"internal/server/gomod.go:73; the proxy-mode branch passes forceProxy true and answers 200 with caching off and again with it on (PXY-MODE-11); the uncatalogued branch at gomod.go:102 needs cacheEnabled and 404s, which PXY-11 measured; GomodFileKey is derived at gomod.go:24 before either branch, so the key is the same and the switch is the difference" \
	"GET /go/github.com/pkg/errors/@v/v0.9.1.info with a proxy-mode entry and proxy_cache_enabled false"

# The one route where the two postures agree, and it is not an oversight:
# forceProxy at cargo.go:353 is `pm == nil || packageMode(pm) == ModeProxy`, so
# the switch gates neither half. PXY-12 is the uncatalogued reading of the same
# request. A check asserting a difference here would be asserting a verdict the
# code does not support.
e2e_http client "/cargo/anyhow/1.0.86/download" || true
check_eq PXY-MODE-05 "a proxy-mode cargo download is fetched with caching off, as an uncatalogued one already is" \
	"200" "$E2E_OUT" \
	"internal/server/cargo.go:353; forceProxy is pm == nil || mode == proxy, true for both, so the postures agree: 200 with caching off here, with it on at PXY-MODE-09, and uncatalogued PXY-12 already 200s in this posture; CargoCrateKey at cargo.go:352 is derived for both branches" \
	"GET /cargo/anyhow/1.0.86/download with a proxy-mode entry and proxy_cache_enabled false"

# ---- the key the manifest implies ------------------------------------------
#
# Proxy caching back on, which is PXY-NPM-02's posture: it proved an
# uncatalogued is-number writes npm/is-number/packument.json. The same paths
# follow with a manifest naming them, so the packument check below differs from
# PXY-NPM-02 in one variable.
#
# The stored copies the switch-off block just wrote go first, for the same
# reason they went first there.

E2E_HOST=server
e2e_config_set server '.proxy_cache_enabled = true' || true
e2e_restart server || true
e2e_on server "sudo rm -rf /var/lib/bodega/npm/is-number /var/lib/bodega/gomod/github.com/pkg /var/lib/bodega/cargo/crates/anyhow-1.0.86.crate; true" || true

E2E_HOST=client
e2e_http client "/npm/is-number" || true
e2e_http client "/npm/is-number/-/is-number-7.0.0.tgz" || true
check_eq PXY-MODE-06 "the proxy-mode npm tarball is served with caching on" "200" "$E2E_OUT" \
	"internal/server/npm.go:67; 200, the same answer PXY-MODE-03 got with caching off, so the switch changes nothing for a proxy-mode entry; the uncatalogued branch answers this route only with the switch on" \
	"GET /npm/is-number/-/is-number-7.0.0.tgz"

# The wire path carries the /-/ separator and the client-facing filename; the
# key carries neither. NpmTarballKey derives it from the name and the version,
# which is the hosted layout, so a proxy-mode fetch lands where an upload would
# have and not in a slot named after the request. The uncatalogued branch
# derives that same key at npm.go:39, so this measures the layout rather than
# which branch served it.
E2E_HOST=server
e2e_on server "sudo find /var/lib/bodega/npm -type f | sed 's|^/var/lib/bodega/||' | sort" || true
check_contains PXY-MODE-07 "the proxy-mode npm tarball lands under the key its manifest implies" \
	"npm/is-number/is-number-7.0.0.tgz" "${E2E_OUT:-nothing stored}" \
	"internal/manifest/keys.go:147; the key is the name and the version, not the /-/ request path; npm.go:39 derives it before the manifest lookup, so the uncatalogued branch writes the same string and this measures the layout rather than the branch" \
	"find /var/lib/bodega/npm -type f"

# The other direction of the same distinction, and the one place on these three
# routes where the branches write different keys. PXY-NPM-02 found
# npm/is-number/packument.json under an uncatalogued name; an entry generates
# that document from itself, so there is nothing to cache and the key is absent.
check_lacks PXY-MODE-08 "a proxy-mode entry caches no packument, where an uncatalogued name does" \
	"npm/is-number/packument.json" "${E2E_OUT:-nothing stored}" \
	"internal/server/npm.go:144; an entry of any mode serves this document from serveManifestPackument, so nothing is cached under npm/is-number/packument.json; the uncatalogued branch fetches and stores it at npm.go:152, which PXY-NPM-02 found; the variable is the entry, not the mode and not the switch, and it is the one key on these routes the two branches do not share" \
	"the same listing, against PXY-NPM-02"

E2E_HOST=client
e2e_http client "/cargo/anyhow/1.0.86/download" || true
check_eq PXY-MODE-09 "the proxy-mode cargo crate is served with caching on" "200" "$E2E_OUT" \
	"internal/server/cargo.go:353; 200, as at PXY-MODE-05 with the switch off and as uncatalogued PXY-12 in that same posture: this route forces past the switch for both branches, so neither the posture nor the manifest changes the answer" \
	"GET /cargo/anyhow/1.0.86/download"

# Requested as anyhow/1.0.86/download, stored as cargo/crates/anyhow-1.0.86.crate.
# Nothing in the key is the request path, and cargo.go:352 derives it for both
# branches, so what the entry adds here is the backend: versionStore
# (internal/server/server.go:1641) reads it off a matching version entry where
# an uncatalogued crate falls back to the type rule. That is invisible on a
# guest with one backend configured, which is why the key is what this asserts.
E2E_HOST=server
e2e_on server "sudo find /var/lib/bodega/cargo -type f | sed 's|^/var/lib/bodega/||' | sort" || true
check_contains PXY-MODE-10 "the proxy-mode cargo crate lands under the key its manifest implies, not the request path" \
	"cargo/crates/anyhow-1.0.86.crate" "${E2E_OUT:-nothing stored}" \
	"internal/manifest/keys.go:159; the key is the crate and the version, not the /download request path, and cargo.go:352 derives it for both branches; what the entry adds is the backend, which versionStore reads off a matching version entry at server.go:1641" \
	"find /var/lib/bodega/cargo -type f"

E2E_HOST=client
e2e_http client "/go/github.com/pkg/errors/@v/v0.9.1.info" || true
check_eq PXY-MODE-11 "the proxy-mode gomod file is served with caching on" "200" "$E2E_OUT" \
	"internal/server/gomod.go:73; 200, the same answer PXY-MODE-04 got with caching off, so the switch changes nothing for a proxy-mode entry; the uncatalogued branch at gomod.go:102 reaches upstream only with the switch on, which is why PXY-11 404s with it off" \
	"GET /go/github.com/pkg/errors/@v/v0.9.1.info"

# No artifact route here can be told apart by its key, gomod included: each
# derives one before the manifest lookup, and for this type a Go client asks
# for the module path verbatim, so GomodFileKey keeps the slashes
# (internal/manifest/keys.go:118). The measurement that does separate the
# branches for this type is PXY-MODE-04 against PXY-11.
E2E_HOST=server
e2e_on server "sudo find /var/lib/bodega/gomod -type f | sed 's|^/var/lib/bodega/||' | sort" || true
check_contains PXY-MODE-12 "the proxy-mode gomod file lands under the key its manifest implies" \
	"gomod/github.com/pkg/errors/@v/v0.9.1.info" "${E2E_OUT:-nothing stored}" \
	"internal/manifest/keys.go:118; GomodFileKey is derived at gomod.go:24 before the manifest lookup, so both branches write gomod/github.com/pkg/errors/@v/v0.9.1.info and the key separates nothing; for this type the branches part at the switch, PXY-MODE-04 against PXY-11" \
	"find /var/lib/bodega/gomod -type f"

# ---- restore ---------------------------------------------------------------
#
# Three manifests and one posture, all of this section's making. Left behind,
# is-number and github.com/pkg/errors would answer any later check out of the
# registry rather than out of storage, which is PXY-07's reasoning applied to
# entries instead of namespaces. `--remove-artifacts` drops the bytes each
# entry's versions name; the rm covers the regenerable files no version names.

E2E_HOST=server
for t in npm cargo gomod; do
	e2e_bodega server "pkg delete $t $(e2e_fixture_name "$t-proxy") --remove-artifacts" || true
	check_eq "PXY-MODE-DEL-$t" "the proxy-mode $t entry is deleted" 0 "$E2E_RC" \
		"cmd/bodega/cmd_delete.go:22" "bodega pkg delete $t $(e2e_fixture_name "$t-proxy") --remove-artifacts" "$E2E_RC"
done

e2e_config_set server '.proxy_cache_enabled = false' || true
e2e_restart server || true
e2e_on server "sudo rm -rf /var/lib/bodega/npm/is-number /var/lib/bodega/gomod/github.com/pkg /var/lib/bodega/cargo/crates/anyhow-1.0.86.crate; true" || true

# Asserted by the request, not by the restart or by the delete's exit code:
# either could succeed while the server still held the old index, and a 404
# here needs both the entry gone and the switch off. PXY-10 and PXY-11 are the
# same two checks before this section ran.
E2E_HOST=client
e2e_http client "/npm/is-number" || true
check_eq PXY-MODE-13 "the npm name is uncatalogued again with the switch off" "404" "$E2E_OUT" \
	"internal/server/npm.go:154" "GET /npm/is-number after the restore"

e2e_http client "/go/github.com/pkg/errors/@v/list" || true
check_eq PXY-MODE-14 "the gomod module is uncatalogued again with the switch off" "404" "$E2E_OUT" \
	"internal/server/gomod.go:103" "GET /go/github.com/pkg/errors/@v/list after the restore"

# cargo has no 404 to assert: PXY-12 and PXY-MODE-05 both serve this path in
# this posture, so the entry's absence is read off the manifest store instead.
E2E_HOST=server
e2e_bodega server "show pkg cargo $(e2e_fixture_name cargo-proxy)" || true
check_ne PXY-MODE-15 "the proxy-mode cargo entry is gone from the manifest store" 0 "$E2E_RC" \
	"cmd/bodega/cmd_show.go:245" "bodega show pkg cargo anyhow" "$E2E_RC"

# The hosted half still works, which is what the rest of the run assumes. PXY-09
# is the same request before this section touched anything.
E2E_HOST=client
e2e_http client "/binaries/hello-binary/1.0.0/LICENSE" || true
check_eq PXY-MODE-16 "a hosted fixture still serves from storage after the restore" "200" "$E2E_OUT" \
	"internal/server/binary.go:57" "GET /binaries/hello-binary/1.0.0/LICENSE after the restore"

# ---- the pypi name a wheel filename spells ---------------------------------
#
# PEP 503 spells a distribution name with hyphens and PEP 427 spells the
# distribution field of a wheel filename with underscores, so a hyphenated
# distribution cataloged the documented way served its own simple index and 404d
# every wheel that index listed. 40 of the 101 distributions in a widget install
# are hyphenated, so this is most of a real install rather than an edge.
#
# The posture on entry is the restore above: proxy_cache_enabled false. pypi
# passes forceProxy true for a proxy-mode entry (internal/server/pypi.go:240), so
# the switch does not enter into it and PXY-PYPI-01 already measured the
# uncatalogued half in this same posture.

E2E_HOST=server
pypi_fx="$(e2e_fixture pypi-proxy)"
e2e_on server "cat > /tmp/e2e-pypiname.json <<'E2EFIXTURE'
$pypi_fx
E2EFIXTURE" || true
e2e_bodega server "pkg import /tmp/e2e-pypiname.json" || true
check_contains PXY-PYPI-NAME-IMPORT "a proxy-mode pypi entry imports under its PEP 503 name" \
	"Imported pypi/$(e2e_fixture_name pypi-proxy)" "$E2E_OUT$E2E_ERR" \
	"test/e2e/lib/fixtures.sh:171" "bodega pkg import /tmp/e2e-pypiname.json" "$E2E_RC"

# The running server holds the manifest index in memory. Reload rather than
# restart, for the reason PXY-MODE's reload gives.
e2e_reload server || true

E2E_HOST=client
e2e_http client "/pypi/wheels/typing_extensions-4.12.2-py3-none-any.whl" || true
check_eq PXY-PYPI-NAME-01 "the wheel a hyphenated distribution's index lists is served" "200" "$E2E_OUT" \
	"internal/server/pypi.go:240; the manifest is named typing-extensions and the wheel filename spells it typing_extensions, so the lookup has to canonicalize; the raw name reaches no entry and the route answers the PXY-PYPI-01 refusal instead" \
	"GET /pypi/wheels/typing_extensions-4.12.2-py3-none-any.whl with a proxy-mode entry named typing-extensions"

# The simple index for the same entry, which is the request pip makes first.
e2e_http client "/pypi/simple/typing-extensions/" || true
check_eq PXY-PYPI-NAME-02 "the simple index for the same entry answers" "200" "$E2E_OUT" \
	"internal/server/pypi.go:139" "GET /pypi/simple/typing-extensions/"

# ---- the index read an observe window runs on ------------------------------
#
# pip meets an uncataloged distribution at the simple index and never composes a
# wheel URL, so the wheel route's recorder is on a path nothing reaches. Without
# a row here the documented bootstrap — observe, install, generate-manifests —
# returns an empty catalog on an empty store, which is the loop the widget
# install ran fifty-one rounds of by hand.

E2E_HOST=server
e2e_config_get server '.discover_mode // ""' || true
discover_mode="$E2E_OUT"

# A real distribution, small and stable, for the leg that ends at pypi.org.
bootstrap_dist=iniconfig

E2E_HOST=client
e2e_http client "/pypi/simple/e2e-no-such-dist/" || true
check_eq PXY-PYPI-DISC-01 "an uncataloged simple index 404s" "404" "$E2E_OUT" \
	"internal/server/pypi.go:188" "GET /pypi/simple/e2e-no-such-dist/"

E2E_HOST=server
if [ "$discover_mode" != observe ]; then
	e2e_skip PXY-PYPI-DISC-02 "the uncataloged index read leaves a discovery row" \
		"discover_mode is \"$discover_mode\", so no row is written at any route" "internal/server/discovery.go:341"
	e2e_skip PXY-PYPI-DISC-03 "generate-manifests promotes that row to a proxy entry" \
		"discover_mode is \"$discover_mode\", so there is no row to promote" "cmd/bodega/cmd_discover.go:513"
else
	# The recorder writes off the request goroutine, so the read is retried
	# rather than assumed to have landed.
	e2e_wait_for server 10 "sudo bodega discover export csv pypi | grep -q e2e-no-such-dist" || true
	e2e_bodega server "discover export csv pypi" || true
	check_contains PXY-PYPI-DISC-02 "the uncataloged index read leaves a discovery row" \
		"e2e-no-such-dist" "$E2E_OUT" \
		"internal/server/pypi.go:189; the row carries the upstream simple index URL, which is the only URL this branch knows: a wheel URL is read out of that document rather than composed" \
		"bodega discover export csv pypi"

	e2e_bodega server "discover generate-manifests pypi" || true
	check_contains PXY-PYPI-DISC-03 "generate-manifests promotes that row to a proxy entry" \
		"e2e-no-such-dist" "$E2E_OUT" \
		"cmd/bodega/cmd_discover.go:513; a pypi row names no version and composes none into its fetch path, so it promotes as an open proxy entry rather than being skipped as unpromotable" \
		"bodega discover generate-manifests pypi"

	# The whole bootstrap rather than its first half. Generating JSON proves
	# nothing about what a client can install: the payload has to import, the
	# server has to pick it up, and the request that 404d has to answer. The
	# distribution is a real one this time, because the retry ends at
	# pypi.org and a made-up name 404s there for its own reasons.
	e2e_bodega server "show pkg pypi $bootstrap_dist" || true
	if [ "$E2E_RC" = 0 ]; then
		for id in PXY-PYPI-DISC-04 PXY-PYPI-DISC-05 PXY-PYPI-DISC-06; do
			e2e_skip "$id" "observe, generate, import, retry bootstraps a catalog" \
				"pypi/$bootstrap_dist is already cataloged on this server, so the 404 the sequence starts from cannot happen" \
				"cmd/bodega/cmd_discover.go:513"
		done
	else
		E2E_HOST=client
		e2e_http client "/pypi/simple/$bootstrap_dist/" || true
		check_eq PXY-PYPI-DISC-04 "the distribution to bootstrap 404s before the sequence" "404" "$E2E_OUT" \
			"internal/server/pypi.go:150" "GET /pypi/simple/$bootstrap_dist/ with no manifest entry"

		E2E_HOST=server
		e2e_wait_for server 10 "sudo bodega discover export csv pypi | grep -q $bootstrap_dist" || true
		e2e_bodega server "discover generate-manifests pypi --since 10m --skip-existing -o /tmp/e2e-bootstrap-all.json" || true
		# Narrowed to the distribution under test before the import. The
		# payload is the generated one; a run that imported every pypi row it
		# observed in the last ten minutes would catalog whatever the suites
		# above reached for and leave it on the server.
		e2e_on server "sudo jq '[.[] | select(.name == \"$bootstrap_dist\")]' /tmp/e2e-bootstrap-all.json | sudo tee /tmp/e2e-bootstrap.json > /dev/null" || true
		e2e_bodega server "pkg import /tmp/e2e-bootstrap.json" || true
		check_contains PXY-PYPI-DISC-05 "the generated payload imports as a manifest" \
			"Imported pypi/$bootstrap_dist" "$E2E_OUT$E2E_ERR" \
			"cmd/bodega/cmd_import.go:127; generate-manifests writes JSON and nothing else, so an operator who stops there has cataloged nothing" \
			"bodega pkg import /tmp/e2e-bootstrap.json" "$E2E_RC"

		e2e_reload server || true

		E2E_HOST=client
		e2e_http client "/pypi/simple/$bootstrap_dist/" || true
		check_eq PXY-PYPI-DISC-06 "the bootstrapped entry serves the index that 404d" "200" "$E2E_OUT" \
			"internal/server/pypi.go:139; this is the whole of what docs/usage.md promises for observe mode on pypi, and the one leg nothing measured" \
			"GET /pypi/simple/$bootstrap_dist/ after the generate and the import"

		# The entry the sequence created. The discovery rows stay: they record
		# requests that happened, and 97-machine-readable reads the pypi table
		# after this suite.
		E2E_HOST=server
		e2e_bodega server "pkg delete pypi $bootstrap_dist" || true
		e2e_on server "sudo rm -f /tmp/e2e-bootstrap.json /tmp/e2e-bootstrap-all.json; true" || true
		e2e_reload server || true
	fi
fi

# ---- restore ---------------------------------------------------------------
#
# The entry alone. The discovery row stays: it is a record of a request that
# happened, 97-machine-readable reads the pypi table after this suite, and
# nothing serves differently for its presence.

E2E_HOST=server
e2e_bodega server "pkg delete pypi $(e2e_fixture_name pypi-proxy)" || true
check_eq PXY-PYPI-NAME-DEL "the proxy-mode pypi entry is deleted" 0 "$E2E_RC" \
	"cmd/bodega/cmd_delete.go:22" "bodega pkg delete pypi typing-extensions" "$E2E_RC"

# By path, because --remove-artifacts refuses for pypi: wheels upload as a
# directory and have no per-version object key. The cached wheel left behind
# would answer the next request for it out of storage, which is PXY-07's
# reasoning applied to one artifact instead of a namespace.
e2e_on server "sudo rm -f /var/lib/bodega/pypi/wheels/typing_extensions-4.12.2-py3-none-any.whl; true" || true
e2e_reload server || true

E2E_HOST=client
e2e_http client "/pypi/wheels/typing_extensions-4.12.2-py3-none-any.whl" || true
check_eq PXY-PYPI-NAME-03 "the wheel is uncataloged again once the entry and the cached copy are gone" \
	"404" "$E2E_OUT" \
	"internal/server/pypi.go:259" "GET /pypi/wheels/typing_extensions-4.12.2-py3-none-any.whl after the delete"

# The body only once the status says it is the refusal: a 200 here would write a
# wheel into the run log and leave it unreadable.
if [ "${E2E_OUT:-}" = 404 ]; then
	e2e_body client "/pypi/wheels/typing_extensions-4.12.2-py3-none-any.whl" || true
	check_contains PXY-PYPI-NAME-04 "the refusal names the distribution by its canonical spelling" \
		"bodega pkg create pypi typing-extensions" "${E2E_OUT:-no body}" \
		"internal/server/pypi.go:259; the underscore spelling the route used to print creates an entry no simple index request reaches" \
		"GET the same wheel, reading the body"
else
	e2e_skip PXY-PYPI-NAME-04 "the refusal names the distribution by its canonical spelling" \
		"the route answered ${E2E_OUT:-nothing} rather than the refusal, which PXY-PYPI-NAME-03 reports" "internal/server/pypi.go:259"
fi

unset pypi_fx discover_mode bootstrap_dist
