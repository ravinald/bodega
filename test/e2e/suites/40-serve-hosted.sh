# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# What a hosted-only install serves. Proxy caching is off for the whole suite,
# which is the posture the product is named for: everything a client needs is
# already in the store and nothing leaves the network.
#
# Two routes per type, asserted separately on purpose. The artifact route is
# the bytes; the index route is how a client finds them. A type serving one and
# not the other is unusable by its native client while looking half-healthy in
# any test that only fetches a known URL.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"
# shellcheck source=../lib/freebsd.sh
. "${E2E_DIR:?}/lib/freebsd.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block SRV-BLOCK "hosted serving" "a guest is unreachable"
	return 0
fi

E2E_HOST=server

# The hosted npm entries were fetched by whatever run first stored them, which
# may predate published_at. The backfill dates them before the restart below
# loads the manifests, so SRV-AGE reads what a fetch today would record.
e2e_bodega server "build fetch npm --backfill-published" || true
check_eq SRV-AGE-01 "the backfill dates every hosted npm version" 0 "$E2E_RC" \
	"cmd/bodega/cmd_fetch.go:102" "bodega build fetch npm --backfill-published" "$E2E_RC"

e2e_config_set server '.proxy_cache_enabled = false' || true
e2e_restart server || true
check_eq SRV-01 "the server restarts with proxy caching off" 0 "$E2E_RC" \
	"internal/server/proxy.go:281" "systemctl restart bodega" "$E2E_RC"

e2e_apt_version >/dev/null

E2E_HOST=client

# ---- index routes ----------------------------------------------------------
#
# One row per type, named so the report reads as a coverage table.

e2e_index_check() {
	local id="$1" title="$2" path="$3" ref="$4"
	e2e_http client "$path" || true
	check_eq "$id" "$title" "200" "$E2E_OUT" "$ref" "curl $E2E_BASE_URL$path"
}

e2e_index_check SRV-IDX-apt "apt serves a Release index" \
	"/apt/dists/noble/Release" "internal/server/apt.go:154"
e2e_index_check SRV-IDX-apt-packages "apt serves a Packages index" \
	"/apt/dists/noble/main/binary-arm64/Packages" "internal/server/apt.go:231"
e2e_index_check SRV-IDX-pypi "pypi serves the simple index for a hosted wheel" \
	"/pypi/simple/six/" "internal/server/pypi.go:62"
e2e_index_check SRV-IDX-gomod "gomod serves @v/list for a hosted module" \
	"/go/github.com/google/uuid/@v/list" "internal/server/gomod.go:13"
e2e_index_check SRV-IDX-helm "helm serves index.yaml for a hosted chart" \
	"/helm/index.yaml" "internal/server/helm.go:28"
e2e_index_check SRV-IDX-npm "npm serves a packument for a hosted package" \
	"/npm/color-convert" "internal/server/npm.go:264"
e2e_index_check SRV-IDX-cargo "cargo serves a sparse index entry for a hosted crate" \
	"/cargo/fo/rm/form_urlencoded" "internal/server/cargo.go:179"
e2e_index_check SRV-IDX-cargo-config "cargo serves config.json" \
	"/cargo/config.json" "internal/server/cargo.go:44"

# ---- artifact routes -------------------------------------------------------

e2e_index_check SRV-ART-apt "apt serves the pool .deb" \
	"/apt/pool/main/h/hello/hello_${E2E_APT_VERSION}_arm64.deb" "internal/server/apt.go:34"
e2e_index_check SRV-ART-git "git serves the bundle" \
	"/git/uuid/uuid-v1.6.0.bundle" "internal/server/git.go:27"
e2e_index_check SRV-ART-binary "binary serves the downloaded file" \
	"/binaries/hello-binary/1.0.0/LICENSE" "internal/server/binary.go:31"
e2e_index_check SRV-ART-gomod "gomod serves the module zip" \
	"/go/github.com/google/uuid/@v/v1.6.0.zip" "internal/server/gomod.go:13"
e2e_index_check SRV-ART-helm "helm serves the chart tarball" \
	"/helm/charts/podinfo-6.7.0.tgz" "internal/server/helm.go:53"
e2e_index_check SRV-ART-npm "npm serves the tarball" \
	"/npm/color-convert/-/color-convert-2.0.1.tgz" "internal/server/npm.go:21"
e2e_index_check SRV-ART-cargo "cargo serves the crate" \
	"/cargo/form_urlencoded/1.2.2/download" "internal/server/cargo.go:122"

# ---- client-side release-age cooldown -------------------------------------
#
# npm reads time[<version>] for min-release-age and treats a version with no
# entry as old enough, so an undated packument passes every cooldown and only
# the refusal proves the time is served. The client's own npm is Ubuntu's 9.2,
# which predates the setting; 11.21.0 is installed into a scratch prefix from
# the public registry, because it is the client tool under test and not a
# package bodega serves. The age is read off the served packument rather than
# assumed, so the two settings straddle whatever bodega published.

E2E_HOST=client
AGE_ROOT=/tmp/e2e-release-age
e2e_on client "rm -rf $AGE_ROOT && mkdir -p $AGE_ROOT && \
	npm install --silent --no-audit --no-fund --prefix $AGE_ROOT/npm11 --cache $AGE_ROOT/npm11-cache npm@11.21.0 >/dev/null 2>&1 && \
	$AGE_ROOT/npm11/node_modules/.bin/npm --version" || true
check_eq SRV-AGE-02 "npm 11.21.0 is available on the client" "11.21.0" "$E2E_OUT" \
	"" "npm install --prefix $AGE_ROOT/npm11 npm@11.21.0" "$E2E_RC"

e2e_on client "curl -s --max-time 30 '$E2E_BASE_URL/npm/color-convert' | python3 -c '
import datetime, json, sys
t = json.load(sys.stdin).get(\"time\", {}).get(\"2.0.1\")
if t:
    published = datetime.datetime.fromisoformat(t.replace(\"Z\", \"+00:00\"))
    print((datetime.datetime.now(datetime.timezone.utc) - published).days)
'" || true
age_days="$E2E_OUT"
# A dry run reads no packument; a placeholder walks the plan through the
# install commands instead of the branch that reports a missing time.
[ "${E2E_DRY_RUN:-no}" = yes ] && age_days=0
check_matches SRV-AGE-03 "the hosted packument dates color-convert@2.0.1" '^[0-9]+$' "$age_days" \
	"internal/server/npm.go:288" "curl $E2E_BASE_URL/npm/color-convert | jq '.time[\"2.0.1\"]'"

# e2e_age_install <min-release-age days> — a fresh project and cache per run, so
# neither attempt can answer from what the other fetched.
e2e_age_install() {
	e2e_on client "rm -rf $AGE_ROOT/proj $AGE_ROOT/cache && mkdir -p $AGE_ROOT/proj && cd $AGE_ROOT/proj && \
		$AGE_ROOT/npm11/node_modules/.bin/npm install --no-audit --no-fund --cache $AGE_ROOT/cache \
		--registry '$E2E_BASE_URL/npm' --min-release-age=$1 color-convert@2.0.1 2>&1 | tail -8"
}

if [ -n "$age_days" ] && [ "$age_days" -ge 0 ] 2>/dev/null; then
	e2e_age_install "$((age_days + 30))" || true
	check_ne SRV-AGE-04 "npm refuses a hosted version younger than --min-release-age" 0 "$E2E_RC" \
		"internal/server/npm.go:332" "npm install --min-release-age=$((age_days + 30)) color-convert@2.0.1" "$E2E_RC"
	check_contains SRV-AGE-05 "the refusal names the release date, not a transport failure" \
		"with a date before" "$E2E_OUT$E2E_ERR" "internal/server/npm.go:288" \
		"npm install --min-release-age=$((age_days + 30)) color-convert@2.0.1" "$E2E_RC"

	e2e_age_install 1 || true
	check_eq SRV-AGE-06 "npm installs a hosted version older than --min-release-age" 0 "$E2E_RC" \
		"internal/server/npm.go:288" "npm install --min-release-age=1 color-convert@2.0.1" "$E2E_RC"
	e2e_on client "test -f $AGE_ROOT/proj/node_modules/color-convert/package.json && echo present" || true
	check_eq SRV-AGE-07 "the cooldown install lands in node_modules" "present" "$E2E_OUT" \
		"internal/server/npm.go:21" "test -f node_modules/color-convert/package.json"
else
	for id in SRV-AGE-04 SRV-AGE-05 SRV-AGE-06 SRV-AGE-07; do
		e2e_record "$id" FAIL "npm honors --min-release-age against a hosted package" \
			"a publish time in the hosted packument" "$(e2e_excerpt "$age_days")" \
			"curl $E2E_BASE_URL/npm/color-convert" 0 "internal/server/npm.go:288"
	done
fi
e2e_on client "rm -rf $AGE_ROOT" || true

# pypi's wheel filename is resolved rather than assumed: the index is the
# client's only route to it, and asserting a name the index does not publish
# would test the fixture instead of the server.
e2e_body client "/pypi/simple/six/" || true
wheel="$(printf '%s' "$E2E_OUT" | sed -n 's/.*href="\([^"]*\.whl\)".*/\1/p' | head -1)"
if [ -n "$wheel" ]; then
	e2e_index_check SRV-ART-pypi "pypi serves the wheel its index links to" \
		"$wheel" "internal/server/pypi.go:155"
else
	e2e_record SRV-ART-pypi FAIL "pypi serves the wheel its index links to" \
		"a .whl href in the simple index" "$(e2e_excerpt "$E2E_OUT")" \
		"curl $E2E_BASE_URL/pypi/simple/six/" 0 "internal/server/pypi.go:62"
fi

# ---- freebsd, both repopath layouts ----------------------------------------
#
# A pkg client reads meta.conf, then packagesite.pkg, then each package at the
# repopath its own catalogue names. Every one of those is compared against the
# fixture bytes rather than against a status code: the two archives carry
# FreeBSD's signature as a member, so a byte of transformation anywhere on this
# path is a signature failure the client reports against bodega.
#
# The upstream is stopped first. These entries are hosted, so nothing here may
# reach it, and taking it away is how that stops being an assumption.

E2E_HOST=server
e2e_freebsd_upstream_stop server || true
e2e_on server "curl -s -o /dev/null -w '%{http_code}' --max-time 5 '$E2E_FREEBSD_URL/latest/meta.conf' || true" || true
check_ne SRV-FBSD-OFFLINE "the fixture pkg upstream is down for the checks below" \
	"200" "$E2E_OUT" "test/e2e/lib/freebsd.sh" "curl $E2E_FREEBSD_URL/latest/meta.conf"

# e2e_freebsd_same <id> <title> <repo> <repopath> — the served bytes against
# the fixture's, by digest.
e2e_freebsd_same() {
	local id="$1" title="$2" repo="$3" rel="$4" served="" stored=""
	e2e_on server "curl -sf --max-time 30 '$E2E_BASE_URL/freebsd/FreeBSD:14:amd64/$repo/$rel' | sha256sum | cut -d' ' -f1" || true
	served="$E2E_OUT"
	e2e_on server "sudo sha256sum '$E2E_FREEBSD_ROOT/$repo/$rel' | cut -d' ' -f1" || true
	stored="$E2E_OUT"
	check_eq "$id" "$title" "$stored" "${served:-nothing served}" \
		"internal/server/freebsd.go:57" "curl $E2E_BASE_URL/freebsd/FreeBSD:14:amd64/$repo/$rel"
}

for fbrepo in latest base_latest; do
	e2e_freebsd_same "SRV-FBSD-META-$fbrepo" "$fbrepo serves meta.conf byte for byte" \
		"$fbrepo" "meta.conf"
	e2e_freebsd_same "SRV-FBSD-CATALOG-$fbrepo" "$fbrepo serves packagesite.pkg byte for byte" \
		"$fbrepo" "packagesite.pkg"
	e2e_freebsd_same "SRV-FBSD-DATA-$fbrepo" "$fbrepo serves data.pkg byte for byte" \
		"$fbrepo" "data.pkg"

	# The object is read out of the catalogue bodega just served, because the
	# catalogue is the only authority on where a package's bytes are and a
	# hardcoded path here would test the fixture instead of the route. The
	# leading "./" goes the way a client drops it.
	e2e_on server "curl -sf --max-time 30 '$E2E_BASE_URL/freebsd/FreeBSD:14:amd64/$fbrepo/packagesite.pkg' \
		| zstd -d 2>/dev/null | tar -xOf - packagesite.yaml \
		| python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())[\"repopath\"].lstrip(\"./\"))'" || true
	fbpath="$E2E_OUT"
	if [ -n "$fbpath" ]; then
		e2e_freebsd_same "SRV-FBSD-OBJ-$fbrepo" "$fbrepo serves the package its own catalogue names" \
			"$fbrepo" "$fbpath"
	else
		e2e_record "SRV-FBSD-OBJ-$fbrepo" FAIL "$fbrepo serves the package its own catalogue names" \
			"a repopath out of the served catalogue" "$(e2e_excerpt "$E2E_OUT$E2E_ERR")" \
			"curl packagesite.pkg | zstd -d | tar -xO packagesite.yaml" "$E2E_RC" \
			"internal/builder/freebsd_catalog.go:161"
	fi
done

# The repository-root layout, which no upstream fixture publishes: a package
# whose repopath has no directory segment at all.
e2e_freebsd_same SRV-FBSD-ROOT "base_latest serves a package at the repository root" \
	"base_latest" "root.pkg"

# Refused by name rather than proxied, on a repository that holds neither.
e2e_http server "/freebsd/FreeBSD:14:amd64/latest/digests.pkg" || true
check_eq SRV-FBSD-GONE "a path no current pkg repository publishes is refused" \
	"404" "$E2E_OUT" "internal/server/freebsd.go:44" \
	"curl $E2E_BASE_URL/freebsd/FreeBSD:14:amd64/latest/digests.pkg"

E2E_HOST=client
e2e_index_check SRV-FBSD-CLIENT "a client host reaches the pkg repository root" \
	"/freebsd/FreeBSD:14:amd64/latest/meta.conf" "internal/server/freebsd.go:57"

# ---- health and metadata ---------------------------------------------------

e2e_index_check SRV-02 "healthz answers without auth" "/healthz" "internal/server/server.go:748"
e2e_index_check SRV-03 "the web dashboard serves at the root" "/" "internal/server/web.go:12"
e2e_index_check SRV-04 "the metrics endpoint answers" "/api/v1/metrics" "internal/server/server.go:804"

e2e_http client "/no-such-path" || true
check_eq SRV-05 "an unknown path under the web root is a 404" "404" "$E2E_OUT" \
	"internal/server/web.go:14" "curl $E2E_BASE_URL/no-such-path"

unset wheel fbrepo fbpath AGE_ROOT age_days
