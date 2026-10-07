# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The supply-chain controls a fresh install ships with, and the ones it does
# not. threat-model.md and QUICKSTART §13 both make claims about the default
# posture; this suite measures them on a running install rather than reading
# them back out of the documentation that made them.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block POL-BLOCK "policy" "the server guest is unreachable"
	return 0
fi

E2E_HOST=server

# ---- the seeded age gates --------------------------------------------------

e2e_bodega server "policy age list" || true
ages="$E2E_OUT"
check_contains POL-01 "npm carries the seeded publish-age gate" "npm" "$ages" \
	"docs/quickstart.md:238" "bodega policy age list"
check_contains POL-02 "pypi carries the seeded publish-age gate" "pypi" "$ages" \
	"docs/quickstart.md:238" "bodega policy age list"
check_contains POL-03 "the seeded action is warn, not block" "warn" "$ages" \
	"docs/quickstart.md:248" "bodega policy age list"

# The ecosystems with no upstream publish timestamp must be refused rather than
# accepted and silently never evaluated.
for eco in apt binary git helm; do
	e2e_bodega server "policy age set $eco 7d warn" || true
	check_ne "POL-AGE-$eco" "an age gate on $eco is refused" 0 "$E2E_RC" \
		"docs/quickstart.md:247" "bodega policy age set $eco 7d warn" "$E2E_RC"
done

# gomod and cargo can be dated and get no seed, which is a documented gap
# rather than a defect: the check records that setting one works.
e2e_bodega server "policy age set gomod 7d warn" || true
check_eq POL-04 "an age gate can be set on gomod" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy_age.go:39" "bodega policy age set gomod 7d warn" "$E2E_RC"
e2e_bodega server "policy age remove gomod" || true

# ---- the allow-list --------------------------------------------------------

e2e_bodega server "policy list" || true
check_eq POL-05 "the allow-list is readable" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy.go:49" "bodega policy list" "$E2E_RC"

e2e_bodega server "policy add npm 'registry.npmjs.org/*' 'e2e run'" || true
check_eq POL-06 "a rule can be added" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy.go:98" "bodega policy add npm registry.npmjs.org/*" "$E2E_RC"

e2e_bodega server "policy list" || true
check_contains POL-07 "the added rule is listed" "registry.npmjs.org" "$E2E_OUT" \
	"cmd/bodega/cmd_policy.go:49" "bodega policy list"

# Exit 1 on a violation is the useful behavior, so the verdict is about the
# output rather than the code: asserting 0 turns "the scan found something"
# into a harness failure.
e2e_bodega server "policy check" || true
check_matches POL-08 "policy check reports either a clean scan or the violations it found" \
	'no policy violations|violation' "$E2E_OUT$E2E_ERR" \
	"cmd/bodega/cmd_policy.go:241" "bodega policy check"

e2e_bodega server "policy remove 'registry.npmjs.org/*' --type npm" || true
check_eq POL-09 "the rule can be removed" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy.go:177" "bodega policy remove registry.npmjs.org/*" "$E2E_RC"

# ---- OSV -------------------------------------------------------------------

e2e_bodega server "policy osv list" || true
check_eq POL-10 "the OSV gate list is readable" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy_osv.go:112" "bodega policy osv list" "$E2E_RC"

e2e_bodega server "policy osv set npm warn" || true
check_eq POL-11 "an OSV gate can be set" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy_osv.go:75" "bodega policy osv set npm warn" "$E2E_RC"

# The sync pulls a real OSV export and is the slowest thing in the suite, so it
# gets its own budget rather than the default.
E2E_SSH_TIMEOUT=900 e2e_bodega server "policy osv sync npm" || true
check_eq POL-12 "the OSV database syncs for npm" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy_osv.go:270" "bodega policy osv sync npm" "$E2E_RC"

e2e_bodega server "policy osv rescan --type npm" || true
check_eq POL-13 "stored versions rescan against the local OSV database" 0 "$E2E_RC" \
	"cmd/bodega/cmd_policy_osv.go:461" "bodega policy osv rescan --type npm" "$E2E_RC"

e2e_bodega server "policy osv remove npm" || true

# ---- doctor reads the posture ---------------------------------------------
#
# doctor exits 2 on any finding, so its exit code says "something is set" and
# not which thing. The rows are what carry the answer.

e2e_bodega server "doctor" || true
doc="$E2E_OUT"
check_eq POL-14 "doctor exits 2 while the host carries findings" 2 "$E2E_RC" \
	"cmd/bodega/cmd_doctor.go:206" "bodega doctor" "$E2E_RC"
check_contains POL-15 "doctor reports policy coverage" "policy-coverage" "$doc" \
	"cmd/bodega/cmd_doctor.go:558" "bodega doctor"
check_lacks POL-16 "the policy checks are not degraded to N/A under sudo" \
	"policy-coverage   N/A" "$doc" "cmd/bodega/cmd_doctor.go:558" "sudo bodega doctor"

# The same command unprivileged cannot read a root-owned config. It measures no
# posture at all, and the three ways it has to say so are the row status, the
# next step, and the exit code. N/A beside OK said none of them.
e2e_bodega_user server "doctor" || true
unpriv="$E2E_OUT"
unpriv_rc="$E2E_RC"
check_matches POL-17 "an unprivileged doctor reports the posture as unmeasured, not N/A" \
	'policy-coverage[[:space:]]+SKIPPED' "$unpriv" "cmd/bodega/cmd_doctor.go:571" "bodega doctor (unprivileged)"
check_contains POL-17b "the rows that could not run name the privilege they need" \
	"sudo bodega doctor" "$unpriv" "cmd/bodega/cmd_doctor.go:629" "bodega doctor (unprivileged)"
check_eq POL-17c "an unmeasured run exits 3, not the 2 a measured host with gaps exits" \
	3 "$unpriv_rc" "cmd/bodega/cmd_doctor.go:206" "bodega doctor (unprivileged)" "$unpriv_rc"

unset ages eco doc unpriv unpriv_rc

# ---- what a refused client prints ------------------------------------------
#
# A refusal is only useful if the person who hit it can read it at their own
# terminal, so these run the real clients on the client guest and grade their
# output, not the response: npm prints the JSON error field, cargo the body,
# go the body under "server response:", and pip only the status line. Each
# check then looks the incident up in the server's audit trail, which is the
# claim the incident exists to make.
#
# The packages are ones no fixture hosts, so each request reaches the proxy
# path the gates sit on, and their cached copies are removed first: a cache
# hit is served before any gate runs.

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_CLIENT_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block POL-REF-BLOCK "refusals at the client" "the client guest is unreachable"
	return 0
fi

E2E_HOST=local
REF_BIN="$REPO_ROOT/dist/bodega-linux-arm64"
if [ "${E2E_SHIP:-yes}" = yes ]; then
	e2e_local make -C "$REPO_ROOT" cross CROSS_TARGETS=linux/arm64 || true
	check_eq POL-REF-01 "make cross builds the server's arm64 binary" 0 "$E2E_RC" \
		"Makefile" "make cross CROSS_TARGETS=linux/arm64" "$E2E_RC"
	E2E_HOST=server
	if e2e_put server "$REF_BIN" /tmp/bodega-under-test &&
		e2e_on server "sudo install -o root -g root -m 0755 /tmp/bodega-under-test /usr/local/bin/bodega"; then
		e2e_record POL-REF-02 PASS "the server takes the new binary" "installed" "installed" "install /usr/local/bin/bodega" 0 ""
	else
		e2e_record POL-REF-02 FAIL "the server takes the new binary" "installed" "$E2E_ERR" "install /usr/local/bin/bodega" "$E2E_RC" ""
	fi
else
	e2e_skip POL-REF-01 "make cross builds the server's arm64 binary" "--no-ship"
	e2e_skip POL-REF-02 "the server takes the new binary" "--no-ship"
fi

E2E_HOST=server
e2e_config_get server '.proxy_cache_enabled' || true
ref_cache_was="${E2E_OUT:-false}"
e2e_config_set server '.proxy_cache_enabled = true' || true
e2e_restart server || true
e2e_on server "bodega --version" || true
check_contains POL-REF-03 "the server runs the commit under test" "${E2E_COMMIT%-dirty}" "$E2E_OUT" \
	"Makefile" "bodega --version"

REF_DIR="${E2E_CLIENT_ROOT:-/var/tmp/bodega-e2e-clients}/refusal"
REF_HOST="${E2E_BASE_URL#*://}"
REF_HOST="${REF_HOST%%[:/]*}"

E2E_HOST=client
e2e_on client "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq npm python3-pip python3-venv cargo golang-go >/dev/null && \
	mkdir -p $REF_DIR && rm -rf $REF_DIR/venv && python3 -m venv $REF_DIR/venv" || true
check_eq POL-REF-04 "the client has npm, pip, go and cargo" 0 "$E2E_RC" \
	"test/e2e/README.md" "apt-get install npm python3-pip python3-venv cargo golang-go" "$E2E_RC"

# One proxy-mode pypi entry, admitted before the pypi rule below exists: pip
# reaches the allow-list only through an entry, since an uncatalogued name is
# answered from storage and never goes upstream.
E2E_HOST=server
e2e_on server "cat > /tmp/e2e-ref-toml.json <<'E2EREF'
{\"config_version\": 1, \"name\": \"toml\", \"type\": \"pypi\", \"versions\": [{\"version\": \"0.10.2\", \"mode\": \"proxy\"}]}
E2EREF" || true
e2e_bodega server "pkg import --merge /tmp/e2e-ref-toml.json" || true

ref_clear_caches() {
	e2e_on server "sudo rm -rf /var/lib/bodega/npm/left-pad /var/lib/bodega/cargo/index/it/oa/itoa \
		/var/lib/bodega/cargo/crates/itoa-* /var/lib/bodega/gomod/github.com/kr \
		/var/lib/bodega/pypi/simple/toml /var/lib/bodega/pypi/wheels/toml-*; true" || true
}

# Each client, from a scratch cache, so a hit from an earlier run cannot stand
# in for a request that reached bodega. The output is stdout and stderr
# together, as the person at the terminal sees it.
ref_npm() {
	e2e_on client "rm -rf $REF_DIR/npm $REF_DIR/npm-cache && mkdir -p $REF_DIR/npm && cd $REF_DIR/npm && \
		npm install --no-audit --no-fund --cache '$REF_DIR/npm-cache' --registry '$E2E_BASE_URL/npm' left-pad@1.3.0 2>&1; true" || true
}
ref_pip() {
	e2e_on client "$REF_DIR/venv/bin/pip install $1 --no-cache-dir --trusted-host '$REF_HOST' \
		--index-url '$E2E_BASE_URL/pypi/simple/' $2 2>&1; true" || true
}
ref_go() {
	e2e_on client "rm -rf $REF_DIR/gomod && mkdir -p $REF_DIR/gomod && cd $REF_DIR/gomod && \
		GOPATH=$REF_DIR/gomod/path GOMODCACHE=$REF_DIR/gomod/cache GOFLAGS=-modcacherw GOSUMDB=off GOTOOLCHAIN=local \
		GOPROXY='$E2E_BASE_URL/go' go mod download github.com/kr/pretty@v0.3.1 2>&1; true" || true
}
ref_cargo() {
	e2e_on client "rm -rf $REF_DIR/cargo && mkdir -p $REF_DIR/cargo/src $REF_DIR/cargo/.cargo && \
		printf 'fn main() {}\n' > $REF_DIR/cargo/src/main.rs && \
		printf '[package]\nname = \"e2e\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"=1.0.11\"\n' > $REF_DIR/cargo/Cargo.toml && \
		printf '[source.crates-io]\nreplace-with = \"bodega\"\n\n[source.bodega]\nregistry = \"sparse+%s/cargo/\"\n' '$E2E_BASE_URL' > $REF_DIR/cargo/.cargo/config.toml && \
		cd $REF_DIR/cargo && CARGO_HOME=$REF_DIR/cargo/home cargo fetch 2>&1; true" || true
}

# ref_check <id> <client> <check> <command>: the client's output names the
# check beside an incident, and that incident is in the server's audit trail.
ref_check() {
	local id="$1" client="$2" check="$3" cmd="$4" out="$E2E_OUT" inc
	E2E_HOST=client
	check_contains "$id-a" "$client prints the $check check and an incident" "($check, incident " "$out" \
		"internal/server/refusal.go" "$cmd"
	inc="$(printf '%s' "$out" | sed -n "s/.*($check, incident \([0-9a-f]\{12\}\)).*/\1/p" | head -1)"
	E2E_HOST=server
	e2e_on server "curl -s --max-time 30 'http://127.0.0.1:8080/api/v1/audit?limit=2000'" || true
	check_contains "$id-b" "the incident $client printed is the one its audit row carries" \
		"${inc:-<no incident in the client output>}" "$E2E_OUT" "internal/server/refusal.go" \
		"GET /api/v1/audit | grep ${inc:-?}"
}

# The allow-list: one rule per type that names some other package, so a rule
# exists and none matches. The pypi rule follows the entry above.
for ref_rule in "npm e2e-refusal-allowed" "pypi e2e-refusal-allowed" "cargo e2e_refusal_allowed" "gomod example.com/e2e-refusal-allowed"; do
	e2e_bodega server "policy add $ref_rule 'e2e refusal run'" || true
done
ref_clear_caches
# A restart rather than waiting out the allow-list's 30s rule cache.
e2e_restart server || true

ref_npm
ref_check POL-REF-NPM-ALLOW npm allow-list "npm install --registry $E2E_BASE_URL/npm left-pad@1.3.0"
# pip prints an index page's failure only at -vv: by default it reports "no
# matching distribution" and nothing of why. A refused file download it prints
# at every verbosity, and only as the status line.
ref_pip -vv toml==0.10.2
ref_check POL-REF-PIP-ALLOW pip allow-list "pip install -vv --index-url $E2E_BASE_URL/pypi/simple/ toml==0.10.2"
ref_pip "" "$E2E_BASE_URL/pypi/wheels/toml-0.10.2-py2.py3-none-any.whl"
ref_check POL-REF-PIPFILE-ALLOW pip allow-list "pip install $E2E_BASE_URL/pypi/wheels/toml-0.10.2-py2.py3-none-any.whl"
ref_go
ref_check POL-REF-GO-ALLOW go allow-list "GOPROXY=$E2E_BASE_URL/go go mod download github.com/kr/pretty@v0.3.1"
ref_cargo
ref_check POL-REF-CARGO-ALLOW cargo allow-list "cargo fetch (itoa =1.0.11) against sparse+$E2E_BASE_URL/cargo/"

for ref_rule in "npm e2e-refusal-allowed" "pypi e2e-refusal-allowed" "cargo e2e_refusal_allowed" "gomod example.com/e2e-refusal-allowed"; do
	e2e_bodega server "policy remove '${ref_rule#* }' --type ${ref_rule%% *}" || true
done

# The age gate, at a window every version of these packages is inside, so the
# verdict does not depend on what upstream published this week.
for eco in npm pypi gomod cargo; do
	e2e_bodega server "policy age set $eco 3650d block" || true
done
ref_clear_caches
e2e_restart server || true

ref_npm
ref_check POL-REF-NPM-AGE npm age "npm install --registry $E2E_BASE_URL/npm left-pad@1.3.0"
ref_pip -vv toml==0.10.2
ref_check POL-REF-PIP-AGE pip age "pip install -vv --index-url $E2E_BASE_URL/pypi/simple/ toml==0.10.2"
ref_go
ref_check POL-REF-GO-AGE go age "GOPROXY=$E2E_BASE_URL/go go mod download github.com/kr/pretty@v0.3.1"
ref_cargo
ref_check POL-REF-CARGO-AGE cargo age "cargo fetch (itoa =1.0.11) against sparse+$E2E_BASE_URL/cargo/"

# Back to the shipped posture the top of this suite asserted, and to the cache
# switch as it was found.
E2E_HOST=server
e2e_bodega server "policy age set npm 7d warn" || true
e2e_bodega server "policy age set pypi 7d warn" || true
e2e_bodega server "policy age remove gomod" || true
e2e_bodega server "policy age remove cargo" || true
e2e_bodega server "pkg delete pypi toml" || true
ref_clear_caches
e2e_config_set server ".proxy_cache_enabled = ${ref_cache_was}" || true
e2e_restart server || true
check_eq POL-REF-05 "the server comes back with the posture restored" 0 "$E2E_RC" \
	"test/e2e/suites/50-policy.sh" "systemctl restart bodega" "$E2E_RC"

unset REF_BIN REF_DIR REF_HOST ref_cache_was ref_rule eco
unset -f ref_clear_caches ref_npm ref_pip ref_go ref_cargo ref_check
