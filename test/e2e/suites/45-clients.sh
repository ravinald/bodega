# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The native clients, from the client guest, over the network. This is the only
# suite that answers the product's actual claim: that apt-get, pip, helm, npm,
# cargo, go, mvn, gradle, gem, bundle, git and curl can consume bodega without
# leaving the network.
#
# The clients are installed here rather than baked into the guest image. The
# guests are disposable, so drift costs a rebuild, and an image carrying every
# ecosystem stops representing the machine a user installs bodega on.
#
# gomod is the exception: `go get` needs a toolchain, and the client guest
# carries none on purpose. That check runs on the server, which has one. It
# still crosses the network stack, and it does not exercise the client guest.

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
	e2e_block CLI-BLOCK "the native clients" "a guest is unreachable"
	return 0
fi

# ---- ecosystem clients -----------------------------------------------------
#
# Every scratch tree below lands under one root on /, not on /tmp: both guests
# mount a 1.7G tmpfs there, and a venv, a node_modules and a cargo registry
# cache are exactly what fills one. Nothing here has hit that ceiling yet, which
# is the argument for moving it rather than against: the first check to hit it
# reports a full filesystem as a client failure against bodega.
#
# $E2E_CLIENT_ROOT moves the lot. The gomod check at the end of this file runs
# on the server guest and uses the same path there, which is the only crossing.
CLIENT_ROOT="${E2E_CLIENT_ROOT:-/var/tmp/bodega-e2e-clients}"

E2E_HOST=client
e2e_on client "mkdir -p $CLIENT_ROOT" || true
e2e_on client "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq npm python3-pip python3-venv cargo" || true
check_eq CLI-00 "the client takes npm, pip and cargo from the archive" 0 "$E2E_RC" \
	"test/e2e/README.md" "apt-get install npm python3-pip cargo" "$E2E_RC"

# helm is not in the Ubuntu archive. Its own install script is the documented
# route and it is pinned rather than tracking latest, so a client failure is
# attributable to a version.
helm_arch="$(e2e_goarch client)" || helm_arch=arm64
e2e_on client "command -v helm >/dev/null 2>&1 || \
	(curl -fsSL https://get.helm.sh/helm-v3.16.2-linux-$helm_arch.tar.gz -o $CLIENT_ROOT/helm.tgz && \
	 tar -xzf $CLIENT_ROOT/helm.tgz -C $CLIENT_ROOT && sudo install -m0755 $CLIENT_ROOT/linux-$helm_arch/helm /usr/local/bin/helm)" || true
e2e_on client "helm version --short" || true
check_matches CLI-01 "the client has a helm binary" '^v3\.' "$E2E_OUT" \
	"test/e2e/README.md" "helm version --short"

# ---- apt -------------------------------------------------------------------
#
# The full documented path: sign on the server, install the keyring on the
# client through `doctor --write-apt-sources`, then let apt-get resolve.
# Nothing here hand-writes a sources file, so a defect in that writer is a
# failure rather than something the harness routes around.

e2e_apt_version >/dev/null

E2E_HOST=server
e2e_bodega server "apt key generate --name 'bodega e2e' --email admin@example.com" || true
e2e_restart server || true
e2e_bodega server "apt key show" || true
server_fpr="$(printf '%s' "$E2E_OUT" | tr -dc '[:alnum:]\n' | grep -Eo '[0-9A-F]{40}' || true)"
server_fpr="${server_fpr%%$'\n'*}"
check_matches CLI-APT-01 "the server holds a signing key" '^[0-9A-F]{40}$' \
	"${server_fpr:-none}" "cmd/bodega/cmd_apt.go:154" "bodega apt key show"

E2E_HOST=client

# The codename bodega generates, read off the instance rather than pinned. A
# server that also mirrors serves a codename per upstream beside it, and with
# no profile to choose between them the server names none: which one a host
# reads is the operator's decision. --suite is this check making it, which is
# what an operator on a mirroring instance does.
e2e_body client /api/v1/status || true
apt_suite="$(printf '%s' "$E2E_OUT" | jq -r '.apt.suites[0] // empty' 2>/dev/null || true)"
apt_suite_flag=""
if [ -n "$apt_suite" ]; then
	apt_suite_flag="--suite $apt_suite"
fi

# Both files go before the write. Left in place they are an earlier run's, and
# CLI-APT-03 through CLI-APT-08 then grade a sources file this run did not
# write: every one of them passed that way on a run where CLI-APT-02 failed.
e2e_on client "sudo rm -f /etc/apt/sources.list.d/bodega.sources /etc/apt/keyrings/bodega-archive-keyring.gpg" || true

# doctor reads its plan from /client/, which answers only a host an identity
# binding names, so the client's address is bound for the write and unbound
# straight after: 55-profile and 60-access bind the same address under their
# own identities and bodega refuses a second binding. Unbound first, so an
# aborted run's leftover does not fail the bind, and on any early exit too.
# cleanup is run.sh's own exit trap, which this one wraps rather than replaces.
CLI_CIDR="${E2E_CLIENT_ADDR:-127.0.0.1}/32"
cli_identity_on_exit() {
	e2e_bodega server "identity unbind cidr $CLI_CIDR" >/dev/null 2>&1 || true
	cleanup
}
trap cli_identity_on_exit EXIT
trap 'exit 130' INT TERM

E2E_HOST=server
e2e_bodega server "identity unbind cidr $CLI_CIDR" >/dev/null 2>&1 || true
e2e_bodega server "identity bind cidr $CLI_CIDR e2e-clients --comment 'e2e run'" || true
check_eq CLI-APT-BIND "the client's address binds to an identity for doctor" 0 "$E2E_RC" \
	"cmd/bodega/cmd_identity.go:59" "bodega identity bind cidr $CLI_CIDR e2e-clients" "$E2E_RC"
e2e_reload server || true

E2E_HOST=client
e2e_on client "sudo bodega doctor --write-apt-sources $apt_suite_flag --url '$E2E_BASE_URL' --allow-plaintext" || true
check_eq CLI-APT-02 "doctor writes the client's apt sources" 0 "$E2E_RC" \
	"cmd/bodega/cmd_doctor.go:87" "bodega doctor --write-apt-sources $apt_suite_flag" "$E2E_RC"

E2E_HOST=server
e2e_bodega server "identity unbind cidr $CLI_CIDR" || true
e2e_reload server || true
trap cleanup EXIT
trap - INT TERM
unset CLI_CIDR
E2E_HOST=client

e2e_on client "cat /etc/apt/sources.list.d/bodega.sources 2>&1" || true
check_contains CLI-APT-03 "the written source is signed-by the bodega keyring" \
	"Signed-By: /etc/apt/keyrings/bodega-archive-keyring.gpg" "$E2E_OUT" \
	"cmd/bodega/cmd_doctor.go:98" "cat /etc/apt/sources.list.d/bodega.sources"

# The keyring fetch is authenticated by the transport alone, so the fingerprint
# is compared against what the server says it signed with. Equal fingerprints
# are the only evidence the client trusts the right key.
e2e_on client "gpg --show-keys --with-colons /etc/apt/keyrings/bodega-archive-keyring.gpg 2>/dev/null | awk -F: '/^fpr:/{print \$10; exit}'" || true
check_eq CLI-APT-04 "the client's keyring fingerprint matches the server's key" \
	"$server_fpr" "$E2E_OUT" "docs/quickstart.md" "gpg --show-keys /etc/apt/keyrings/bodega-archive-keyring.gpg"

# Only bodega's source, so a package resolving proves it came from bodega. With
# the archive still enabled apt would satisfy `hello` upstream and the check
# would pass against a server that serves nothing.
e2e_on client "sudo mv /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.e2e-off 2>/dev/null; \
	sudo DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | tail -5" || true
check_lacks CLI-APT-05 "apt-get update accepts the bodega index" \
	"NO_PUBKEY" "$E2E_OUT$E2E_ERR" "internal/server/apt.go:185" "apt-get update"

e2e_on client "apt-cache policy hello 2>&1 | head -6" || true
check_contains CLI-APT-06 "apt sees the bodega-served candidate" \
	"$E2E_APT_VERSION" "$E2E_OUT" "internal/server/apt.go:231" "apt-cache policy hello"

e2e_on client "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y hello 2>&1 | tail -6" || true
check_eq CLI-APT-07 "apt-get installs a package served only by bodega" 0 "$E2E_RC" \
	"internal/server/apt.go:34" "apt-get install -y hello" "$E2E_RC"

e2e_on client "/usr/bin/hello 2>&1 | head -2" || true
check_contains CLI-APT-08 "the installed binary runs" "Hello" "$E2E_OUT" \
	"internal/server/apt.go:34" "/usr/bin/hello"

# The archive goes back on before anything else installs from apt, or every
# later client install fails for a reason that has nothing to do with bodega.
e2e_on client "sudo mv /etc/apt/sources.list.d/ubuntu.sources.e2e-off /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null; \
	sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq" || true

# ---- pypi ------------------------------------------------------------------
#
# --trusted-host because this run serves plaintext: pip ignores an http index
# outright and reports "no matching distribution", which names the package and
# not the transport. It is pip's policy rather than a bodega behavior, and it
# disappears the day this suite runs against TLS.

E2E_HOST=client
e2e_on client "rm -rf $CLIENT_ROOT/venv && python3 -m venv $CLIENT_ROOT/venv && \
	$CLIENT_ROOT/venv/bin/pip install --quiet --no-cache-dir \
	--trusted-host '$E2E_SERVER_HOST' \
	--index-url '$E2E_BASE_URL/pypi/simple/' six 2>&1 | tail -5" || true
check_eq CLI-PYPI-01 "pip installs from the bodega index" 0 "$E2E_RC" \
	"internal/server/pypi.go:23" "pip install --index-url $E2E_BASE_URL/pypi/simple/ six" "$E2E_RC"

e2e_on client "$CLIENT_ROOT/venv/bin/python -c 'import six; print(six.__version__)'" || true
check_matches CLI-PYPI-02 "the installed module imports" '^[0-9]+\.' "$E2E_OUT$E2E_ERR" \
	"internal/server/pypi.go:155" "python -c 'import six'"

# ---- npm -------------------------------------------------------------------

# color-convert rather than a leaf: it declares color-name ~1.1.4, and both are
# hosted, so this is the one shape of install that can tell a working registry
# from one whose packument declares no dependencies. --cache at a scratch path
# wiped alongside the project, because npm's default cache lives in $HOME and a
# hit there serves the packument and the tarball without asking bodega for
# either. npm has no --no-cache: it parses as cache=false and warns that the
# value is not a filesystem path.
e2e_on client "rm -rf $CLIENT_ROOT/npm $CLIENT_ROOT/npm-cache && mkdir -p $CLIENT_ROOT/npm && cd $CLIENT_ROOT/npm && \
	npm install --no-audit --no-fund --cache '$CLIENT_ROOT/npm-cache' --registry '$E2E_BASE_URL/npm' color-convert@2.0.1 2>&1 | tail -8" || true
check_eq CLI-NPM-01 "npm installs from the bodega registry" 0 "$E2E_RC" \
	"internal/server/npm.go:16" "npm install --registry $E2E_BASE_URL/npm color-convert@2.0.1" "$E2E_RC"

e2e_on client "test -f $CLIENT_ROOT/npm/node_modules/color-convert/package.json && echo present" || true
check_eq CLI-NPM-02 "the package lands in node_modules" "present" "$E2E_OUT" \
	"internal/server/npm.go:21" "test -f node_modules/color-convert/package.json"

# The defect #356 named: the install succeeds, writes one directory, and the
# package is broken afterwards. Requiring it is the only check that sees that,
# because the failure is MODULE_NOT_FOUND at require time and npm reports the
# install as a success.
e2e_on client "test -f $CLIENT_ROOT/npm/node_modules/color-name/package.json && echo present" || true
check_eq CLI-NPM-03 "the declared dependency is installed alongside it" "present" "$E2E_OUT" \
	"internal/server/npm.go:283" "test -f node_modules/color-name/package.json"

# The resolve guard is the check, and the value is the proof it ran. Ubuntu
# ships color-name at /usr/share/nodejs/color-name, which node falls back to
# after the project's node_modules misses, so a bare require() of
# color-convert succeeds on a guest whose registry served no dependency at
# all. This check reported PASS against exactly that for one full run.
e2e_on client "cd $CLIENT_ROOT/npm && node -e \"const p=require.resolve('color-name'); if(!p.startsWith(process.cwd())) throw new Error('resolved outside the project: '+p); console.log(require('color-convert').keyword.rgb('blue').join(','))\" 2>&1 | tail -3" || true
check_eq CLI-NPM-04 "the package loads against the dependency bodega served" "0,0,255" "$E2E_OUT" \
	"internal/server/npm.go:283" "node -e \"require.resolve('color-name') under the project, then require('color-convert')\""

# npm verifies every tarball against dist.integrity and fails EINTEGRITY on a
# mismatch, so CLI-NPM-01 above is the enforcement check and this is the one
# that says the key was there to enforce. Omitted rather than contradicted is
# the deliberate case (#358), and it looks identical from the install side.
e2e_on client "curl -sS --max-time 30 '$E2E_BASE_URL/npm/color-convert/2.0.1'" || true
check_contains CLI-NPM-05 "the served version document carries dist.integrity" \
	'"integrity":"sha256-' "$E2E_OUT" "internal/server/npm.go:305" \
	"curl $E2E_BASE_URL/npm/color-convert/2.0.1"

# ---- cargo -----------------------------------------------------------------

e2e_on client "rm -rf $CLIENT_ROOT/cargo && mkdir -p $CLIENT_ROOT/cargo/src && \
	printf 'fn main() {}\n' > $CLIENT_ROOT/cargo/src/main.rs && \
	printf '[package]\nname = \"e2e\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nform_urlencoded = \"=1.2.2\"\n' > $CLIENT_ROOT/cargo/Cargo.toml && \
	mkdir -p $CLIENT_ROOT/cargo/.cargo && \
	printf '[source.crates-io]\nreplace-with = \"bodega\"\n\n[source.bodega]\nregistry = \"sparse+%s/cargo/\"\n' '$E2E_BASE_URL' > $CLIENT_ROOT/cargo/.cargo/config.toml && \
	cd $CLIENT_ROOT/cargo && cargo fetch --offline 2>/dev/null; cargo fetch 2>&1 | tail -6" || true
check_eq CLI-CARGO-01 "cargo resolves a crate from the bodega sparse index" 0 "$E2E_RC" \
	"internal/server/cargo.go:179" "cargo fetch against sparse+$E2E_BASE_URL/cargo/" "$E2E_RC"

# form_urlencoded declares percent-encoding ^2.3.0, and cargo fetches what the
# index line names and nothing else. A line declaring deps: [] resolves and
# then fails at compile, which is louder than npm's but arrives just as late.
e2e_on client "cat $CLIENT_ROOT/cargo/Cargo.lock 2>&1" || true
check_contains CLI-CARGO-02 "cargo resolves the crate's declared dependency" \
	"percent-encoding" "$E2E_OUT" "internal/server/cargo.go:177" \
	"cat Cargo.lock after cargo fetch"

# ---- helm ------------------------------------------------------------------

e2e_on client "helm repo remove bodega >/dev/null 2>&1; \
	helm repo add bodega '$E2E_BASE_URL/helm' 2>&1 | tail -3" || true
check_contains CLI-HELM-01 "helm adds the bodega chart repository" \
	"has been added" "$E2E_OUT" "internal/server/helm.go:28" "helm repo add bodega $E2E_BASE_URL/helm"

e2e_on client "helm search repo bodega/podinfo --versions 2>&1 | tail -3" || true
check_contains CLI-HELM-02 "helm finds the hosted chart" "6.7.0" "$E2E_OUT" \
	"internal/server/helm.go:28" "helm search repo bodega/podinfo"

e2e_on client "rm -rf $CLIENT_ROOT/chart && mkdir -p $CLIENT_ROOT/chart && \
	helm pull bodega/podinfo --version 6.7.0 -d $CLIENT_ROOT/chart 2>&1 | tail -3; \
	ls $CLIENT_ROOT/chart" || true
check_contains CLI-HELM-03 "helm pulls the chart tarball" "podinfo-6.7.0.tgz" "$E2E_OUT" \
	"internal/server/helm.go:53" "helm pull bodega/podinfo --version 6.7.0"

# ---- git -------------------------------------------------------------------

e2e_on client "rm -rf $CLIENT_ROOT/git && mkdir -p $CLIENT_ROOT/git && cd $CLIENT_ROOT/git && \
	curl -sS -o uuid.bundle '$E2E_BASE_URL/git/uuid/uuid-v1.6.0.bundle'" || true
check_eq CLI-GIT-01 "the bundle downloads" 0 "$E2E_RC" \
	"internal/server/git.go:27" "curl $E2E_BASE_URL/git/uuid/uuid-v1.6.0.bundle" "$E2E_RC"

# The form QUICKSTART documents, with no --branch. A bundle carrying only a tag
# ref and no HEAD clones into an empty repository on this path, and the error
# names the local branch rather than the bundle, so the reader looks in the
# wrong place.
e2e_on client "cd $CLIENT_ROOT/git && git clone -q uuid.bundle uuid 2>&1; \
	git -C uuid log --oneline -1 2>&1" || true
check_matches CLI-GIT-02 "the documented clone command produces a checkout" \
	'^[0-9a-f]{7}' "$E2E_OUT$E2E_ERR" "docs/quickstart.md:154" "git clone uuid.bundle uuid"

# Naming the ref works, which is what separates "the bundle is broken" from
# "the bundle has no default branch".
e2e_on client "cd $CLIENT_ROOT/git && rm -rf uuid-ref && git clone -q --branch v1.6.0 uuid.bundle uuid-ref 2>&1; \
	git -C uuid-ref log --oneline -1 2>&1" || true
check_matches CLI-GIT-03 "naming the ref clones the bundle" \
	'^[0-9a-f]{7}' "$E2E_OUT$E2E_ERR" "internal/server/git.go:27" "git clone --branch v1.6.0 uuid.bundle"

e2e_on client "cd $CLIENT_ROOT/git && git bundle list-heads uuid.bundle" || true
check_contains CLI-GIT-04 "the bundle advertises the tag it was built for" \
	"refs/tags/v1.6.0" "$E2E_OUT" "internal/server/git.go:27" "git bundle list-heads uuid.bundle"

# ---- binary ----------------------------------------------------------------

e2e_on client "curl -sS -o $CLIENT_ROOT/LICENSE -w '%{http_code} %{size_download}' \
	'$E2E_BASE_URL/binaries/hello-binary/1.0.0/LICENSE'" || true
check_matches CLI-BIN-01 "curl downloads a hosted binary artifact" \
	'^200 [0-9]{3,}$' "$E2E_OUT" "internal/server/binary.go:31" "curl $E2E_BASE_URL/binaries/..."

# ---- FreeBSD ports tree ----------------------------------------------------
#
# ports.txz is what bsdinstall extracts, so it is the tree a freshly installed
# host already has, and bodega serves it as an ordinary binary entry. Listed
# rather than extracted: the tree is ~1.3 GB on ext4 and every claim below is
# answered by the member list.

ports_sha="$(printf '%s' "$(e2e_fixture ports-txz)" | jq -r '.versions[0].sha256')"
E2E_HOST=server
e2e_on server "cat > /tmp/e2e-fx-ports-txz.json <<'E2EFIXTURE'
$(e2e_fixture ports-txz)
E2EFIXTURE" || true
# --merge because this suite runs on its own as often as after 30-pipeline's
# reset, and a plain import of an entry already present exits 1.
e2e_bodega server "pkg import --merge /tmp/e2e-fx-ports-txz.json && sudo bodega build upload binary freebsd-ports" || true
check_eq CLI-PORTS-01 "the ports tarball builds as a binary entry" 0 "$E2E_RC" \
	"docs/usage.md#serving-the-freebsd-ports-tree" "bodega build upload binary freebsd-ports" "$E2E_RC"

E2E_HOST=client
e2e_on client "curl -sS -o $CLIENT_ROOT/ports.txz '$E2E_BASE_URL/binaries/freebsd-ports/15.1-RELEASE/ports.txz' && \
	sha256sum $CLIENT_ROOT/ports.txz | cut -d' ' -f1" || true
check_eq CLI-PORTS-02 "the client receives the digest the release MANIFEST publishes" \
	"$ports_sha" "$E2E_OUT" "internal/server/binary.go:31" \
	"curl $E2E_BASE_URL/binaries/freebsd-ports/15.1-RELEASE/ports.txz | sha256sum" "$E2E_RC"

# Members are rooted at usr/ports/, which is why the documented extraction is
# `tar -xf ports.txz -C /`. The .git count is the claim the update-path docs
# rest on: this tree cannot be `git pull`ed.
e2e_on client "tar -tJf $CLIENT_ROOT/ports.txz | awk '\$0==\"usr/ports/Mk/bsd.port.mk\"{mk=1} /^usr\\/ports\\/\\.git(\\/|\$)/{g++} END{print (mk?\"mk\":\"no-mk\"), g+0}'" || true
check_eq CLI-PORTS-03 "the tarball is a ports tree rooted at usr/ports with no .git" \
	"mk 0" "$E2E_OUT" "docs/usage.md#serving-the-freebsd-ports-tree" \
	"tar -tJf ports.txz" "$E2E_RC"
e2e_on client "rm -f $CLIENT_ROOT/ports.txz" || true
unset ports_sha

# ---- gomod -----------------------------------------------------------------
#
# On the server, which has the toolchain the client guest deliberately lacks.

E2E_HOST=server
e2e_on server "rm -rf $CLIENT_ROOT/gomod && mkdir -p $CLIENT_ROOT/gomod && cd $CLIENT_ROOT/gomod && \
	/usr/local/go/bin/go mod init e2e >/dev/null 2>&1; \
	GOFLAGS=-mod=mod GOSUMDB=off GONOSUMDB='*' GOPROXY='$E2E_BASE_URL/go' \
	/usr/local/go/bin/go get github.com/google/uuid@v1.6.0 2>&1 | tail -6" || true
check_eq CLI-GOMOD-01 "go get resolves a module through the bodega proxy" 0 "$E2E_RC" \
	"internal/server/gomod.go:13" "GOPROXY=$E2E_BASE_URL/go go get github.com/google/uuid@v1.6.0" "$E2E_RC"

# ---- JVM and Ruby clients: the server's posture -----------------------------
#
# maven and rubygems are pull-through types with nothing hosted to fall back
# on, so an uncataloged artifact is served only while proxy_cache_enabled is
# on, which 40-serve-hosted turns off. discover_mode observe is what writes the
# rows the checks below read. The gradle namespace is what a project's
# distributionUrl names: the wrapper downloads Gradle itself before any init
# script applies, so only a binary_upstreams namespace over services.gradle.org
# keeps that download on bodega. All three go back as they were at the end.

E2E_HOST=server
e2e_config_get server '{proxy_cache_enabled, discover_mode, binary_upstreams} | tojson' || true
jvm_saved="$E2E_OUT"
[ -n "$jvm_saved" ] || jvm_saved='{}'
e2e_config_set server '.proxy_cache_enabled = true | .discover_mode = "observe" | .binary_upstreams = ((.binary_upstreams // {}) + {"gradle": {"url": "https://services.gradle.org/", "mode": "open"}})' || true
e2e_restart server || true
check_eq CLI-MVN-00 "the server restarts proxying with discovery on and a gradle namespace" 0 "$E2E_RC" \
	"internal/server/maven.go:78" "jq '.proxy_cache_enabled = true | .discover_mode = \"observe\" | .binary_upstreams.gradle' config.json" "$E2E_RC"

CLI_CIDR="${E2E_CLIENT_ADDR:-127.0.0.1}/32"
CLI_CLIENT="${E2E_CLIENT_ADDR:-127.0.0.1}"

# shellcheck disable=SC2317,SC2329  # invoked by the EXIT trap cli_doctor sets
cli_doctor_on_exit() {
	e2e_bodega server "identity unbind cidr $CLI_CIDR" >/dev/null 2>&1 || true
	cleanup
}

# cli_doctor <system> — doctor --configure <system> --apply on the client, as
# the ssh user, so every ~ path in the plan is that user's home. doctor reads
# its plan from /client/, which answers only a host an identity binding names,
# and 55-profile and 60-access bind the same address under their own
# identities, so the binding is held for the doctor run alone.
cli_doctor() {
	local rc out
	E2E_HOST=server
	trap cli_doctor_on_exit EXIT
	trap 'exit 130' INT TERM
	e2e_bodega server "identity unbind cidr $CLI_CIDR" >/dev/null 2>&1 || true
	e2e_bodega server "identity bind cidr $CLI_CIDR e2e-clients --comment 'e2e run'" || true
	e2e_reload server || true
	E2E_HOST=client
	e2e_on client "bodega doctor --configure $1 --apply --url '$E2E_BASE_URL' --allow-plaintext 2>&1 | tail -8" || true
	rc="$E2E_RC" out="$E2E_OUT"
	E2E_HOST=server
	e2e_bodega server "identity unbind cidr $CLI_CIDR" >/dev/null 2>&1 || true
	e2e_reload server || true
	trap cleanup EXIT
	trap - INT TERM
	E2E_HOST=client
	E2E_RC="$rc" E2E_OUT="$out"
}

# cli_home_save <name...> / cli_home_restore <name...> — set aside what the
# doctor and the build write under ~, and put it back. A stale ~/.m2 or
# ~/.gradle answers a build from the local cache without asking bodega, so
# each section starts from none. A slot already holding something is an
# aborted run's: it is the original, and what sits in ~ is that run's.
cli_home_save() {
	local n cmd="mkdir -p $CLIENT_ROOT/home-saved"
	for n in "$@"; do
		cmd="$cmd; if [ -e $CLIENT_ROOT/home-saved/$n ]; then rm -rf ~/$n; elif [ -e ~/$n ]; then mv ~/$n $CLIENT_ROOT/home-saved/$n; fi"
	done
	e2e_on client "$cmd" || true
}
cli_home_restore() {
	local n cmd="true"
	for n in "$@"; do
		cmd="$cmd; rm -rf ~/$n; if [ -e $CLIENT_ROOT/home-saved/$n ]; then mv $CLIENT_ROOT/home-saved/$n ~/$n; fi"
	done
	e2e_on client "$cmd" || true
}

# cli_discovered <type> <package> <since> — prints "recorded" when a discovery
# row names the package, the client's address as last_client, and a last_seen
# at or after <since> (epoch seconds on the server). The time bound is what
# keeps a row an earlier run wrote from passing for this one. The recorder
# writes off the request goroutine, so the read is retried.
cli_discovered() {
	E2E_HOST=server
	e2e_on server "for i in \$(seq 1 10); do \
		seen=\$(sudo bodega discover export csv $1 | awk -F, -v p='$2' -v c='$CLI_CLIENT' '\$4 == p && \$10 == c {print \$9}' | sort | tail -1); \
		if [ -n \"\$seen\" ] && [ \"\$(date -d \"\$seen\" +%s)\" -ge $3 ]; then echo recorded; exit 0; fi; sleep 1; \
	done; echo \"no row since $3 from $CLI_CLIENT (last_seen: \${seen:-none})\"" || true
	E2E_HOST=client
}

# cli_since — the server's clock, for cli_discovered.
cli_since() {
	E2E_HOST=server
	e2e_on server "date +%s" || true
	cli_t0="${E2E_OUT:-0}"
	E2E_HOST=client
}

# ---- maven -----------------------------------------------------------------
#
# A fixture with one dependency and one class that uses it, so `package`
# compiles against the jar rather than packaging an empty project. Maven's own
# plugins (compiler, surefire, jar) come through the same mirror, so this is
# also every request a first `mvn package` on a fresh host makes.

E2E_HOST=client
e2e_on client "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq maven default-jdk-headless" || true
check_eq CLI-MVN-01 "the client takes maven and a JDK from the archive" 0 "$E2E_RC" \
	"test/e2e/README.md" "apt-get install maven default-jdk-headless" "$E2E_RC"

cli_home_save .m2 .gradle
cli_since
cli_doctor maven
check_eq CLI-MVN-02 "doctor --configure maven applies the plan" 0 "$E2E_RC" \
	"cmd/bodega/cmd_doctor.go:112" "bodega doctor --configure maven --apply" "$E2E_RC"

e2e_on client "grep -c '<url>$E2E_BASE_URL/maven/</url>' ~/.m2/settings.xml" || true
check_eq CLI-MVN-03 "settings.xml mirrors every repository to bodega" "1" "$E2E_OUT" \
	"internal/clientconf/maven.go:36" "grep '<url>$E2E_BASE_URL/maven/</url>' ~/.m2/settings.xml"

e2e_on client "rm -rf $CLIENT_ROOT/maven && mkdir -p $CLIENT_ROOT/maven/src/main/java/e2e && cd $CLIENT_ROOT/maven && \
	cat > pom.xml <<'E2EPOM'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>e2e</groupId>
  <artifactId>e2e</artifactId>
  <version>1.0</version>
  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.16</version>
    </dependency>
  </dependencies>
</project>
E2EPOM
cat > src/main/java/e2e/App.java <<'E2EJAVA'
package e2e;

public class App {
    static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(App.class);
}
E2EJAVA" || true

E2E_SSH_TIMEOUT=900 e2e_on client "cd $CLIENT_ROOT/maven && mvn -B -ntp package 2>&1 | tail -8" || true
check_eq CLI-MVN-04 "mvn package builds the fixture through bodega" 0 "$E2E_RC" \
	"internal/server/maven.go:37" "mvn -B -ntp package" "$E2E_RC"

e2e_on client "test -f ~/.m2/repository/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar && echo present" || true
check_eq CLI-MVN-05 "the dependency's jar lands in ~/.m2/repository" "present" "$E2E_OUT" \
	"internal/server/maven.go:37" "test -f ~/.m2/repository/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar"

cli_discovered maven org.slf4j:slf4j-api "$cli_t0"
check_eq CLI-MVN-06 "bodega records a discovery row for org.slf4j:slf4j-api from the client" "recorded" "$E2E_OUT" \
	"internal/server/maven.go:316" "bodega discover export csv maven"

e2e_on client "rm -rf $CLIENT_ROOT/maven" || true
cli_home_restore .m2 .gradle

# ---- gradle ----------------------------------------------------------------
#
# The wrapper is generated by the Gradle it names, fetched from the gradle
# namespace, and then gradlew downloads that distribution again on its own:
# the wrapper's download is the request the namespace exists for. The
# properties file is written whole rather than left as `gradle wrapper` wrote
# it, so the URL and the checksum the wrapper verifies are this suite's. The
# timeout is raised from the wrapper's 10s because bodega reads the whole
# distribution from upstream before it answers a cold request.
#
# 9.1.0 because the archive's default JDK is 25, the first release Gradle runs
# on. The build names mavenCentral() and the plugin portal by default, as a
# project does, and the init script doctor writes replaces both with bodega.

gradle_ver=9.1.0
gradle_sha=a17ddd85a26b6a7f5ddb71ff8b05fc5104c0202c6e64782429790c933686c806
gradle_url="$E2E_BASE_URL/binaries/gradle/distributions/gradle-$gradle_ver-bin.zip"

e2e_on client "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip default-jdk-headless" || true
check_eq CLI-GRADLE-01 "the client takes unzip and a JDK from the archive" 0 "$E2E_RC" \
	"test/e2e/README.md" "apt-get install unzip default-jdk-headless" "$E2E_RC"

cli_home_save .m2 .gradle
cli_since
cli_doctor maven
check_eq CLI-GRADLE-02 "doctor --configure maven writes the Gradle init script" 0 "$E2E_RC" \
	"internal/clientconf/maven.go:18" "bodega doctor --configure maven --apply" "$E2E_RC"

e2e_on client "rm -rf $CLIENT_ROOT/gradle && mkdir -p $CLIENT_ROOT/gradle/boot $CLIENT_ROOT/gradle/e2e/src/main/java/e2e && \
	cd $CLIENT_ROOT/gradle && curl -fsS -o boot/gradle.zip '$gradle_url' && \
	echo '$gradle_sha  boot/gradle.zip' | sha256sum -c --quiet && unzip -q boot/gradle.zip -d boot && \
	cd e2e && : > settings.gradle && \
	../boot/gradle-$gradle_ver/bin/gradle --no-daemon -q wrapper --gradle-distribution-url '$gradle_url' 2>&1 | tail -5" || true
check_eq CLI-GRADLE-03 "the Gradle bootstrap comes from the gradle namespace and writes a wrapper" 0 "$E2E_RC" \
	"internal/server/binary.go:31" "curl $gradle_url && gradle wrapper" "$E2E_RC"

e2e_on client "cd $CLIENT_ROOT/gradle/e2e && \
	cat > gradle/wrapper/gradle-wrapper.properties <<E2EPROPS
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=$gradle_url
distributionSha256Sum=$gradle_sha
networkTimeout=300000
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
E2EPROPS
cat > settings.gradle <<'E2ESETTINGS'
rootProject.name = 'e2e'
E2ESETTINGS
cat > build.gradle <<'E2EBUILD'
plugins {
    id 'java'
    id 'org.cyclonedx.bom' version '3.0.1'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'com.google.code.gson:gson:2.11.0'
}
E2EBUILD
cat > src/main/java/e2e/App.java <<'E2EJAVA'
package e2e;

public class App {
    static String json() {
        return new com.google.gson.Gson().toJson(1);
    }
}
E2EJAVA" || true

E2E_SSH_TIMEOUT=900 e2e_on client "cd $CLIENT_ROOT/gradle/e2e && ./gradlew --no-daemon -q build 2>&1 | tail -12" || true
check_eq CLI-GRADLE-04 "gradlew build fetches Gradle, a plugin and a dependency through bodega" 0 "$E2E_RC" \
	"internal/server/maven.go:37" "./gradlew build" "$E2E_RC"

e2e_on client "test -f ~/.gradle/wrapper/dists/gradle-$gradle_ver-bin/*/gradle-$gradle_ver/bin/gradle && echo present" || true
check_eq CLI-GRADLE-05 "the wrapper installs the distribution it downloaded" "present" "$E2E_OUT" \
	"internal/clientconf/maven.go:78" "test -f ~/.gradle/wrapper/dists/gradle-$gradle_ver-bin/*/gradle-$gradle_ver/bin/gradle"

cli_discovered maven com.google.code.gson:gson "$cli_t0"
check_eq CLI-GRADLE-06 "bodega records a discovery row for the Maven Central dependency" "recorded" "$E2E_OUT" \
	"internal/server/maven.go:316" "bodega discover export csv maven"

cli_discovered maven org.cyclonedx.bom:org.cyclonedx.bom.gradle.plugin "$cli_t0"
check_eq CLI-GRADLE-07 "bodega records a discovery row for the plugin marker from the plugin portal" "recorded" "$E2E_OUT" \
	"internal/server/maven.go:316" "bodega discover export csv maven"

e2e_on client "rm -rf $CLIENT_ROOT/gradle" || true
cli_home_restore .m2 .gradle

# ---- rubygems --------------------------------------------------------------
#
# gem installs into a scratch directory and Bundler into the fixture's own
# vendor/bundle, both named on the command line, so nothing lands in the
# system's gem directory. Bundler with no path set asks for sudo to write
# there, and with passwordless sudo it gets it. BUNDLE_PATH rather than
# `bundle config set`, which Bundler 1.x reads as a key named "set".
#
# rack-test because it declares rack, which the archive's Ruby does not ship,
# so Bundler has to resolve a dependency through bodega to finish.

e2e_on client "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ruby-bundler" || true
check_eq CLI-GEM-01 "the client takes ruby-bundler from the archive" 0 "$E2E_RC" \
	"test/e2e/README.md" "apt-get install ruby-bundler" "$E2E_RC"

cli_home_save .gemrc .gem .bundle
cli_since
cli_doctor rubygems
check_eq CLI-GEM-02 "doctor --configure rubygems applies the plan" 0 "$E2E_RC" \
	"internal/clientconf/clientconf.go:218" "bodega doctor --configure rubygems --apply" "$E2E_RC"

e2e_on client "rm -rf $CLIENT_ROOT/rubygems && mkdir -p $CLIENT_ROOT/rubygems && cd $CLIENT_ROOT/rubygems && \
	gem install --no-document --install-dir ./gems rake 2>&1 | tail -4" || true
check_eq CLI-GEM-03 "gem install takes rake from bodega" 0 "$E2E_RC" \
	"internal/server/rubygems.go:21" "gem install --install-dir ./gems rake" "$E2E_RC"

e2e_on client "cd $CLIENT_ROOT/rubygems && GEM_HOME=./gems GEM_PATH=./gems ./gems/bin/rake --version 2>&1" || true
check_matches CLI-GEM-04 "the installed rake runs" '^rake, version [0-9]' "$E2E_OUT" \
	"internal/server/rubygems.go:21" "GEM_HOME=./gems ./gems/bin/rake --version"

e2e_on client "mkdir -p $CLIENT_ROOT/rubygems/app && cd $CLIENT_ROOT/rubygems/app && \
	printf \"source 'https://rubygems.org'\\n\\ngem 'rake'\\ngem 'rack-test'\\n\" > Gemfile && \
	BUNDLE_PATH=vendor/bundle bundle install 2>&1 | tail -6" || true
check_eq CLI-GEM-05 "bundle install resolves the Gemfile through the mirror" 0 "$E2E_RC" \
	"internal/clientconf/clientconf.go:229" "BUNDLE_PATH=vendor/bundle bundle install" "$E2E_RC"

e2e_on client "cd $CLIENT_ROOT/rubygems/app && \
	BUNDLE_PATH=vendor/bundle bundle exec ruby -e 'require \"rack/test\"; require \"rack\"; puts Rack.release' 2>&1 | tail -3" || true
check_matches CLI-GEM-06 "the bundle loads rack-test and the rack it declared" '^[0-9]+\.[0-9]+' "$E2E_OUT" \
	"internal/server/rubygems.go:21" "bundle exec ruby -e 'require \"rack/test\"; require \"rack\"'"

gem_rows=""
for gem in rake rack-test rack; do
	cli_discovered rubygems "$gem" "$cli_t0"
	gem_rows="$gem_rows$gem=$E2E_OUT "
done
check_eq CLI-GEM-07 "bodega records a discovery row for each gem from the client" \
	"rake=recorded rack-test=recorded rack=recorded " "$gem_rows" \
	"internal/server/rubygems.go:209" "bodega discover export csv rubygems"

e2e_on client "rm -rf $CLIENT_ROOT/rubygems" || true
cli_home_restore .gemrc .gem .bundle

# ---- JVM and Ruby clients: the posture back ---------------------------------

E2E_HOST=server
e2e_config_set server "reduce ($jvm_saved | to_entries[]) as \$e (.; if \$e.value == null then del(.[\$e.key]) else .[\$e.key] = \$e.value end)" || true
e2e_restart server || true
e2e_config_get server '{proxy_cache_enabled, discover_mode, binary_upstreams} | tojson' || true
jvm_now="$E2E_OUT"
[ -n "$jvm_now" ] || jvm_now='{}'
check_eq CLI-GEM-08 "the server's proxy, discovery and binary namespace settings are back" \
	"$jvm_saved" "$jvm_now" "test/e2e/suites/45-clients.sh" "jq '{proxy_cache_enabled, discover_mode, binary_upstreams}' config.json"

unset -f cli_doctor_on_exit cli_doctor cli_home_save cli_home_restore cli_discovered cli_since
unset jvm_saved jvm_now CLI_CIDR CLI_CLIENT cli_t0 gradle_ver gradle_sha gradle_url gem_rows gem
unset server_fpr CLIENT_ROOT helm_arch
