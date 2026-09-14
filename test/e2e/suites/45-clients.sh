# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The native clients, from the client guest, over the network. This is the only
# suite that answers the product's actual claim: that apt-get, pip, helm, npm,
# cargo, go, git and curl can consume bodega without leaving the network.
#
# The clients are installed here rather than baked into the guest image.
# DEV_HOSTS.md says drift is fine because a UTM snapshot restores the pair, and
# an image carrying every ecosystem stops representing the machine a user
# installs bodega on.
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

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block CLI-BLOCK "the native clients" "a guest is unreachable"
	return 0
fi

# ---- ecosystem clients -----------------------------------------------------

E2E_HOST=client
e2e_on client "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq npm python3-pip python3-venv cargo" || true
check_eq CLI-00 "the client takes npm, pip and cargo from the archive" 0 "$E2E_RC" \
	"docs-internal/DEV_HOSTS.md" "apt-get install npm python3-pip cargo" "$E2E_RC"

# helm is not in the Ubuntu archive. Its own install script is the documented
# route and it is pinned rather than tracking latest, so a client failure is
# attributable to a version.
e2e_on client "command -v helm >/dev/null 2>&1 || \
	(curl -fsSL https://get.helm.sh/helm-v3.16.2-linux-arm64.tar.gz -o /tmp/helm.tgz && \
	 tar -xzf /tmp/helm.tgz -C /tmp && sudo install -m0755 /tmp/linux-arm64/helm /usr/local/bin/helm)" || true
e2e_on client "helm version --short" || true
check_matches CLI-01 "the client has a helm binary" '^v3\.' "$E2E_OUT" \
	"docs-internal/DEV_HOSTS.md" "helm version --short"

# ---- apt -------------------------------------------------------------------
#
# The full documented path: sign on the server, install the keyring on the
# client through `doctor --write-apt-sources`, then let apt-get resolve.
# Nothing here hand-writes a sources file, so a defect in that writer is a
# failure rather than something the harness routes around.

e2e_apt_version >/dev/null

E2E_HOST=server
e2e_bodega server "apt key generate --name 'bodega e2e' --email admin@cow.org" || true
e2e_restart server || true
e2e_bodega server "apt key show" || true
server_fpr="$(printf '%s' "$E2E_OUT" | tr -dc '[:alnum:]\n' | grep -Eo '[0-9A-F]{40}' | head -1)"
check_matches CLI-APT-01 "the server holds a signing key" '^[0-9A-F]{40}$' \
	"${server_fpr:-none}" "cmd/bodega/cmd_apt.go:154" "bodega apt key show"

E2E_HOST=client
e2e_on client "sudo bodega doctor --write-apt-sources --url '$E2E_BASE_URL' --allow-plaintext" || true
check_eq CLI-APT-02 "doctor writes the client's apt sources" 0 "$E2E_RC" \
	"cmd/bodega/cmd_doctor.go:87" "bodega doctor --write-apt-sources" "$E2E_RC"

e2e_on client "cat /etc/apt/sources.list.d/bodega.sources 2>&1" || true
check_contains CLI-APT-03 "the written source is signed-by the bodega keyring" \
	"Signed-By: /etc/apt/keyrings/bodega-archive-keyring.gpg" "$E2E_OUT" \
	"cmd/bodega/cmd_doctor.go:98" "cat /etc/apt/sources.list.d/bodega.sources"

# The keyring fetch is authenticated by the transport alone, so the fingerprint
# is compared against what the server says it signed with. Equal fingerprints
# are the only evidence the client trusts the right key.
e2e_on client "gpg --show-keys --with-colons /etc/apt/keyrings/bodega-archive-keyring.gpg 2>/dev/null | awk -F: '/^fpr:/{print \$10; exit}'" || true
check_eq CLI-APT-04 "the client's keyring fingerprint matches the server's key" \
	"$server_fpr" "$E2E_OUT" "docs/QUICKSTART.md" "gpg --show-keys /etc/apt/keyrings/bodega-archive-keyring.gpg"

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
e2e_on client "rm -rf /tmp/e2e-venv && python3 -m venv /tmp/e2e-venv && \
	/tmp/e2e-venv/bin/pip install --quiet --no-cache-dir \
	--trusted-host '$E2E_SERVER_HOST' \
	--index-url '$E2E_BASE_URL/pypi/simple/' six 2>&1 | tail -5" || true
check_eq CLI-PYPI-01 "pip installs from the bodega index" 0 "$E2E_RC" \
	"internal/server/pypi.go:23" "pip install --index-url $E2E_BASE_URL/pypi/simple/ six" "$E2E_RC"

e2e_on client "/tmp/e2e-venv/bin/python -c 'import six; print(six.__version__)'" || true
check_matches CLI-PYPI-02 "the installed module imports" '^[0-9]+\.' "$E2E_OUT$E2E_ERR" \
	"internal/server/pypi.go:155" "python -c 'import six'"

# ---- npm -------------------------------------------------------------------

e2e_on client "rm -rf /tmp/e2e-npm && mkdir -p /tmp/e2e-npm && cd /tmp/e2e-npm && \
	npm install --no-audit --no-fund --registry '$E2E_BASE_URL/npm' left-pad@1.3.0 2>&1 | tail -8" || true
check_eq CLI-NPM-01 "npm installs from the bodega registry" 0 "$E2E_RC" \
	"internal/server/npm.go:16" "npm install --registry $E2E_BASE_URL/npm left-pad@1.3.0" "$E2E_RC"

e2e_on client "test -f /tmp/e2e-npm/node_modules/left-pad/package.json && echo present" || true
check_eq CLI-NPM-02 "the package lands in node_modules" "present" "$E2E_OUT" \
	"internal/server/npm.go:21" "test -f node_modules/left-pad/package.json"

# ---- cargo -----------------------------------------------------------------

e2e_on client "rm -rf /tmp/e2e-cargo && mkdir -p /tmp/e2e-cargo/src && \
	printf 'fn main() {}\n' > /tmp/e2e-cargo/src/main.rs && \
	printf '[package]\nname = \"e2e\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"=1.0.11\"\n' > /tmp/e2e-cargo/Cargo.toml && \
	mkdir -p /tmp/e2e-cargo/.cargo && \
	printf '[source.crates-io]\nreplace-with = \"bodega\"\n\n[source.bodega]\nregistry = \"sparse+%s/cargo/\"\n' '$E2E_BASE_URL' > /tmp/e2e-cargo/.cargo/config.toml && \
	cd /tmp/e2e-cargo && cargo fetch --offline 2>/dev/null; cargo fetch 2>&1 | tail -6" || true
check_eq CLI-CARGO-01 "cargo resolves a crate from the bodega sparse index" 0 "$E2E_RC" \
	"internal/server/cargo.go:179" "cargo fetch against sparse+$E2E_BASE_URL/cargo/" "$E2E_RC"

# ---- helm ------------------------------------------------------------------

e2e_on client "helm repo remove bodega >/dev/null 2>&1; \
	helm repo add bodega '$E2E_BASE_URL/helm' 2>&1 | tail -3" || true
check_contains CLI-HELM-01 "helm adds the bodega chart repository" \
	"has been added" "$E2E_OUT" "internal/server/helm.go:28" "helm repo add bodega $E2E_BASE_URL/helm"

e2e_on client "helm search repo bodega/podinfo --versions 2>&1 | tail -3" || true
check_contains CLI-HELM-02 "helm finds the hosted chart" "6.7.0" "$E2E_OUT" \
	"internal/server/helm.go:28" "helm search repo bodega/podinfo"

e2e_on client "rm -rf /tmp/e2e-helm && mkdir -p /tmp/e2e-helm && \
	helm pull bodega/podinfo --version 6.7.0 -d /tmp/e2e-helm 2>&1 | tail -3; \
	ls /tmp/e2e-helm" || true
check_contains CLI-HELM-03 "helm pulls the chart tarball" "podinfo-6.7.0.tgz" "$E2E_OUT" \
	"internal/server/helm.go:53" "helm pull bodega/podinfo --version 6.7.0"

# ---- git -------------------------------------------------------------------

e2e_on client "rm -rf /tmp/e2e-git && mkdir -p /tmp/e2e-git && cd /tmp/e2e-git && \
	curl -sS -o uuid.bundle '$E2E_BASE_URL/git/uuid/uuid-v1.6.0.bundle'" || true
check_eq CLI-GIT-01 "the bundle downloads" 0 "$E2E_RC" \
	"internal/server/git.go:27" "curl $E2E_BASE_URL/git/uuid/uuid-v1.6.0.bundle" "$E2E_RC"

# The form QUICKSTART documents, with no --branch. A bundle carrying only a tag
# ref and no HEAD clones into an empty repository on this path, and the error
# names the local branch rather than the bundle, so the reader looks in the
# wrong place.
e2e_on client "cd /tmp/e2e-git && git clone -q uuid.bundle uuid 2>&1; \
	git -C uuid log --oneline -1 2>&1" || true
check_matches CLI-GIT-02 "the documented clone command produces a checkout" \
	'^[0-9a-f]{7}' "$E2E_OUT$E2E_ERR" "docs/QUICKSTART.md:154" "git clone uuid.bundle uuid"

# Naming the ref works, which is what separates "the bundle is broken" from
# "the bundle has no default branch".
e2e_on client "cd /tmp/e2e-git && rm -rf uuid-ref && git clone -q --branch v1.6.0 uuid.bundle uuid-ref 2>&1; \
	git -C uuid-ref log --oneline -1 2>&1" || true
check_matches CLI-GIT-03 "naming the ref clones the bundle" \
	'^[0-9a-f]{7}' "$E2E_OUT$E2E_ERR" "internal/server/git.go:27" "git clone --branch v1.6.0 uuid.bundle"

e2e_on client "cd /tmp/e2e-git && git bundle list-heads uuid.bundle" || true
check_contains CLI-GIT-04 "the bundle advertises the tag it was built for" \
	"refs/tags/v1.6.0" "$E2E_OUT" "internal/server/git.go:27" "git bundle list-heads uuid.bundle"

# ---- binary ----------------------------------------------------------------

e2e_on client "curl -sS -o /tmp/e2e-LICENSE -w '%{http_code} %{size_download}' \
	'$E2E_BASE_URL/binaries/hello-binary/1.0.0/LICENSE'" || true
check_matches CLI-BIN-01 "curl downloads a hosted binary artifact" \
	'^200 [0-9]{3,}$' "$E2E_OUT" "internal/server/binary.go:31" "curl $E2E_BASE_URL/binaries/..."

# ---- gomod -----------------------------------------------------------------
#
# On the server, which has the toolchain the client guest deliberately lacks.

E2E_HOST=server
e2e_on server "rm -rf /tmp/e2e-gomod && mkdir -p /tmp/e2e-gomod && cd /tmp/e2e-gomod && \
	/usr/local/go/bin/go mod init e2e >/dev/null 2>&1; \
	GOFLAGS=-mod=mod GOSUMDB=off GONOSUMDB='*' GOPROXY='$E2E_BASE_URL/go' \
	/usr/local/go/bin/go get github.com/google/uuid@v1.6.0 2>&1 | tail -6" || true
check_eq CLI-GOMOD-01 "go get resolves a module through the bodega proxy" 0 "$E2E_RC" \
	"internal/server/gomod.go:13" "GOPROXY=$E2E_BASE_URL/go go get github.com/google/uuid@v1.6.0" "$E2E_RC"

unset server_fpr
