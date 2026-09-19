# shellcheck shell=bash
#
# The package set every suite shares, as importable PackageManifest documents.
# `pkg create` prompts for every field, so automation goes through
# `pkg import` instead.
#
# Every entry names a small, public, credential-free upstream and pins an exact
# version. A fixture needing a login fails as a 404 and reads as a bodega bug,
# and a floating version turns a failure into "which upstream release broke
# this", an answer the report never carries.
#
# npm and cargo are pairs rather than single packages, emitted as the JSON
# array 'pkg import' already accepts. Both were dependency-free leaves until
# B72 — left-pad and itoa — which is why no client check had ever observed a
# hosted package resolving with none of its dependencies. The pair is the
# smallest fixture that can see it: color-convert@2.0.1 needs color-name
# ~1.1.4, form_urlencoded@1.2.2 needs percent-encoding ^2.3.0, and each
# dependency is itself a leaf, so the closure ends after one hop and the check
# fails for one reason only.
#
# e2e_fixture_name and e2e_fixture_version name the first of each pair. A suite
# walking the types measures the dependent package; the leaf is there to be
# resolved, not asserted on.

[ -n "${E2E_LIB_FIXTURES:-}" ] && return 0
E2E_LIB_FIXTURES=1

# manifest.AllTypes order, so a suite walking these reports in the order the
# product builds them. Hosted entries, every one: the proxy-mode fixtures are
# named apart below and deliberately absent here, because a suite walking this
# list is walking the build pipeline and a proxy-mode entry builds nothing.
export E2E_FIXTURE_TYPES
E2E_FIXTURE_TYPES="binary git apt pypi gomod helm npm cargo"

# e2e_fixture <type> [apt-version] — one PackageManifest on stdout.
#
# <type> is one of E2E_FIXTURE_TYPES, or one of npm-proxy, cargo-proxy and
# gomod-proxy for the proxy-mode entries at the bottom of the case.
e2e_fixture() {
	case "$1" in
	binary) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "hello-binary",
  "type": "binary",
  "description": "e2e fixture: a small static file over https",
  "versions": [
    {
      "version": "1.0.0",
      "url": "https://raw.githubusercontent.com/google/uuid/v1.6.0/LICENSE",
      "filename": "LICENSE"
    }
  ]
}
JSON
	git) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "uuid",
  "type": "git",
  "description": "e2e fixture: a small repository with a tagged release",
  "versions": [
    {
      "version": "v1.6.0",
      "url": "https://github.com/google/uuid.git",
      "ref": "v1.6.0",
      "source": "clone"
    }
  ]
}
JSON
	pypi) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "six",
  "type": "pypi",
  "description": "e2e fixture: a pure-python wheel with no dependencies",
  "versions": [{ "version": "1.16.0" }]
}
JSON
	gomod) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "github.com/google/uuid",
  "type": "gomod",
  "description": "e2e fixture: a module with no dependencies",
  "versions": [{ "version": "v1.6.0" }]
}
JSON
	helm) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "podinfo",
  "type": "helm",
  "description": "e2e fixture: a small chart served over https",
  "versions": [
    {
      "version": "6.7.0",
      "url": "https://stefanprodan.github.io/podinfo/podinfo-6.7.0.tgz"
    }
  ]
}
JSON
	npm) cat <<'JSON' ;;
[
  {
    "config_version": 1,
    "name": "color-convert",
    "type": "npm",
    "description": "e2e fixture: a package declaring exactly one dependency",
    "versions": [{ "version": "2.0.1" }]
  },
  {
    "config_version": 1,
    "name": "color-name",
    "type": "npm",
    "description": "e2e fixture: the leaf color-convert@2.0.1 depends on",
    "versions": [{ "version": "1.1.4" }]
  }
]
JSON
	cargo) cat <<'JSON' ;;
[
  {
    "config_version": 1,
    "name": "form_urlencoded",
    "type": "cargo",
    "description": "e2e fixture: a crate declaring exactly one dependency",
    "versions": [{ "version": "1.2.2" }]
  },
  {
    "config_version": 1,
    "name": "percent-encoding",
    "type": "cargo",
    "description": "e2e fixture: the leaf form_urlencoded@1.2.2 depends on",
    "versions": [{ "version": "2.3.2" }]
  }
]
JSON
	apt)
		# The version is resolved on the guest rather than pinned here: an apt
		# version is a property of the suite the guest tracks, and a constant
		# would go stale on the next point release and fail as "no candidate".
		printf '{
  "config_version": 1,
  "name": "hello",
  "type": "apt",
  "description": "e2e fixture: the smallest package in the archive",
  "versions": [{ "version": "%s", "source_name": "hello" }]
}\n' "${2:?apt fixture needs a version}"
		;;
	# ---- proxy mode ---------------------------------------------------------
	#
	# The eight names above are hosted entries: none sets `mode`, so
	# EffectiveMode returns "hosted" for every one of them and every proxy
	# check in the suite reaches the serving code through "no manifest names
	# this". These three are the other half of that distinction — an entry a
	# manifest does name, whose bytes come from upstream — and the serving code
	# reads them on a different branch.
	#
	# Named apart rather than selected by a second argument, because apt's
	# second argument is already its version, and because a mode argument
	# threaded through every call site would leave the mode of a given call
	# readable only at the caller. `npm-proxy` says what it emits where it is
	# written. E2E_FIXTURE_TYPES keeps naming exactly the eight the pipeline
	# suites walk, so nothing here changes what 30-pipeline imports.
	#
	# Each upstream is one 65-proxy.sh already depends on, so a proxy-mode
	# fixture adds no new way for the suite to fail on somebody else's outage.
	npm-proxy) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "is-number",
  "type": "npm",
  "description": "e2e fixture: a proxy-mode entry, fetched from upstream on miss",
  "versions": [{ "version": "7.0.0", "mode": "proxy" }]
}
JSON
	cargo-proxy) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "anyhow",
  "type": "cargo",
  "description": "e2e fixture: a proxy-mode entry, fetched from upstream on miss",
  "versions": [{ "version": "1.0.86", "mode": "proxy" }]
}
JSON
	gomod-proxy) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "github.com/pkg/errors",
  "type": "gomod",
  "description": "e2e fixture: a proxy-mode entry, fetched from upstream on miss",
  "versions": [{ "version": "v0.9.1", "mode": "proxy" }]
}
JSON
	*)
		printf 'e2e_fixture: no fixture for type %q\n' "$1" >&2
		return 2
		;;
	esac
}

e2e_fixture_name() {
	case "$1" in
	binary) printf 'hello-binary' ;;
	git) printf 'uuid' ;;
	apt) printf 'hello' ;;
	pypi) printf 'six' ;;
	gomod) printf 'github.com/google/uuid' ;;
	helm) printf 'podinfo' ;;
	npm) printf 'color-convert' ;;
	cargo) printf 'form_urlencoded' ;;
	npm-proxy) printf 'is-number' ;;
	cargo-proxy) printf 'anyhow' ;;
	gomod-proxy) printf 'github.com/pkg/errors' ;;
	*) return 2 ;;
	esac
}

e2e_fixture_version() {
	case "$1" in
	binary) printf '1.0.0' ;;
	git) printf 'v1.6.0' ;;
	apt) printf '%s' "${E2E_APT_VERSION:-}" ;;
	pypi) printf '1.16.0' ;;
	gomod) printf 'v1.6.0' ;;
	helm) printf '6.7.0' ;;
	npm) printf '2.0.1' ;;
	cargo) printf '1.2.2' ;;
	npm-proxy) printf '7.0.0' ;;
	cargo-proxy) printf '1.0.86' ;;
	gomod-proxy) printf 'v0.9.1' ;;
	*) return 2 ;;
	esac
}
