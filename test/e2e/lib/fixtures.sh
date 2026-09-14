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

[ -n "${E2E_LIB_FIXTURES:-}" ] && return 0
E2E_LIB_FIXTURES=1

# manifest.AllTypes order, so a suite walking these reports in the order the
# product builds them.
export E2E_FIXTURE_TYPES
E2E_FIXTURE_TYPES="binary git apt pypi gomod helm npm cargo"

# e2e_fixture <type> [apt-version] — one PackageManifest on stdout.
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
{
  "config_version": 1,
  "name": "left-pad",
  "type": "npm",
  "description": "e2e fixture: a single-file package with no dependencies",
  "versions": [{ "version": "1.3.0" }]
}
JSON
	cargo) cat <<'JSON' ;;
{
  "config_version": 1,
  "name": "itoa",
  "type": "cargo",
  "description": "e2e fixture: a crate with no dependencies",
  "versions": [{ "version": "1.0.11" }]
}
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
	npm) printf 'left-pad' ;;
	cargo) printf 'itoa' ;;
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
	npm) printf '1.3.0' ;;
	cargo) printf '1.0.11' ;;
	*) return 2 ;;
	esac
}
