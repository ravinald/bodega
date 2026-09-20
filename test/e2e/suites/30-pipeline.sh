# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The pipeline, per type: import a manifest, fetch, run, package, upload, and
# confirm the store agrees with the manifest afterwards.
#
# Every type gets the same five stages and the same assertions, so a type that
# is quietly missing a stage shows up as a gap in one column rather than as an
# absent suite nobody notices.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"
# shellcheck source=../lib/fixtures.sh
. "${E2E_DIR:?}/lib/fixtures.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block PIPE-BLOCK "the build pipeline" "the server guest is unreachable"
	return 0
fi

E2E_HOST=server

# ---- a clean store ---------------------------------------------------------
#
# Every later suite reads what this one builds, so it starts from nothing. A
# store carrying an earlier run's entries turns "upload wrote one file" into a
# count nobody can predict.
e2e_reset_store server || true
e2e_restart server || true

# The apt version is a property of the suite the guest tracks, so it is read
# rather than pinned. A constant goes stale at the next point release and fails
# as "no candidate", which reads as a bodega defect.
e2e_apt_version >/dev/null
check_matches PIPE-01 "the guest offers an apt candidate for the fixture" \
	'^[0-9]' "${E2E_APT_VERSION:-none}" "test/e2e/README.md" "apt-cache policy hello"

# ---- import ----------------------------------------------------------------

for t in $E2E_FIXTURE_TYPES; do
	fx="$(e2e_fixture "$t" "$E2E_APT_VERSION")"
	e2e_on server "cat > /tmp/e2e-fx-$t.json <<'E2EFIXTURE'
$fx
E2EFIXTURE" || true
	e2e_bodega server "pkg import /tmp/e2e-fx-$t.json" || true
	check_contains "PIPE-IMPORT-$t" "$t imports from a manifest file" \
		"Imported $t/$(e2e_fixture_name "$t")" "$E2E_OUT$E2E_ERR" \
		"cmd/bodega/cmd_import.go:29" "bodega pkg import /tmp/e2e-fx-$t.json" "$E2E_RC"
done

# An entry pinning nothing cannot be dated, and the age gate used to try: every
# registry it reads composes the version into the URL it queries, so "*" resolved
# to https://pypi.org/pypi/<dist>/*/json, 404d, and warned. Cataloging 146
# distributions produced 146 of those lines against entries that were all
# correct, which reads to a new operator as an import that half failed.
#
# Measured on stderr rather than on the exit code: the gate warns, so the import
# succeeds either way and a check on the status measures nothing.

# The gate short-circuits to pass when no age policy exists for the type, so
# without one this check would pass against the tree it exists to fail.
e2e_bodega server "policy age list" || true
age_policy="$E2E_OUT"

e2e_on server "cat > /tmp/e2e-agestar.json <<'E2EFIXTURE'
{
  \"config_version\": 1,
  \"name\": \"e2e-age-star\",
  \"type\": \"pypi\",
  \"description\": \"e2e fixture: an open proxy entry, which nothing can date\",
  \"versions\": [{ \"version\": \"*\", \"mode\": \"proxy\", \"url\": \"https://pypi.org\" }]
}
E2EFIXTURE" || true
e2e_bodega server "pkg import /tmp/e2e-agestar.json" || true
case "$age_policy" in
*pypi*)
	check_lacks PIPE-AGE-STAR "an entry pinning nothing is passed by the age gate, not dated" \
		"upstream timestamp unavailable" "$E2E_OUT$E2E_ERR" \
		"internal/policy/age.go:93; the guard already passes an empty Version for this reason, and \"*\" is as undateable" \
		"bodega pkg import an entry with version \"*\""
	;;
*)
	e2e_skip PIPE-AGE-STAR "an entry pinning nothing is passed by the age gate, not dated" \
		"no pypi row in \"policy age list\", so the gate returns before it reads the version" "internal/policy/age.go:80"
	;;
esac

e2e_bodega server "pkg delete pypi e2e-age-star" || true
unset age_policy

# ---- one cascade from an un-fetched store ----------------------------------
#
# The stage loop below runs `build fetch` first, so by the time it reaches
# `build upload` every artifact is already on disk and the cascade inside upload
# has nothing left to run. That cascade is the advertised one-command install
# and it carries its own builder config, so the digest it pins on a first fetch
# is only exercised when nothing has been fetched yet.
#
# binary is the type whose fetch is the whole pipeline, so one cascade covers
# fetch through upload without leaving the other seven in a state the loop has
# to account for.

e2e_bodega server "build upload binary" || true
check_eq PIPE-CASCADE "build upload cascades from an un-fetched store" 0 "$E2E_RC" \
	"cmd/bodega/cmd_upload.go:51" "bodega build upload binary" "$E2E_RC"

e2e_bodega server "pkg checksum list --type binary --name hello-binary" || true
check_lacks PIPE-CASCADE-PIN "the cascade pinned the digest it fetched" \
	"No cached checksums" "$E2E_OUT" "internal/builder/checksum.go:132" \
	"bodega pkg checksum list --type binary --name hello-binary"

# ---- stages ----------------------------------------------------------------
#
# `build upload` cascades every earlier stage, so running them separately is
# what tells you which one a type is missing. A single cascaded upload would
# report one verdict for five questions.

for stage in fetch run package upload; do
	for t in $E2E_FIXTURE_TYPES; do
		e2e_bodega server "build $stage $t" || true
		if [ "$E2E_RC" -eq 0 ]; then
			e2e_record "PIPE-$(printf '%s' "$stage" | tr '[:lower:]' '[:upper:]')-$t" PASS \
				"$t survives build $stage" "exit 0" "exit 0" "bodega build $stage $t" 0 ""
		else
			e2e_record "PIPE-$(printf '%s' "$stage" | tr '[:lower:]' '[:upper:]')-$t" FAIL \
				"$t survives build $stage" "exit 0" "$(e2e_excerpt "$E2E_OUT$E2E_ERR")" \
				"bodega build $stage $t" "$E2E_RC" ""
		fi
	done
done

# ---- what the store says ---------------------------------------------------

e2e_bodega server "build status" || true
check_lacks PIPE-02 "no entry is reported missing from the backend after upload" \
	"MISSING" "$E2E_OUT" "cmd/bodega/cmd_status.go:15" "bodega build status"

e2e_bodega server "pkg verify" || true
check_eq PIPE-03 "every manifest matches its md5 sidecar" 0 "$E2E_RC" \
	"cmd/bodega/cmd_verify.go:15" "bodega pkg verify" "$E2E_RC"

e2e_bodega server "audit check" || true
check_eq PIPE-04 "every recorded dependency is satisfied" 0 "$E2E_RC" \
	"cmd/bodega/cmd_audit_check.go:16" "bodega audit check" "$E2E_RC"

# ---- the version that was asked for is the version that landed -------------
#
# An entry pinning one version and a store holding another is a supply-chain
# claim that does not hold: the manifest is the record of what was approved.

# Read from the stored artifact, never from the manifest. Asking `show pkg` what
# version it holds and comparing that to the fixture compares the manifest with
# itself and passes whatever landed on disk: the pypi fetch stored a 1.17.0
# wheel against a manifest pinning 1.16.0 and a manifest-side check called it
# correct.
for t in $E2E_FIXTURE_TYPES; do
	want="$(e2e_fixture_version "$t")"
	case "$t" in
	binary) glob="/var/lib/bodega/binaries/hello-binary/*" ;;
	git) glob="/var/lib/bodega/repos/uuid/*.bundle" ;;
	apt) glob="/var/lib/bodega/packages/apt/pool/main/h/hello/*.deb" ;;
	pypi) glob="/var/lib/bodega/pypi/wheels/six-*.whl" ;;
	gomod) glob="/var/lib/bodega/gomod/github.com/google/uuid/@v/*.zip" ;;
	helm) glob="/var/lib/bodega/charts/podinfo-*.tgz" ;;
	npm) glob="/var/lib/bodega/npm/color-convert/*.tgz" ;;
	cargo) glob="/var/lib/bodega/cargo/crates/form_urlencoded-*.crate" ;;
	esac
	e2e_on server "sudo sh -c 'ls -d $glob 2>/dev/null' | head -3" || true
	check_contains "PIPE-VERSION-$t" "the $t artifact on disk carries the pinned version" \
		"$want" "${E2E_OUT:-nothing stored}" "internal/manifest/types.go:105" "ls $glob"
done

unset t fx stage want glob
