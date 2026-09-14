# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Host profiles: what a given client is entitled to see. The profile is bound to
# an identity, the identity to the client's address, and every serving surface
# is then asked the same question from that address.
#
# Per surface, because the enforcement is per surface. helm filters its index to
# empty entries rather than refusing, so `helm repo add` still works; apt
# filters the generated Packages index rather than gating the request; the rest
# gate directly. A suite that checked one surface and generalized would report a
# control that is only partly there.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block PROF-BLOCK "host profiles" "a guest is unreachable"
	return 0
fi

E2E_CLIENT_CIDR="${E2E_CLIENT_ADDR:-127.0.0.1}/32"
E2E_HOST=server

# ---- build a profile -------------------------------------------------------

e2e_bodega server "profile remove e2e-profile binary hello-binary --force" >/dev/null 2>&1 || true
e2e_bodega server "profile create e2e-profile --description 'e2e run' --force" || true
check_eq PROF-01 "a profile is created" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go:130" "bodega profile create e2e-profile" "$E2E_RC"

e2e_bodega server "profile list" || true
check_contains PROF-02 "the profile is listed" "e2e-profile" "$E2E_OUT" \
	"cmd/bodega/cmd_profile.go:628" "bodega profile list"

# Closed membership AND expansion block. Closed alone is not a refusal: with
# the default `warn` expansion, `profile show` says so in as many words —
# "every apt request from a bound host is served and recorded as a reach
# outside this class". A suite that set only the membership would measure a
# profile that refuses nothing and read every 200 as a missing control.
for t in binary git apt pypi gomod helm npm cargo; do
	e2e_bodega server "profile set e2e-profile $t --membership closed --expansion block" || true
done
e2e_bodega server "profile show e2e-profile" || true
check_contains PROF-03 "the profile shows closed membership" "closed" "$E2E_OUT" \
	"cmd/bodega/cmd_profile.go:909" "bodega profile set e2e-profile <type> --membership closed"
check_contains PROF-03b "the profile blocks rather than warns on expansion" "block" "$E2E_OUT" \
	"internal/audit/profile.go:44" "bodega profile set e2e-profile <type> --expansion block"

# One entry, so the suite can tell "entitled" from "refused" on the same server.
e2e_bodega server "profile add e2e-profile binary hello-binary --reason 'e2e run'" || true
check_eq PROF-04 "an entry is added to the profile" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go:1128" "bodega profile add e2e-profile binary hello-binary" "$E2E_RC"

# ---- pins ------------------------------------------------------------------

e2e_bodega server "profile pin e2e-profile binary hello-binary 1.0.0 --reason 'e2e run'" || true
check_eq PROF-05 "a version pins with a reason" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go:1170" "bodega profile pin ... --reason" "$E2E_RC"

e2e_bodega server "profile pin e2e-profile binary hello-binary 1.0.0" || true
check_ne PROF-06 "a pin with no reason is refused" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go:1232" "bodega profile pin with no --reason" "$E2E_RC"

e2e_bodega server "profile pins e2e-profile --json" || true
if printf '%s' "$E2E_OUT" | jq -e . >/dev/null 2>&1; then
	e2e_record PROF-07 PASS "profile pins --json emits a document" "JSON" "parsed" \
		"bodega profile pins e2e-profile --json" 0 "cmd/bodega/cmd_profile.go:1497"
else
	e2e_record PROF-07 FAIL "profile pins --json emits a document" "JSON" \
		"$(e2e_excerpt "$E2E_OUT$E2E_ERR")" "bodega profile pins e2e-profile --json" "$E2E_RC" \
		"cmd/bodega/cmd_profile.go:1497"
fi

# --stale exits 1 when any pin is past its review date, which is how a cron job
# reports without parsing anything. A fresh pin has none, so exit 0 is correct.
e2e_bodega server "profile pins e2e-profile --stale" || true
check_eq PROF-08 "--stale exits 0 while no pin is overdue" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go:1449" "bodega profile pins e2e-profile --stale" "$E2E_RC"

e2e_bodega server "profile pin e2e-profile binary hello-binary 1.0.0 --reason 'e2e overdue' --review-after 2020-01-01" || true
e2e_bodega server "profile pins e2e-profile --stale" || true
check_eq PROF-09 "--stale exits 1 once a pin is overdue" 1 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go:1496" "bodega profile pins --stale with a 2020 review date" "$E2E_RC"

# ---- bind it to the client -------------------------------------------------

e2e_bodega server "identity bind cidr $E2E_CLIENT_CIDR e2e-host --comment 'e2e run'" || true
e2e_bodega server "profile bind e2e-profile e2e-host --force" || true
check_eq PROF-10 "the profile binds to the client's identity" 0 "$E2E_RC" \
	"cmd/bodega/cmd_profile.go:782" "bodega profile bind e2e-profile e2e-host" "$E2E_RC"
e2e_reload server || true
sleep 3

# The binding is confirmed before anything is measured through it. Without this
# a refresh that has not landed yet makes every enforcement check below report
# a control that is absent rather than one that is late.
e2e_bodega server "profile show e2e-profile" || true
check_contains PROF-10b "the profile reports a bound host" "e2e-host" "$E2E_OUT" \
	"cmd/bodega/cmd_profile.go:673" "bodega profile show e2e-profile"

# ---- enforcement, per surface ---------------------------------------------

E2E_HOST=client

e2e_http client "/binaries/hello-binary/1.0.0/LICENSE" || true
check_eq PROF-11 "the entitled artifact is still served" "200" "$E2E_OUT" \
	"internal/server/binary.go:71" "GET an entitled binary"

for spec in \
	"git:/git/uuid/uuid-v1.6.0.bundle:internal/server/git.go:44" \
	"npm:/npm/left-pad/-/left-pad-1.3.0.tgz:internal/server/npm.go:59" \
	"cargo:/cargo/itoa/1.0.11/download:internal/server/cargo.go:138" \
	"helm:/helm/charts/podinfo-6.7.0.tgz:internal/server/helm.go:71"; do
	t="${spec%%:*}"
	rest="${spec#*:}"
	path="${rest%%:*}"
	ref="${rest#*:}"
	e2e_http client "$path" || true
	check_ne "PROF-DENY-$t" "a $t artifact outside the profile is refused" \
		"200" "$E2E_OUT" "$ref" "GET $path under a closed profile"
done

# helm is the deliberate exception: the index is filtered to empty rather than
# refused, so `helm repo add` still succeeds against a profile entitling no
# charts. A 403 here would break the client before it could report anything.
e2e_http client "/helm/index.yaml" || true
check_eq PROF-12 "the helm index is filtered rather than refused" "200" "$E2E_OUT" \
	"internal/server/helm.go:22" "GET /helm/index.yaml under a closed profile"

e2e_body client "/helm/index.yaml" || true
check_lacks PROF-13 "the filtered helm index publishes no unentitled chart" \
	"podinfo-6.7.0.tgz" "$E2E_OUT" "internal/server/helm.go:28" "GET /helm/index.yaml"

# apt is filtered at the index too, rather than gated per request.
e2e_body client "/apt/dists/noble/main/binary-arm64/Packages" || true
check_lacks PROF-14 "the filtered apt index publishes no unentitled package" \
	"Package: hello" "$E2E_OUT" "internal/server/apt_profile.go:347" \
	"GET /apt/dists/noble/main/binary-arm64/Packages"

# A refusal that leaves no trail is a refusal nobody can audit.
E2E_HOST=server
e2e_bodega server "audit events --type denied --limit 50" || true
check_contains PROF-15 "a profile refusal is recorded with its reason" \
	"profile" "$E2E_OUT" "internal/server/audit.go:107" "bodega audit events --type denied"

# ---- attestation vs the profile -------------------------------------------
#
# #300: the attestation endpoint answers for a package the profile refuses.

E2E_HOST=client
e2e_http client "/api/v1/packages/helm/podinfo/6.7.0/attestation" || true
check_ne PROF-17 "attestation does not answer for a package the profile refuses" \
	"200" "$E2E_OUT" "internal/server/attestation.go:27" \
	"GET an attestation for an unentitled package"

# ---- restore ---------------------------------------------------------------

E2E_HOST=server
e2e_bodega server "profile unbind e2e-host" || true
e2e_bodega server "identity unbind cidr $E2E_CLIENT_CIDR" || true
e2e_reload server || true
sleep 3
E2E_HOST=client
e2e_http client "/helm/charts/podinfo-6.7.0.tgz" || true
check_eq PROF-18 "unbinding the profile restores full access" "200" "$E2E_OUT" \
	"internal/server/profile.go:83" "GET a chart after the profile is unbound"

unset t spec rest path ref
