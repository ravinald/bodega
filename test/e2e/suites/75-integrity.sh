# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Integrity: the checksum pinned on first fetch, the manifest md5 sidecars, and
# the repair paths. Each check tampers with something and then asks bodega
# whether it noticed. A check that only reads a clean store proves the reader
# works, not the detector.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block INT-BLOCK "integrity" "the server guest is unreachable"
	return 0
fi

E2E_HOST=server

# ---- checksums -------------------------------------------------------------

e2e_bodega server "pkg checksum list" || true
check_eq INT-01 "the checksum cache is readable" 0 "$E2E_RC" \
	"cmd/bodega/cmd_checksum.go:36" "bodega pkg checksum list" "$E2E_RC"

check_contains INT-02 "a checksum was pinned on first fetch" "binary" "$E2E_OUT" \
	"docs/USAGE.md#checksum-verification" "bodega pkg checksum list"

# ---- manifest integrity ----------------------------------------------------
#
# Every manifest carries an md5 sidecar. Editing the manifest without the
# sidecar is what a tampering attempt looks like from the filesystem, and
# `pkg verify` is the only thing that reads the pair.

e2e_bodega server "pkg verify" || true
check_eq INT-03 "a clean store verifies" 0 "$E2E_RC" \
	"cmd/bodega/cmd_verify.go:15" "bodega pkg verify" "$E2E_RC"

e2e_on server "sudo cp /var/lib/bodega/manifests/binary/hello-binary.json /tmp/e2e-manifest.bak && \
	sudo sed -i 's/\"description\": \"[^\"]*\"/\"description\": \"tampered\"/' \
	/var/lib/bodega/manifests/binary/hello-binary.json" || true
e2e_bodega server "pkg verify" || true
check_ne INT-04 "an edited manifest fails verification" 0 "$E2E_RC" \
	"cmd/bodega/cmd_verify.go:15" "bodega pkg verify after editing a manifest" "$E2E_RC"
check_contains INT-05 "the failure names the package that was edited" \
	"hello-binary" "$E2E_OUT$E2E_ERR" "cmd/bodega/cmd_verify.go:15" "bodega pkg verify"

# --break-glass-update-md5 is the documented way back, and it is deliberately
# awkward: it re-stamps the sidecar over whatever the manifest now says.
e2e_bodega server "--break-glass-update-md5 binary" || true
e2e_bodega server "pkg verify" || true
check_eq INT-06 "break-glass restores agreement between manifest and sidecar" 0 "$E2E_RC" \
	"cmd/bodega/main.go:145" "bodega --break-glass-update-md5 binary" "$E2E_RC"

e2e_on server "sudo cp /tmp/e2e-manifest.bak /var/lib/bodega/manifests/binary/hello-binary.json && \
	sudo chown ${E2E_SERVICE_USER:-bodega} /var/lib/bodega/manifests/binary/hello-binary.json" || true
e2e_bodega server "--break-glass-update-md5 binary" || true

# ---- repair ----------------------------------------------------------------
#
# `repair check` is the dry run and must write nothing. Comparing the store
# before and after is the only way to tell a dry run from a quiet fix.

e2e_on server "sudo find /var/lib/bodega -type f | sort | md5sum" || true
before="$E2E_OUT"
e2e_bodega server "repair check" || true
check_eq INT-07 "repair check runs" 0 "$E2E_RC" \
	"cmd/bodega/cmd_repair.go:19" "bodega repair check" "$E2E_RC"
e2e_on server "sudo find /var/lib/bodega -type f | sort | md5sum" || true
check_eq INT-08 "repair check changes nothing on disk" "$before" "$E2E_OUT" \
	"cmd/bodega/cmd_repair.go:36" "find /var/lib/bodega -type f | md5sum, before and after"

e2e_bodega server "repair keys --dry-run" || true
check_eq INT-09 "repair keys --dry-run runs" 0 "$E2E_RC" \
	"cmd/bodega/cmd_repair_keys.go:92" "bodega repair keys --dry-run" "$E2E_RC"

# ---- storage placement -----------------------------------------------------

e2e_bodega server "pkg storage binary hello-binary" || true
check_eq INT-10 "the destination backend for the next write is reportable" 0 "$E2E_RC" \
	"cmd/bodega/cmd_storage.go:16" "bodega pkg storage binary hello-binary" "$E2E_RC"

e2e_bodega server "build status" || true
check_lacks INT-11 "nothing is missing from the backend" "MISSING" "$E2E_OUT" \
	"cmd/bodega/cmd_status.go:15" "bodega build status"

unset before
