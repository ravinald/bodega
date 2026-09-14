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

# README.md: "Checksum verification: computed on first fetch, enforced on
# subsequent fetches." Eight types have been fetched and uploaded by the time
# this runs, so an empty cache means the first half of that sentence did not
# happen and the second half has nothing to enforce against.
check_lacks INT-02 "the checksum cache is not empty after eight types were fetched" \
	"No cached checksums" "$E2E_OUT" "README.md" "bodega pkg checksum list"

# ---- manifest integrity ----------------------------------------------------
#
# Every manifest carries an md5 sidecar. Editing the manifest without the
# sidecar is what a tampering attempt looks like from the filesystem, and
# `pkg verify` is the only thing that reads the pair.

# The sidecar is the thing verification compares against. With none on disk,
# `pkg verify` has nothing to check and its "All manifests passed integrity
# check" is a statement about an empty comparison. README.md advertises
# "Manifest integrity: MD5 verification on every read/write".
e2e_on server "sudo find /var/lib/bodega/manifests -name '*.md5' | wc -l | tr -d ' '" || true
check_ne INT-02b "the manifest store carries md5 sidecars to verify against" \
	"0" "$E2E_OUT" "README.md" "find /var/lib/bodega/manifests -name '*.md5' | wc -l"

# Reported MISSING while the file is on disk, in the same output that then
# declares every manifest passed.
e2e_on server "sudo test -f /var/lib/bodega/manifests/cargo/itoa/manifest.json && echo present || echo absent" || true
cargo_manifest="$E2E_OUT"
e2e_bodega server "pkg verify" || true
if [ "$cargo_manifest" = present ]; then
	check_lacks INT-02c "verify does not report a manifest missing while it is on disk" \
		"cargo    MISSING" "$E2E_OUT" "cmd/bodega/cmd_verify.go:15" \
		"bodega pkg verify with cargo/itoa/manifest.json present"
else
	e2e_skip INT-02c "verify does not report a manifest missing while it is on disk" \
		"no cargo manifest in this store"
fi

e2e_bodega server "pkg verify" || true
check_eq INT-03 "a clean store verifies" 0 "$E2E_RC" \
	"cmd/bodega/cmd_verify.go:15" "bodega pkg verify" "$E2E_RC"

# A run that prints "MISSING (no manifest file)" and then "All manifests passed
# integrity check" at exit 0 says two things that cannot both be true, and the
# reassuring one is last and is what a reader keeps.
if printf '%s' "$E2E_OUT" | grep -q MISSING; then
	check_lacks INT-03a "a verify reporting MISSING does not also declare every manifest passed" \
		"All manifests passed" "$E2E_OUT" "cmd/bodega/cmd_verify.go:15" "bodega pkg verify"
else
	e2e_skip INT-03a "a verify reporting MISSING does not also declare every manifest passed" \
		"no MISSING rows in this store"
fi

# The manifest is a directory per package holding manifest.json, not a flat
# <name>.json. The flat path does not exist, so a sed against it edits nothing
# and `pkg verify` then passes a store nobody tampered with: the check reported
# a working detector while testing no detection at all.
MANIFEST=/var/lib/bodega/manifests/binary/hello-binary/manifest.json
e2e_on server "sudo test -f $MANIFEST" || true
check_eq INT-03b "the manifest the tamper test edits exists" 0 "$E2E_RC" \
	"internal/manifest" "test -f $MANIFEST" "$E2E_RC"

e2e_on server "sudo cp -p $MANIFEST /tmp/e2e-manifest.bak && \
	sudo sed -i 's/\"description\":[^,}]*/\"description\":\"tampered by the e2e harness\"/' \
	$MANIFEST && sudo grep -c tampered $MANIFEST" || true
check_eq INT-03c "the tamper actually changed the file" "1" "$E2E_OUT" \
	"internal/manifest" "sed -i the description, then grep -c tampered"
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

e2e_on server "sudo cp /tmp/e2e-manifest.bak $MANIFEST && \
	sudo chown ${E2E_SERVICE_USER:-bodega} $MANIFEST" || true
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

unset before MANIFEST cargo_manifest
