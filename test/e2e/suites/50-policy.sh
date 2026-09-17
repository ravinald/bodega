# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The supply-chain controls a fresh install ships with, and the ones it does
# not. THREAT_MODEL.md and QUICKSTART §13 both make claims about the default
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
	"docs/QUICKSTART.md:238" "bodega policy age list"
check_contains POL-02 "pypi carries the seeded publish-age gate" "pypi" "$ages" \
	"docs/QUICKSTART.md:238" "bodega policy age list"
check_contains POL-03 "the seeded action is warn, not block" "warn" "$ages" \
	"docs/QUICKSTART.md:248" "bodega policy age list"

# The ecosystems with no upstream publish timestamp must be refused rather than
# accepted and silently never evaluated.
for eco in apt binary git helm; do
	e2e_bodega server "policy age set $eco 7d warn" || true
	check_ne "POL-AGE-$eco" "an age gate on $eco is refused" 0 "$E2E_RC" \
		"docs/QUICKSTART.md:247" "bodega policy age set $eco 7d warn" "$E2E_RC"
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
