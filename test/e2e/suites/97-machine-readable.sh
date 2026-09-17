# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Which read-only commands can be consumed by something other than a person.
#
# Not a bug list. Each row is one command and whether it has any machine
# readable mode at all, and the count is the case for a global --json. Today
# there are three mechanisms for the same need: a --json flag on `profile
# pins`, a trailing positional `json` on `show repo` and `show pkg`, and a
# positional format on `discover export`. Everything else is a table.
#
# The harness is the evidence: every check in every other suite that parses a
# table instead of a document is parsing something with no contract, and will
# break on a column change nobody considered breaking.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block JSON-BLOCK "machine-readable output" "the server guest is unreachable"
	return 0
fi

E2E_HOST=server

# The commands that already have a mode. These must keep it.
for spec in \
	"profile-pins:profile pins --json" \
	"show-repo:show repo json" \
	"show-pkg:show pkg json" \
	"discover-export:discover export json"; do
	id="${spec%%:*}"
	cmd="${spec#*:}"
	e2e_bodega server "$cmd" || true
	# `jq empty` parses without judging the value. `jq -e .` treats null and
	# false as failure, so an empty export reports as unparseable output when
	# what it emitted was valid JSON.
	if printf '%s' "$E2E_OUT" | jq empty >/dev/null 2>&1; then
		e2e_record "JSON-HAS-$id" PASS "$cmd emits parseable JSON" \
			"a JSON document" "parsed" "bodega $cmd" 0 "cmd/bodega"
	else
		e2e_record "JSON-HAS-$id" FAIL "$cmd emits parseable JSON" \
			"a JSON document" "$(e2e_excerpt "$E2E_OUT$E2E_ERR")" "bodega $cmd" "$E2E_RC" "cmd/bodega"
	fi
done

# The commands that have none. Recorded as SKIP rather than FAIL: each one is a
# deliberate absence today, and the row exists so the count is visible in the
# report instead of living in someone's memory.
for cmd in \
	"build status" "status" "pkg verify" "pkg checksum list" "pkg storage" \
	"audit events" "audit check" "token list" "acl admin list" "acl deny list" \
	"acl proxies list" "identity list" "policy list" "policy check" \
	"policy age list" "policy osv list" "discover list" "discover show" \
	"profile list" "profile show" "profile diff" "profile check" \
	"apt key show" "doctor" "repair check"; do
	id="$(printf '%s' "$cmd" | tr ' ' '-')"
	e2e_skip "JSON-NONE-$id" "\`bodega $cmd\` has no machine-readable mode" \
		"human table only; parsed by position in this harness" "cmd/bodega"
done

unset spec id cmd

# An export is a collection whether or not it holds rows. `null` is valid JSON
# and breaks a consumer written the obvious way: `jq '.[]'` over it is an
# error, and a shell loop over the result iterates nothing without saying why.
# The assertion is on the document's shape rather than on emptiness, because
# this guest's discovery table holds whatever the suites before this one drove
# through the proxy.
e2e_bodega server "discover export json" || true
check_matches JSON-EMPTY-01 "a discover export is a collection, not null" \
	'^\[' "$(printf '%s' "$E2E_OUT" | tr -d '[:space:]')" \
	"cmd/bodega/cmd_discover.go:362" "bodega discover export json"
