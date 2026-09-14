# shellcheck shell=bash
# shellcheck disable=SC2016  # backticks below are markdown, not command substitution
#
# findings.jsonl -> report.md. Nothing here talks to a guest; the report is
# rendered from the file, so a run can be re-rendered after the fact and the
# renderer can be tested with no VM.

# Sourcing is idempotent: run.sh loads the libs once, and each suite loads them
# again so a suite can be linted and run on its own. A second load must not
# reset the counters.
[ -n "${E2E_LIB_REPORT:-}" ] && return 0
E2E_LIB_REPORT=1

e2e_report() {
	local findings="$1" out="$2" run_id="$3"

	{
		printf '# bodega e2e run %s\n\n' "$run_id"
		printf '| field | value |\n|---|---|\n'
		printf '| commit | `%s` |\n' "$(jq -r 'first(.commit) // "unknown"' "$findings" 2>/dev/null || echo unknown)"
		printf '| started | %s |\n' "$(jq -rs 'if length>0 then .[0].ts else "-" end' "$findings")"
		printf '| finished | %s |\n' "$(jq -rs 'if length>0 then .[-1].ts else "-" end' "$findings")"
		printf '| checks | %s |\n\n' "$(jq -rs 'length' "$findings")"

		printf '## Verdicts\n\n'
		printf '| verdict | count |\n|---|---:|\n'
		jq -rs '
			group_by(.verdict) | map({v:.[0].verdict, n:length})
			| sort_by(.v) | .[] | "| \(.v) | \(.n) |"' "$findings"
		printf '\n'

		printf '## By suite\n\n'
		printf '| suite | PASS | FAIL | XFAIL | XPASS | SKIP | BLOCKED |\n|---|---:|---:|---:|---:|---:|---:|\n'
		jq -rs '
			group_by(.suite) | sort_by(.[0].suite) | .[]
			| . as $rows
			| ($rows[0].suite) as $s
			| def n($v): [$rows[] | select(.verdict==$v)] | length;
			  "| \($s) | \(n("PASS")) | \(n("FAIL")) | \(n("XFAIL")) | \(n("XPASS")) | \(n("SKIP")) | \(n("BLOCKED")) |"' "$findings"
		printf '\n'

		local nfail
		nfail="$(jq -rs '[.[] | select(.verdict=="FAIL")] | length' "$findings")"
		if [ "$nfail" -gt 0 ]; then
			printf '## Failures\n\n'
			printf 'Each of these is a candidate issue. `run.sh --file %s` opens one per entry.\n\n' "$run_id"
			jq -rs '.[] | select(.verdict=="FAIL") |
				"### \(.id) — \(.title)\n\n" +
				"- host: `\(.host)`  ·  suite: `\(.suite)`  ·  rc: `\(.rc)`\n" +
				(if .ref != "" then "- ref: `\(.ref)`\n" else "" end) +
				"- command:\n\n```\n\(.cmd)\n```\n\n" +
				"- expected: `\(.expected)`\n" +
				"- actual:\n\n```\n\(.actual)\n```\n"' "$findings"
		fi

		local nxpass
		nxpass="$(jq -rs '[.[] | select(.verdict=="XPASS")] | length' "$findings")"
		if [ "$nxpass" -gt 0 ]; then
			printf '## Fixed (XPASS)\n\n'
			printf 'These map to an open issue and now pass. Close the issue, drop the row from `known-issues.tsv`.\n\n'
			jq -rs '.[] | select(.verdict=="XPASS") | "- **\(.id)** #\(.issue) — \(.title)"' "$findings"
			printf '\n'
		fi

		local nxfail
		nxfail="$(jq -rs '[.[] | select(.verdict=="XFAIL")] | length' "$findings")"
		if [ "$nxfail" -gt 0 ]; then
			printf '## Known failures (XFAIL)\n\n'
			jq -rs '.[] | select(.verdict=="XFAIL") | "- **\(.id)** #\(.issue) — \(.title)"' "$findings"
			printf '\n'
		fi

		local nblock
		nblock="$(jq -rs '[.[] | select(.verdict=="BLOCKED")] | length' "$findings")"
		if [ "$nblock" -gt 0 ]; then
			printf '## Blocked\n\n'
			printf 'A prerequisite failed, so these never ran. They are not passes and not failures.\n\n'
			jq -rs '.[] | select(.verdict=="BLOCKED") | "- **\(.id)** — \(.title): \(.actual)"' "$findings"
			printf '\n'
		fi

		local nskip
		nskip="$(jq -rs '[.[] | select(.verdict=="SKIP")] | length' "$findings")"
		if [ "$nskip" -gt 0 ]; then
			printf '## Skipped\n\n'
			jq -rs '.[] | select(.verdict=="SKIP") | "- **\(.id)** — \(.title): \(.actual)"' "$findings"
			printf '\n'
		fi
	} >"$out"
}

# e2e_file_issues <findings> <run-id> [--dry-run]
#
# One issue per FAIL that known-issues.tsv does not already map. The check id
# goes in the title and the body so the next run's XFAIL mapping is a one-line
# append to the TSV.
e2e_file_issues() {
	local findings="$1" run_id="$2" dry="${3:-}"
	local id title suite host cmd expected actual ref sev body num

	jq -rs '.[] | select(.verdict=="FAIL") | tojson | @base64' "$findings" | while IFS= read -r row; do
		local json
		json="$(printf '%s' "$row" | base64 --decode)"
		id="$(printf '%s' "$json" | jq -r .id)"
		title="$(printf '%s' "$json" | jq -r .title)"
		suite="$(printf '%s' "$json" | jq -r .suite)"
		host="$(printf '%s' "$json" | jq -r .host)"
		cmd="$(printf '%s' "$json" | jq -r .cmd)"
		expected="$(printf '%s' "$json" | jq -r .expected)"
		actual="$(printf '%s' "$json" | jq -r .actual)"
		ref="$(printf '%s' "$json" | jq -r .ref)"
		sev="${E2E_SEVERITY:-M}"

		body="$(printf 'Found by `test/e2e` check `%s` (suite `%s`) on run `%s`, commit `%s`, host `%s`.\n\n**Expected**\n\n```\n%s\n```\n\n**Actual**\n\n```\n%s\n```\n\n**Reproduce**\n\n```\n%s\n```\n%s' \
			"$id" "$suite" "$run_id" "$(printf '%s' "$json" | jq -r .commit)" "$host" \
			"$expected" "$actual" "$cmd" \
			"$([ -n "$ref" ] && printf '\nRef: `%s`\n' "$ref")")"

		if [ "$dry" = "--dry-run" ]; then
			printf 'would file: [%s] %s\n' "$id" "$title"
			continue
		fi

		num="$(gh issue create \
			--title "$id: $title" \
			--body "$body" \
			--label caveat \
			--label "sev:$sev" \
			2>&1 | tail -1)"
		printf 'filed %s  <- %s\n' "$num" "$id"
		printf '%s\t%s\t%s\n' "$id" "${num##*/}" "filed from run $run_id" >>"$E2E_KNOWN_FILE"
	done
}
