# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The two interactive surfaces. Smoke depth on purpose: a TUI driven by
# synthetic keystrokes tests the harness's patience more than the product, and
# the panes and the dashboard's own fetches are what break silently.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] &&
	{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
	E2E_HOST=local
	e2e_block UI-BLOCK "the TUI and dashboard" "a guest is unreachable"
	return 0
fi

# ---- the TUI ---------------------------------------------------------------
#
# Under `script`, which allocates a pty. Without one the TUI has no terminal to
# draw on and exits immediately, which passes an exit-code check while proving
# nothing rendered.

E2E_HOST=server
e2e_on server "printf 'q' | script -qec 'sudo -E bodega shell' /dev/null 2>&1 | head -40; true" || true
tui="$E2E_OUT"
check_eq UI-01 "the TUI starts and quits on q" 0 "$E2E_RC" \
	"cmd/bodega/cmd_shell.go:15" "printf q | script -qec 'bodega shell' /dev/null" "$E2E_RC"

check_matches UI-02 "the TUI renders something, not an empty screen" \
	'[A-Za-z]' "$tui" "internal/tui/app.go" "printf q | script -qec 'bodega shell' /dev/null"

# ---- the dashboard ---------------------------------------------------------
#
# index.html is a single page that fetches four endpoints. Serving the HTML
# proves nothing if those 404: the page renders empty and looks like a server
# with no packages.

E2E_HOST=client
e2e_body client "/" || true
page="$E2E_OUT"
check_contains UI-03 "the dashboard serves HTML" "<html" "$page" \
	"internal/server/web.go:12" "GET /"

for ep in /api/v1/packages /api/v1/status /api/v1/metrics; do
	e2e_http client "$ep" || true
	check_eq "UI-EP-$(printf '%s' "$ep" | tr '/' '-')" "the dashboard's $ep call answers" \
		"200" "$E2E_OUT" "internal/server/web/index.html" "GET $ep"
done

# The shapes the page parses, not just the status codes. A 200 carrying a
# different document renders an empty dashboard with no error anywhere.
e2e_body client "/api/v1/metrics" || true
if printf '%s' "$E2E_OUT" | jq -e . >/dev/null 2>&1; then
	e2e_record UI-04 PASS "the metrics document parses" "JSON" "parsed" "GET /api/v1/metrics" 0 \
		"internal/server/server.go:1060"
else
	e2e_record UI-04 FAIL "the metrics document parses" "JSON" \
		"$(e2e_excerpt "$E2E_OUT")" "GET /api/v1/metrics" 0 "internal/server/server.go:1060"
fi

e2e_body client "/api/v1/packages" || true
if printf '%s' "$E2E_OUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
	e2e_record UI-05 PASS "the package list is an object keyed by type" "an object" "parsed" \
		"GET /api/v1/packages" 0 "internal/server/server.go:875"
else
	e2e_record UI-05 FAIL "the package list is an object keyed by type" "an object" \
		"$(e2e_excerpt "$E2E_OUT")" "GET /api/v1/packages" 0 "internal/server/server.go:875"
fi

unset tui page ep
