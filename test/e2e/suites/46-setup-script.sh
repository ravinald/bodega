# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# The served setup script, run the way an operator runs it: fetched from the
# server by the host it configures, checked against the published digest, and
# executed by that host's own /bin/sh. The Linux client runs it under dash with
# curl; the FreeBSD client runs it with a PATH holding the base system alone,
# so it goes through fetch(1) and FreeBSD's sh.
#
# /client/ answers only a host it can name, so each client guest is bound by
# address before its first case and unbound after its last. The script writes
# /etc/pip.conf and root's ~/.npmrc (the two systems every plan installs on
# both operating systems). A helper on the guest saves both before the first
# case, seeds a known pip.conf so every case has something to replace, and
# restores them after each case, backups included, so the guests end as they
# began.
#
# This suite ships the commit under test to the server itself when shipping is
# on, because `run.sh --suite 46-` skips 10-ship-install.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block SETUP-BLOCK "the served setup script" "the server guest is unreachable"
	return 0
fi

SETUP_SRC="$REPO_ROOT/internal/server/client_setup.sh"
setup_digest="$(shasum -a 256 "$SETUP_SRC" | cut -d ' ' -f 1)"

# ---- ship ------------------------------------------------------------------

E2E_HOST=local
SETUP_BIN="$REPO_ROOT/dist/bodega-linux-arm64"
if [ "${E2E_SHIP:-yes}" = yes ]; then
	e2e_local make -C "$REPO_ROOT" cross CROSS_TARGETS=linux/arm64 || true
	check_eq SETUP-01 "make cross builds the server's arm64 binary" 0 "$E2E_RC" \
		"Makefile" "make cross CROSS_TARGETS=linux/arm64" "$E2E_RC"
	E2E_HOST=server
	if e2e_put server "$SETUP_BIN" /tmp/bodega-under-test &&
		e2e_on server "sudo install -o root -g root -m 0755 /tmp/bodega-under-test /usr/local/bin/bodega" &&
		e2e_restart server; then
		e2e_record SETUP-02 PASS "the server takes the new binary and restarts" "running" "running" "install; systemctl restart bodega" 0 ""
	else
		e2e_record SETUP-02 FAIL "the server takes the new binary and restarts" "running" "$E2E_ERR" "install; systemctl restart bodega" "$E2E_RC" ""
	fi
else
	e2e_skip SETUP-01 "make cross builds the server's arm64 binary" "--no-ship"
	e2e_skip SETUP-02 "the server takes the new binary and restarts" "--no-ship"
fi

E2E_HOST=server
e2e_on server "bodega --version" || true
check_contains SETUP-03 "the server runs the commit under test" "${E2E_COMMIT%-dirty}" "$E2E_OUT" "Makefile" "bodega --version"

e2e_body server /api/v1/status || true
check_eq SETUP-04 "/api/v1/status publishes the digest of the script in this tree" \
	"$setup_digest" "$(printf '%s' "$E2E_OUT" | jq -r '.client_setup_sha256 // empty' 2>/dev/null)" \
	"internal/server/server.go" "GET /api/v1/status | jq .client_setup_sha256"

# ---- guest helper ----------------------------------------------------------
#
# save | seed | restore | state | drop, run as root with HOME=/root. state
# prints one line per path, its digest or "absent", and then how many
# .bodega-* backups exist that the save did not find, which is the number a
# case that wrote nothing has to leave at zero.

SETUP_HELPER=/tmp/bodega-e2e-setup-state.sh
setup_helper_local="$(mktemp "${TMPDIR:-/tmp}/e2e-setup-state.XXXXXX")"
cat >"$setup_helper_local" <<'E2ESETUPSTATE'
#!/bin/sh
set -eu
dir=/var/tmp/bodega-e2e-setup
paths="/etc/pip.conf $HOME/.npmrc"
backups() { for p in $paths; do ls -d "$p".bodega-* 2>/dev/null || true; done; }
case "$1" in
save)
	rm -rf "$dir"
	mkdir -p "$dir"
	i=0
	for p in $paths; do
		i=$((i + 1))
		if [ -e "$p" ]; then cp -p "$p" "$dir/$i"; fi
	done
	backups >"$dir/backups"
	: >"$dir/complete"
	;;
seed)
	printf '[global]\nindex-url = https://pypi.org/simple/\n' >/etc/pip.conf
	rm -f "$HOME/.npmrc"
	;;
restore)
	[ -f "$dir/complete" ] || {
		echo "no complete save at $dir, so nothing was touched" >&2
		exit 1
	}
	i=0
	for p in $paths; do
		i=$((i + 1))
		if [ -e "$dir/$i" ]; then cp -p "$dir/$i" "$p"; else rm -f "$p"; fi
	done
	for b in $(backups); do grep -qxF "$b" "$dir/backups" || rm -f "$b"; done
	;;
state)
	for p in $paths; do
		if [ -e "$p" ]; then printf '%s %s\n' "$p" "$(sha256sum <"$p" | cut -d ' ' -f 1)"; else printf '%s absent\n' "$p"; fi
	done
	n=0
	for b in $(backups); do grep -qxF "$b" "$dir/backups" || n=$((n + 1)); done
	printf 'new-backups %s\n' "$n"
	;;
drop) rm -rf "$dir" ;;
esac
E2ESETUPSTATE

# The tampered case: a stand-in server on the guest's loopback answers the
# plan with the real plan's records, except that pypi's URL points at a second
# stand-in serving the real file with one line appended. The digest in the
# plan is the server's own, so the script meets exactly what a rewritten file
# in transit looks like. nc answers one request each; Content-Length lets the
# client close the connection without waiting on nc.
SETUP_TAMPER=/tmp/bodega-e2e-setup-tamper.sh
setup_tamper_local="$(mktemp "${TMPDIR:-/tmp}/e2e-setup-tamper.XXXXXX")"
cat >"$setup_tamper_local" <<'E2ESETUPTAMPER'
#!/bin/sh
# tamper <base> <script> <path-for-the-script>
set -eu
base=$1
script=$2
runpath=$3
work=$(mktemp -d /tmp/bodega-e2e-tamper.XXXXXX)
trap 'rm -rf "$work"' EXIT
case $(uname -s) in
Linux) q="os=linux&codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release | tr -d '"')" ;;
FreeBSD) q="os=freebsd&abi=$(pkg config abi)" ;;
esac
curl -fsS -o "$work/plan.txt" "$base/client/plan.txt?$q"
url=$(awk -F '\t' '$4 == "pypi" { print $7 }' "$work/plan.txt")
curl -fsS -o "$work/pip.conf" "$url"
printf 'extra-index-url = http://203.0.113.9/simple/\n' >>"$work/pip.conf"
awk -F '\t' -v OFS='\t' '$4 == "pypi" { $7 = "http://127.0.0.1:18462/pip.conf" } 1' "$work/plan.txt" >"$work/fake.txt"
serve() {
	n=$(wc -c <"$1" | tr -d ' ')
	{
		printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %s\r\nConnection: close\r\n\r\n' "$n"
		cat "$1"
	} | timeout 60 nc -l 127.0.0.1 "$2" >/dev/null 2>&1 &
}
serve "$work/fake.txt" 18461
serve "$work/pip.conf" 18462
sleep 1
rc=0
sudo -H env PATH="$runpath" sh "$script" --url http://127.0.0.1:18461 --allow-plaintext --systems pypi,npm --apply || rc=$?
kill $(jobs -p) 2>/dev/null || true
exit "$rc"
E2ESETUPTAMPER

# ---- per guest -------------------------------------------------------------

# setup_guest <alias> <address> <PATH the script runs with> <fetch command>
setup_guest() {
	local g="$1" addr="$2" runpath="$3" getter="$4"
	local tag cidr ident script=/tmp/bodega-e2e-setup.sh run found seeded
	tag="$(printf '%s' "$g" | tr '[:lower:]' '[:upper:]')"
	cidr="$addr/32"
	ident="e2e-setup-$g"
	run="sudo -H env PATH='$runpath' sh $script --url '$E2E_BASE_URL' --allow-plaintext --systems pypi,npm"

	E2E_HOST="$g"
	if ! e2e_on "$g" true 2>/dev/null; then
		e2e_block "SETUP-$tag-BLOCK" "the setup script on $g" "the $g guest is unreachable; power it on"
		return 0
	fi

	E2E_HOST=server
	e2e_bodega server "identity unbind cidr $cidr" >/dev/null 2>&1 || true
	e2e_bodega server "identity bind cidr $cidr $ident --comment 'e2e setup script'" || true
	check_eq "SETUP-$tag-01" "$g binds by address before its first case" 0 "$E2E_RC" \
		"cmd/bodega/cmd_identity.go" "bodega identity bind cidr $cidr $ident" "$E2E_RC"
	e2e_reload server || true
	sleep 2

	E2E_HOST="$g"
	e2e_on "$g" "rm -f $script && $getter $script '$E2E_BASE_URL/client/setup.sh' && sha256sum <$script | cut -d ' ' -f 1" || true
	check_eq "SETUP-$tag-02" "$g fetches the script, and its digest is the published one" \
		"$setup_digest" "$E2E_OUT" "internal/server/client.go" "$getter $script $E2E_BASE_URL/client/setup.sh; sha256sum" "$E2E_RC"

	e2e_on "$g" "env PATH='$runpath' sh -c 'command -v curl || echo none'" || true
	if [ "$runpath" = "${SETUP_BASE_PATH:-}" ]; then
		check_eq "SETUP-$tag-03" "the script's PATH on $g holds the base system and no curl" \
			"none" "$E2E_OUT" "internal/server/client_setup.sh" "env PATH=$runpath command -v curl"
	fi

	e2e_put "$g" "$setup_helper_local" "$SETUP_HELPER" && e2e_put "$g" "$setup_tamper_local" "$SETUP_TAMPER" || true
	e2e_on "$g" "sudo -H sh $SETUP_HELPER save && sudo -H sh $SETUP_HELPER state" || true
	found="$E2E_OUT"
	check_contains "SETUP-$tag-04" "$g's pip and npm files are saved before the first case" \
		"new-backups 0" "$found" "test/e2e/suites/46-setup-script.sh" "sh $SETUP_HELPER save; state"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER seed && sudo -H sh $SETUP_HELPER state" || true
	seeded="$E2E_OUT"

	# dry run: a diff, and nothing written
	e2e_on "$g" "sudo -H sh $SETUP_HELPER seed && $run" || true
	check_eq "SETUP-$tag-10" "a dry run on $g exits 0" 0 "$E2E_RC" \
		"internal/server/client_setup.sh" "sh setup.sh --systems pypi,npm" "$E2E_RC"
	check_contains "SETUP-$tag-11" "the dry run names the identity, profile and binding the server resolved" \
		"Plan for $ident (no profile, matched by cidr:$cidr)" "$E2E_OUT" "internal/server/client_setup.sh" "sh setup.sh"
	check_contains "SETUP-$tag-12" "the dry run prints a unified diff of pip.conf" \
		"+index-url = " "$E2E_OUT" "internal/server/client_setup.sh" "sh setup.sh"
	check_contains "SETUP-$tag-13" "the dry run says it wrote nothing" \
		"Dry run: nothing was written" "$E2E_OUT" "internal/server/client_setup.sh" "sh setup.sh"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER state" || true
	check_eq "SETUP-$tag-14" "after the dry run $g holds what it held before, and no backup" \
		"$seeded" "$E2E_OUT" "internal/server/client_setup.sh" "sh $SETUP_HELPER state"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER restore" || true

	# --apply: a backup of what it replaced, and the plan's files
	e2e_on "$g" "sudo -H sh $SETUP_HELPER seed && $run --apply" || true
	check_eq "SETUP-$tag-20" "--apply on $g exits 0" 0 "$E2E_RC" \
		"internal/server/client_setup.sh" "sh setup.sh --systems pypi,npm --apply" "$E2E_RC"
	check_contains "SETUP-$tag-21" "--apply backs up the pip.conf it replaces" \
		"backed up  /etc/pip.conf -> /etc/pip.conf.bodega-" "$E2E_OUT" "internal/server/client_setup.sh" "sh setup.sh --apply"
	e2e_on "$g" "sudo cat /etc/pip.conf; sudo -H sh -c 'cat \$HOME/.npmrc'; sudo sh -c 'cat /etc/pip.conf.bodega-*'" || true
	check_contains "SETUP-$tag-22" "pip.conf now names bodega's index" \
		"/pypi/simple/" "$E2E_OUT" "internal/clientconf/clientconf.go" "cat /etc/pip.conf"
	check_contains "SETUP-$tag-23" "root's ~/.npmrc is created with bodega's registry" \
		"/npm/" "$E2E_OUT" "internal/clientconf/clientconf.go" "cat ~root/.npmrc"
	check_contains "SETUP-$tag-24" "the backup holds what pip.conf held before" \
		"https://pypi.org/simple/" "$E2E_OUT" "internal/server/client_setup.sh" "cat /etc/pip.conf.bodega-*"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER restore" || true

	# a second --apply changes nothing
	e2e_on "$g" "sudo -H sh $SETUP_HELPER seed && $run --apply >/dev/null && sudo -H sh $SETUP_HELPER state" || true
	local after_first="$E2E_OUT"
	e2e_on "$g" "$run --apply" || true
	check_eq "SETUP-$tag-30" "a second --apply on $g exits 0" 0 "$E2E_RC" \
		"internal/server/client_setup.sh" "sh setup.sh --apply (twice)" "$E2E_RC"
	check_contains "SETUP-$tag-31" "a second --apply reports nothing to change" \
		"Nothing to change" "$E2E_OUT" "internal/server/client_setup.sh" "sh setup.sh --apply (twice)"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER state" || true
	check_eq "SETUP-$tag-32" "a second --apply writes no file and makes no second backup" \
		"$after_first" "$E2E_OUT" "internal/server/client_setup.sh" "sh $SETUP_HELPER state"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER restore" || true

	# a tampered file aborts with nothing written
	e2e_on "$g" "sudo -H sh $SETUP_HELPER seed && sh $SETUP_TAMPER '$E2E_BASE_URL' $script '$runpath'" || true
	check_ne "SETUP-$tag-40" "a tampered file stops the run on $g" 0 "$E2E_RC" \
		"internal/server/client_setup.sh" "sh $SETUP_TAMPER" "$E2E_RC"
	local tamper_err="$E2E_ERR"
	check_contains "SETUP-$tag-41" "the refusal names the system" "pypi: " "$tamper_err" \
		"internal/server/client_setup.sh" "sh $SETUP_TAMPER"
	check_matches "SETUP-$tag-42" "the refusal names both digests" \
		'plan says: +[0-9a-f]{64}' "$tamper_err" "internal/server/client_setup.sh" "sh $SETUP_TAMPER"
	check_matches "SETUP-$tag-43" "the refusal names the file's own digest and the next step" \
		'file is: +[0-9a-f]{64}' "$tamper_err" "internal/server/client_setup.sh" "sh $SETUP_TAMPER"
	check_contains "SETUP-$tag-44" "the refusal says nothing was changed" \
		"nothing on this host was changed" "$tamper_err" "internal/server/client_setup.sh" "sh $SETUP_TAMPER"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER state" || true
	check_eq "SETUP-$tag-45" "after the tampered run $g holds what it held before, and no backup" \
		"$seeded" "$E2E_OUT" "internal/server/client_setup.sh" "sh $SETUP_HELPER state"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER restore" || true

	# the guest as found
	e2e_on "$g" "sudo -H sh $SETUP_HELPER state" || true
	check_eq "SETUP-$tag-90" "$g ends with the files it began with" \
		"$found" "$E2E_OUT" "test/e2e/suites/46-setup-script.sh" "sh $SETUP_HELPER restore; state"
	e2e_on "$g" "sudo -H sh $SETUP_HELPER drop; rm -f $SETUP_HELPER $SETUP_TAMPER $script" || true

	E2E_HOST=server
	e2e_bodega server "identity unbind cidr $cidr" || true
	check_eq "SETUP-$tag-91" "$g's binding is removed after its last case" 0 "$E2E_RC" \
		"cmd/bodega/cmd_identity.go" "bodega identity unbind cidr $cidr" "$E2E_RC"
	e2e_reload server || true
}

SETUP_BASE_PATH=/bin:/sbin:/usr/bin:/usr/sbin
setup_guest client "${E2E_CLIENT_ADDR:-127.0.0.1}" /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "curl -fsS -o"
setup_guest freebsd "${E2E_FREEBSD_ADDR:-127.0.0.1}" "$SETUP_BASE_PATH" "fetch -q -o"

rm -f "$setup_helper_local" "$setup_tamper_local"
unset SETUP_SRC setup_digest SETUP_BIN SETUP_HELPER setup_helper_local SETUP_TAMPER setup_tamper_local SETUP_BASE_PATH
unset -f setup_guest
