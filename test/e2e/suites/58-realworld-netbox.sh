# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# A real application through bodega: NetBox v4.7.2, installed standalone on the
# client with the client's egress locked to the server, then the
# observe-then-restrict workflow run on what it fetched.
#
#   0  egress    the client reaches the server and nothing else
#   1  log-only  observe, open admission, a closed profile at expansion warn:
#                every fetch is served and every one writes a denied row
#   2  learn     the rows become the profile; expansion block, pypi pinned
#   3  reinstall from nothing, under the learned profile, with no denial
#   4  refusal   a neighbor application and an apt package outside the set
#   5  pin       a newer Django than the one NetBox pins
#   6  outage    the server loses every upstream; the reinstall still works
#   7  restore   the state the suite found
#
# Every other suite installs one leaf package per type. A leaf that installs
# says nothing about a 100-distribution pip closure, an apt transaction with
# build dependencies and a git release tarball meeting one server in one
# posture, or about whether a profile learned from that install admits it again
# and refuses its neighbors. The lock is what makes the install evidence: with
# no route but bodega, a package that installed came through bodega, and a
# phase whose drop counter moved tried to go around it.
#
# State the suite changes is put back by nbx_cleanup, from the EXIT trap as well
# as from the end of the run, so an interrupted run leaves no lock, no binding,
# no profile entry and no NetBox behind. Catalog entries it adds to reach
# NetBox's closure (one git entry, a proxy-mode pypi entry per distribution)
# stay: they are what a second run starts from, and removing them would turn
# every run into the cold bootstrap.

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"
# shellcheck source=../lib/bodega.sh
. "${E2E_DIR:?}/lib/bodega.sh"
# shellcheck source=../lib/egress.sh
. "${E2E_DIR:?}/lib/egress.sh"

NBX_PROFILE=e2e-netbox
NBX_IDENTITY=e2e-netbox-host
NBX_TAG=v4.7.2
NBX_SRC_DIR=netbox-4.7.2
NBX_ROOT=/opt/netbox
NBX_WORK=/var/tmp/bodega-e2e-netbox
NBX_TYPES="apt pypi git"
# The packages NetBox's installation guide names, in its order.
NBX_APT="postgresql redis-server python3 python3-pip python3-venv python3-dev build-essential libxml2-dev libxslt1-dev libffi-dev libpq-dev libssl-dev zlib1g-dev"
# An apt transaction, a migrate and a cold pip resolve each outlast the
# harness's 300s ssh default by a wide margin on these guests.
NBX_LONG="${NBX_LONG:-2400}"
# The cold catalog bootstrap adds roughly one distribution per round; NetBox's
# closure is about 100.
NBX_CATALOG_ROUNDS="${NBX_CATALOG_ROUNDS:-150}"
# F67's deadman clears a lock 30 minutes after it was applied. A phase that
# runs longer re-applies it well inside that.
NBX_RELOCK_SECS=1200
NBX_REASON="e2e suite 58: NetBox v4.7.2 phase 1 install"

# ---- state the cleanup reads ------------------------------------------------
#
# Each flag is set the moment the change it names is made, and nbx_cleanup
# undoes only what a flag says happened. A run blocked in preflight therefore
# touches nothing, and a profile somebody else created is never emptied.

nbx_cleaned=no
nbx_locked_client=no
nbx_locked_server=no
nbx_config_saved=no
nbx_profile_made=no
nbx_cidr_bound=no
nbx_client_configured=no
nbx_netbox_touched=no
nbx_prior_modes=""
nbx_prior_discover=""
nbx_drops_base=0
nbx_drops_acc=0
nbx_locked_at=0

nbx_host="${E2E_BASE_URL#*://}"
nbx_host="${nbx_host%%[:/]*}"
nbx_pip_env="PIP_TRUSTED_HOST=$nbx_host PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1"

# ---- helpers -----------------------------------------------------------------

nbx_phase() { printf '\n  phase %s\n' "$1"; }

# nbx_long <alias> <command> — e2e_on with the install-sized timeout.
nbx_long() { E2E_SSH_TIMEOUT="$NBX_LONG" e2e_on "$1" "$2"; }

# nbx_tail — the last lines of the previous command's output, for a record.
nbx_tail() { e2e_excerpt "$(printf '%s\n%s' "$E2E_OUT" "$E2E_ERR" | tail -n 25)"; }

# nbx_rc <id> <title> <ref> <cmd> — PASS on exit 0, FAIL carrying the output.
nbx_rc() {
	if [ "$E2E_RC" = 0 ]; then
		e2e_record "$1" PASS "$2" "exit 0" "exit 0" "$4" 0 "$3"
	else
		e2e_record "$1" FAIL "$2" "exit 0" "$(nbx_tail)" "$4" "$E2E_RC" "$3"
	fi
}

# nbx_rc_fails <id> <title> <ref> <cmd> — PASS on a non-zero exit.
nbx_rc_fails() {
	if [ "$E2E_RC" != 0 ]; then
		e2e_record "$1" PASS "$2" "non-zero exit" "exit $E2E_RC" "$4" "$E2E_RC" "$3"
	else
		e2e_record "$1" FAIL "$2" "non-zero exit" "$(nbx_tail)" "$4" 0 "$3"
	fi
}

# nbx_canon — PEP 503 names, one per line in and out, sorted and unique.
nbx_canon() { tr '[:upper:]' '[:lower:]' | sed -E 's/[-_.]+/-/g' | sed '/^$/d' | sort -u; }

# nbx_safe <word> — a package name or version that may be spliced into a
# command run as root on the server. Names arrive from request paths through
# the discovery table, so one carrying shell syntax is refused rather than run.
nbx_safe() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+:~-]*$ ]]; }

# nbx_now <alias> — the guest's UTC clock. Rows are stamped by the server, so
# a window over them is read off the server's clock rather than this one.
nbx_now() {
	e2e_on "$1" "date -u +%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1 || true
	printf '%s' "${E2E_OUT:-1970-01-01T00:00:00Z}"
}

# The jq that reads a discovery export. last_seen arrives as RFC 3339 with
# fractional seconds and whatever zone the sink wrote; fromdateiso8601 takes
# neither, so both are normalized before a row is placed in a window.
# shellcheck disable=SC2016  # jq program, not shell
NBX_JQ_EPOCH='def epoch: sub("\\.[0-9]+"; "")
	| if test("Z$") then fromdateiso8601
	  else capture("^(?<t>.*)(?<s>[+-])(?<h>[0-9]{2}):(?<m>[0-9]{2})$")
	    | ((.t + "Z") | fromdateiso8601)
	      - ((if .s == "+" then 1 else -1 end) * ((.h | tonumber) * 3600 + (.m | tonumber) * 60))
	  end;'

# nbx_rows <type> <decision> <since> [until] — the export's rows of that
# decision from the client's address inside the window, as a JSON array.
#
# discover export rather than discover list: list aggregates to one bucket per
# pattern and has no machine-readable mode, and the bucket carries neither the
# client nor the package name.
nbx_rows() {
	local typ="$1" decision="$2" since="$3" until="${4:-9999-12-31T23:59:59Z}"
	e2e_bodega server "discover export json $typ" >/dev/null 2>&1 || true
	printf '%s' "${E2E_OUT:-[]}" | jq -c --arg c "$nbx_client_addr" --arg d "$decision" \
		--arg s "$since" --arg u "$until" "$NBX_JQ_EPOCH"'
		[(. // [])[] | select(.decision == $d and .last_client == $c
			and (.last_seen | epoch) >= ($s | epoch) and (.last_seen | epoch) <= ($u | epoch))]' 2>/dev/null ||
		printf '[]'
}

# nbx_profile_entries <type> — the profile's entries of one type, one name per
# line. `profile show` has no machine-readable mode, so this reads its Entries
# table by position: TYPE then PACKAGE.
nbx_profile_entries() {
	e2e_bodega server "profile show $NBX_PROFILE" >/dev/null 2>&1 || true
	printf '%s\n' "$E2E_OUT" | awk -v t="$1" '
		/^Entries \(/ { on = 1; next }
		on && /^[[:space:]]*$/ { on = 0 }
		on && $1 == t { print $2 }'
}

# ---- the egress lock ---------------------------------------------------------
#
# A lock's self-check probes an address outside the allowed set, and that probe
# is itself a dropped packet. The count every phase asserts is therefore the
# movement since the lock settled, not the raw counter.

nbx_drops_now() {
	local n
	n="$(e2e_egress_drops "$1" 2>/dev/null)" || n=""
	printf '%s' "$n"
}

# nbx_lock_client — lock, or re-lock to re-arm the deadman, carrying the
# movement since the previous lock into the phase's total.
nbx_lock_client() {
	local n
	if [ "$nbx_locked_client" = yes ]; then
		n="$(nbx_drops_now client)"
		nbx_drops_acc=$((nbx_drops_acc + ${n:-0} - nbx_drops_base))
	fi
	e2e_egress_lock client "$nbx_server_addr" || return 1
	nbx_locked_client=yes
	nbx_locked_at="$(date -u +%s)"
	n="$(nbx_drops_now client)"
	nbx_drops_base="${n:-0}"
}

# nbx_keepalive — re-arm the client's deadman when the lock is getting old.
nbx_keepalive() {
	[ "$nbx_locked_client" = yes ] || return 0
	[ $(($(date -u +%s) - nbx_locked_at)) -ge "$NBX_RELOCK_SECS" ] || return 0
	nbx_lock_client || true
}

# nbx_phase_drops <phase> — R11: the client tried no route but bodega.
nbx_phase_drops() {
	local phase="$1" n moved
	E2E_HOST=client
	n="$(nbx_drops_now client)"
	if [ -z "$n" ]; then
		e2e_record "NBX-P$phase-DROPS" FAIL "phase $phase: the client sent nothing around bodega" \
			"0 packets dropped" "the drop counter could not be read, so the lock was gone before the phase ended" \
			"e2e_egress_drops client" 1 "test/e2e/lib/egress.sh:334"
	else
		moved=$((nbx_drops_acc + n - nbx_drops_base))
		check_eq "NBX-P$phase-DROPS" "phase $phase: the client sent nothing around bodega" 0 "$moved" \
			"test/e2e/lib/egress.sh:334; a dropped packet is the client reaching for a host other than the bodega server" \
			"e2e_egress_drops client, against the count when the phase began"
	fi
	nbx_drops_acc=0
	nbx_drops_base="${n:-0}"
}

# ---- remote scripts ----------------------------------------------------------
#
# Each prints a script run on the client through `bash -s`, so its quoting is
# the guest shell's alone.

nbx_script_tarball() {
	cat <<EOF
set -e
sudo rm -rf $NBX_ROOT $NBX_WORK/src
mkdir -p $NBX_WORK/src
cd $NBX_WORK/src
curl -fsS --max-time 300 -o netbox.tar.gz '$E2E_BASE_URL/git/netbox/netbox-$NBX_TAG.tar.gz'
tar -xzf netbox.tar.gz
test -f $NBX_SRC_DIR/requirements.txt
sudo mv $NBX_SRC_DIR $NBX_ROOT
sudo chown -R "\$(id -un)" $NBX_ROOT
EOF
}

nbx_script_database() {
	cat <<'EOF'
set -e
cd /tmp
sudo systemctl start postgresql redis-server
sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'
DROP DATABASE IF EXISTS netbox;
DROP ROLE IF EXISTS netbox;
CREATE ROLE netbox LOGIN PASSWORD 'e2e-netbox';
CREATE DATABASE netbox OWNER netbox;
SQL
EOF
	cat <<EOF
cat > $NBX_ROOT/netbox/netbox/configuration.py <<'PY'
ALLOWED_HOSTS = ['*']
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'netbox',
        'USER': 'netbox',
        'PASSWORD': 'e2e-netbox',
        'HOST': 'localhost',
        'PORT': '',
        'CONN_MAX_AGE': 300,
    }
}
REDIS = {
    'tasks': {'HOST': 'localhost', 'PORT': 6379, 'DATABASE': 0, 'SSL': False},
    'caching': {'HOST': 'localhost', 'PORT': 6379, 'DATABASE': 1, 'SSL': False},
}
PY
printf "SECRET_KEY = '%s'\n" "\$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')" >> $NBX_ROOT/netbox/netbox/configuration.py
EOF
}

# The dev server runs for one probe and is killed in the same ssh call, so no
# process outlives the command that started it.
nbx_script_login() {
	cat <<EOF
cd $NBX_ROOT/netbox
setsid ../venv/bin/python manage.py runserver 127.0.0.1:8000 --noreload --insecure >$NBX_WORK/runserver.log 2>&1 </dev/null &
pid=\$!
code=000
for _ in \$(seq 90); do
	code=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8000/login/)
	[ "\$code" = 200 ] && break
	sleep 1
done
kill "\$pid" 2>/dev/null
sleep 1
kill -9 "\$pid" 2>/dev/null
printf '%s' "\$code"
EOF
}

# nbx_script_remove — NetBox off the client: the dev server, the database and
# role, the tree and its venv, the apt packages a phase installed, and every
# cache an install could be answered from instead of bodega.
nbx_script_remove() {
	cat <<EOF
pkill -f 'manage.py runserver 127.0.0.1:8000' 2>/dev/null
if command -v psql >/dev/null 2>&1 && systemctl is-active --quiet postgresql; then
	(cd /tmp && sudo -u postgres psql -c 'DROP DATABASE IF EXISTS netbox' -c 'DROP ROLE IF EXISTS netbox') >/dev/null 2>&1
fi
sudo rm -rf $NBX_ROOT
rm -rf $NBX_WORK/src $NBX_WORK/resolve-venv $NBX_WORK/p4-venv $NBX_WORK/p5-venv
if [ -s $NBX_WORK/apt-installed ]; then
	sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y \$(cat $NBX_WORK/apt-installed) || exit 1
	: > $NBX_WORK/apt-installed
	if ! dpkg-query -W -f='\${Status}' postgresql-common 2>/dev/null | grep -q 'ok installed'; then
		sudo rm -rf /var/lib/postgresql /etc/postgresql
	fi
fi
python3 -m pip cache purge >/dev/null 2>&1
rm -rf "\$HOME/.cache/pip"
sudo apt-get clean
EOF
}

# ---- install -----------------------------------------------------------------

# nbx_install <id-prefix> — NetBox's standalone install, start to login page.
# Phases 1, 3 and 6 run it unchanged, so a difference between their verdicts
# is a difference in what bodega served.
nbx_install() {
	local p="$1" before
	E2E_HOST=client
	nbx_netbox_touched=yes
	e2e_on client "mkdir -p $NBX_WORK && touch $NBX_WORK/apt-installed && { wc -l < /var/log/apt/history.log 2>/dev/null || echo 0; }" || true
	before="${E2E_OUT:-0}"

	nbx_long client "sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $NBX_APT" || true
	nbx_rc "$p-APT" "the apt packages NetBox's install guide names install through bodega" \
		"internal/server/apt.go" "apt-get update && apt-get install -y $NBX_APT"

	# What this transaction fetched, and of that what it newly installed. The
	# second list is kept on the guest so a cleanup after an interrupt purges
	# exactly it: an upgraded package was there before the run, and purging
	# python3 because python3-dev pulled a newer one would take the guest's
	# tooling with it.
	e2e_on client "seg=\$(tail -n +$((before + 1)) /var/log/apt/history.log 2>/dev/null)
		names() { sed -E 's/\\([^)]*\\)//g' | tr ',' '\\n' | sed -E 's/^[[:space:]]+//; s/[:[:space:]].*//' | sed '/^\$/d' | sort -u; }
		printf '%s\\n' \"\$seg\" | sed -n -E 's/^Install: //p' | names > $NBX_WORK/apt-new
		sort -u $NBX_WORK/apt-installed $NBX_WORK/apt-new -o $NBX_WORK/apt-installed
		printf '%s\\n' \"\$seg\" | sed -n -E 's/^(Install|Upgrade|Reinstall|Downgrade): //p' | names" || true
	nbx_apt_fetched="$E2E_OUT"

	nbx_long client "bash -s" <<<"$(nbx_script_tarball)" || true
	nbx_rc "$p-TARBALL" "the NetBox $NBX_TAG release tarball comes from bodega's git release route" \
		"internal/server/git.go" "curl $E2E_BASE_URL/git/netbox/netbox-$NBX_TAG.tar.gz | tar -x"

	nbx_long client "bash -s" <<<"$(nbx_script_database)" || true
	nbx_rc "$p-DB" "NetBox's PostgreSQL database and role are created" \
		"docs.netbox.dev installation step 1" "psql: CREATE ROLE netbox; CREATE DATABASE netbox"

	[ "$p" = NBX-P1 ] && nbx_catalog

	nbx_long client "rm -f $NBX_WORK/pip.log $NBX_WORK/pip-report.json && cd $NBX_ROOT && python3 -m venv venv &&
		$nbx_pip_env venv/bin/pip install --log $NBX_WORK/pip.log --report $NBX_WORK/pip-report.json -r requirements.txt" || true
	nbx_rc "$p-PIP" "pip install -r requirements.txt resolves NetBox's closure through bodega" \
		"internal/server/pypi.go" "python3 -m venv venv && venv/bin/pip install --report ... -r requirements.txt"

	nbx_long client "cd $NBX_ROOT/netbox && ../venv/bin/python manage.py check" || true
	nbx_rc "$p-CHECK" "manage.py check exits 0" "docs.netbox.dev installation step 3" \
		"cd $NBX_ROOT/netbox && ../venv/bin/python manage.py check"

	nbx_long client "cd $NBX_ROOT/netbox && ../venv/bin/python manage.py migrate --no-input" || true
	nbx_rc "$p-MIGRATE" "manage.py migrate completes" "docs.netbox.dev installation step 3" \
		"cd $NBX_ROOT/netbox && ../venv/bin/python manage.py migrate --no-input"

	nbx_long client "bash -s" <<<"$(nbx_script_login)" || true
	check_eq "$p-LOGIN" "the NetBox dev server answers /login/ with 200" "200" "$E2E_OUT" \
		"docs.netbox.dev installation step 3" "manage.py runserver 127.0.0.1:8000; curl /login/"
}

# nbx_remove <id-prefix>
nbx_remove() {
	E2E_HOST=client
	nbx_long client "bash -s" <<<"$(nbx_script_remove)" || true
	nbx_rc "$1-REMOVE" "NetBox, its packages and every client-side cache are removed" \
		"test/e2e/suites/58-realworld-netbox.sh" "rm venv and $NBX_ROOT; apt-get purge; pip cache purge; apt-get clean"
}

# ---- the pypi catalog --------------------------------------------------------
#
# pypi serves a distribution only through a manifest entry, whatever the
# admission mode says, so NetBox's closure has to be cataloged before pip can
# resolve it. This is the documented bootstrap (docs/usage.md, `discover
# generate-manifests`): observe, let the install fail, promote what it reached
# for, retry. On a server that already holds the closure the first resolve
# succeeds and nothing is imported.
#
# The payload is narrowed to rows this client wrote during this run, so a row
# another suite left (65-proxy reads an uncataloged name on purpose) is never
# imported.

nbx_catalog() {
	local round=0 rc=1 added=0 keep payload f="${E2E_ARTIFACT_DIR:-/tmp}/nbx-catalog.json"
	E2E_HOST=client
	# One index read per top-level requirement, so the first pass catalogs the
	# direct dependencies together rather than one per round.
	e2e_on client "grep -Ev '^[[:space:]]*(#|\$)' $NBX_ROOT/requirements.txt | sed -E 's/^([A-Za-z0-9._-]+).*/\\1/' |
		tr '[:upper:]' '[:lower:]' | sed -E 's/[-_.]+/-/g' | while read -r n; do curl -s -o /dev/null --max-time 60 '$E2E_BASE_URL/pypi/simple/'\"\$n\"/; done" || true
	nbx_long client "rm -rf $NBX_WORK/resolve-venv && python3 -m venv $NBX_WORK/resolve-venv" || true

	while [ "$round" -lt "$NBX_CATALOG_ROUNDS" ]; do
		round=$((round + 1))
		nbx_keepalive
		E2E_HOST=server
		keep="$(nbx_rows pypi no_manifest "$nbx_p1_since" | jq -c '[.[].pkg_name | ascii_downcase | gsub("[-_.]+"; "-")] | unique')"
		e2e_bodega server "discover generate-manifests pypi --skip-existing" >/dev/null 2>&1 || true
		payload="$(printf '%s' "${E2E_OUT:-null}" | jq -c --argjson keep "${keep:-[]}" \
			'[(. // [])[] | select((.name | ascii_downcase | gsub("[-_.]+"; "-")) as $n | $keep | index($n))]' 2>/dev/null)"
		added="$(printf '%s' "${payload:-[]}" | jq 'length' 2>/dev/null || echo 0)"
		if [ "${added:-0}" -gt 0 ]; then
			printf '%s\n' "$payload" >"$f"
			e2e_put server "$f" "/tmp/nbx-catalog.json" || true
			e2e_bodega server "pkg import --merge /tmp/nbx-catalog.json" || true
			e2e_reload server || true
			sleep 2
		fi
		E2E_HOST=client
		nbx_long client "cd $NBX_ROOT && $nbx_pip_env $NBX_WORK/resolve-venv/bin/pip install --dry-run -r requirements.txt" || true
		rc="$E2E_RC"
		[ "$rc" = 0 ] && break
		# The recorder writes off the request goroutine.
		sleep 1
		# A failed resolve with nothing new to import is a resolve this loop can
		# never finish, and another round would spend the budget learning that.
		[ "${added:-0}" -gt 0 ] || [ "$round" -eq 1 ] || break
	done
	local verdict=FAIL seen
	seen="$(nbx_tail)"
	if [ "$rc" = 0 ]; then
		verdict=PASS
		seen="resolved after $round round(s)"
	fi
	e2e_record NBX-P1-CATALOG "$verdict" "observe and generate-manifests catalog NetBox's pypi closure" \
		"pip --dry-run resolves" "$seen" \
		"discover generate-manifests pypi --skip-existing | pkg import --merge; pip install --dry-run, up to $NBX_CATALOG_ROUNDS rounds" \
		"$rc" "cmd/bodega/cmd_discover.go:942"
}

# ---- cleanup -----------------------------------------------------------------

nbx_cleanup() {
	[ "$nbx_cleaned" = yes ] && return 0
	nbx_cleaned=yes
	local t m

	if [ "$nbx_netbox_touched" = yes ]; then
		nbx_long client "bash -s" <<<"$(nbx_script_remove)" >/dev/null 2>&1 || true
	fi
	if [ "$nbx_client_configured" = yes ]; then
		e2e_on client "o=$NBX_WORK/orig
			for f in /etc/apt/sources.list.d/bodega.sources /etc/pip.conf; do
				b=\$(basename \$f)
				if [ -f \$o/\$b ]; then sudo install -m 0644 \$o/\$b \$f; else sudo rm -f \$f; fi
			done
			for f in /etc/apt/sources.list.d/*.e2e-netbox-off; do
				[ -e \"\$f\" ] && sudo mv \"\$f\" \"\${f%.e2e-netbox-off}\"
			done
			sudo find /etc/apt/sources.list.d /etc -maxdepth 1 -name '*.bodega-*' -newer \$o -delete" >/dev/null 2>&1 || true
	fi
	e2e_on client "rm -rf $NBX_WORK" >/dev/null 2>&1 || true

	if [ "$nbx_locked_client" = yes ]; then
		e2e_egress_unlock client >/dev/null 2>&1 || true
		nbx_locked_client=no
	fi
	if [ "$nbx_locked_server" = yes ]; then
		e2e_egress_unlock server >/dev/null 2>&1 || true
		nbx_locked_server=no
	fi

	if [ "$nbx_profile_made" = yes ]; then
		e2e_bodega server "profile unbind $NBX_IDENTITY" >/dev/null 2>&1 || true
		for t in $NBX_TYPES; do
			for m in $(nbx_profile_entries "$t"); do
				nbx_safe "$m" || continue
				e2e_bodega server "profile remove $NBX_PROFILE $t $m --force" >/dev/null 2>&1 || true
			done
		done
		# There is no `profile delete` (F72); this is the call that will remove
		# the profile once there is, and NBX-RESTORE-PROFILE says whether it did.
		e2e_bodega server "profile delete $NBX_PROFILE" >/dev/null 2>&1 || true
	fi
	if [ "$nbx_cidr_bound" = yes ]; then
		e2e_bodega server "identity unbind cidr $nbx_client_addr/32" >/dev/null 2>&1 || true
	fi
	for m in $nbx_prior_modes; do
		e2e_bodega server "policy mode set ${m%%=*} ${m#*=}" >/dev/null 2>&1 || true
	done
	if [ "$nbx_config_saved" = yes ]; then
		e2e_on server "sudo install -o root -g ${E2E_SERVICE_USER:-bodega} -m 0640 $NBX_WORK/config.json /etc/bodega/config.json" >/dev/null 2>&1 || true
		e2e_restart server >/dev/null 2>&1 || true
	fi
	e2e_on server "sudo rm -rf $NBX_WORK" >/dev/null 2>&1 || true
}

# The suite is sourced into run.sh, whose own EXIT trap closes the ssh control
# sockets. Replacing it would leave those open, so the suite's trap runs the
# cleanup and then whatever was there before, and the original is put back
# when the suite returns. INT and TERM become an exit so the EXIT trap fires
# on an interrupt too.
nbx_prev_exit="$(trap -p EXIT)"
nbx_prev_int="$(trap -p INT)"
nbx_prev_term="$(trap -p TERM)"
nbx_prev_exit_cmd=""
nbx_prev_argv=()
if [ -n "$nbx_prev_exit" ]; then
	eval "nbx_prev_argv=($nbx_prev_exit)"
	nbx_prev_exit_cmd="${nbx_prev_argv[2]}"
fi

# shellcheck disable=SC2329  # the EXIT trap calls it
nbx_on_exit() {
	nbx_cleanup
	[ -z "$nbx_prev_exit_cmd" ] || eval "$nbx_prev_exit_cmd"
}

nbx_restore_traps() {
	trap - EXIT INT TERM
	[ -z "$nbx_prev_exit" ] || eval "$nbx_prev_exit"
	[ -z "$nbx_prev_int" ] || eval "$nbx_prev_int"
	[ -z "$nbx_prev_term" ] || eval "$nbx_prev_term"
}

# ---- preflight ---------------------------------------------------------------

nbx_preflight() {
	local root avail mem
	nbx_phase "preflight"
	if [ "${E2E_DRY_RUN:-no}" != yes ] &&
		{ [ "${E2E_SERVER_UP:-no}" != yes ] || [ "${E2E_CLIENT_UP:-no}" != yes ]; }; then
		E2E_HOST=local
		e2e_block NBX-PRE-REACH "NetBox through bodega" \
			"a guest is unreachable: server up=${E2E_SERVER_UP:-no}, client up=${E2E_CLIENT_UP:-no}"
		return 1
	fi
	nbx_server_addr="${E2E_SERVER_ADDR:-}"
	nbx_client_addr="${E2E_CLIENT_ADDR:-}"
	if [ "${E2E_DRY_RUN:-no}" = yes ]; then
		nbx_server_addr="${nbx_server_addr:-192.0.2.1}"
		nbx_client_addr="${nbx_client_addr:-192.0.2.2}"
	fi
	if [ -z "$nbx_server_addr" ] || [ -z "$nbx_client_addr" ]; then
		E2E_HOST=local
		e2e_block NBX-PRE-ADDR "NetBox through bodega" \
			"00-preflight resolved no address for the server or the client, so no lock can name them"
		return 1
	fi

	E2E_HOST=server
	e2e_config_get server '.storage_path // "/var/lib/bodega"' || true
	root="${E2E_OUT:-/var/lib/bodega}"
	e2e_on server "df -B1 --output=avail '$root' | tail -1 | tr -dc '0-9'" || true
	avail="${E2E_OUT:-0}"
	if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${avail:-0}" -lt 1073741824 ]; then
		e2e_block NBX-PRE-DISK "the server has 1 GiB free under bodega's storage root" \
			"$root has $((${avail:-0} / 1048576)) MiB free, under the 1 GiB NetBox's closure needs cached"
		return 1
	fi
	e2e_record NBX-PRE-DISK PASS "the server has 1 GiB free under bodega's storage root" ">= 1 GiB" \
		"$((${avail:-0} / 1048576)) MiB under $root" "df -B1 $root" 0 ""

	E2E_HOST=client
	e2e_on client "awk '/^MemTotal:/ {print \$2}' /proc/meminfo" || true
	mem="${E2E_OUT:-0}"
	if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${mem:-0}" -lt 2097152 ]; then
		e2e_block NBX-PRE-RAM "the client has 2 GiB of RAM" \
			"MemTotal is $((${mem:-0} / 1024)) MiB, under the 2 GiB a NetBox migrate needs"
		return 1
	fi
	e2e_record NBX-PRE-RAM PASS "the client has 2 GiB of RAM" ">= 2 GiB" "$((${mem:-0} / 1024)) MiB" \
		"grep MemTotal /proc/meminfo" 0 ""

	E2E_HOST=server
	e2e_bodega server "profile list" || true
	if printf '%s\n' "$E2E_OUT" | awk -v p="$NBX_PROFILE" '$1 == p { found = 1 } END { exit !found }'; then
		e2e_block NBX-PRE-PROFILE "no profile named $NBX_PROFILE exists" \
			"$NBX_PROFILE already exists, and this suite will not empty a profile it did not create (bodega has no profile delete yet, F72)"
		return 1
	fi
	e2e_record NBX-PRE-PROFILE PASS "no profile named $NBX_PROFILE exists" "absent" "absent" \
		"bodega profile list" 0 "cmd/bodega/cmd_profile.go:632"

	e2e_bodega server "identity list" || true
	if printf '%s\n' "$E2E_OUT" | grep -Fq "$nbx_client_addr/32"; then
		e2e_block NBX-PRE-CIDR "the client's /32 carries no identity binding" \
			"$nbx_client_addr/32 is already bound, and bodega refuses a second identity for one address; unbind it or let the suite that bound it finish"
		return 1
	fi
	e2e_record NBX-PRE-CIDR PASS "the client's /32 carries no identity binding" "unbound" "unbound" \
		"bodega identity list" 0 "cmd/bodega/cmd_identity.go:59"

	# What the cleanup puts back. The whole config file rather than one key:
	# phase 1 changes discover_mode, proxy_cache_enabled and apt_upstreams, and
	# restoring each by hand is three chances to leave one changed.
	e2e_config_get server '.discover_mode // ""' || true
	nbx_prior_discover="$E2E_OUT"
	e2e_bodega server "policy mode list" || true
	nbx_prior_modes="$(printf '%s\n' "$E2E_OUT" | awk -v want=" $NBX_TYPES " \
		'index(want, " " $1 " ") && ($2 == "listed" || $2 == "open") { printf "%s=%s ", $1, $2 }')"
	e2e_on server "sudo mkdir -p $NBX_WORK && sudo cp -p /etc/bodega/config.json $NBX_WORK/config.json" || true
	if [ "$E2E_RC" != 0 ]; then
		e2e_block NBX-PRE-SAVE "the server's config is saved before anything changes" \
			"copying /etc/bodega/config.json exited $E2E_RC: $E2E_ERR"
		return 1
	fi
	nbx_config_saved=yes
	e2e_record NBX-PRE-SAVE PASS "the server's config is saved before anything changes" "saved" \
		"discover_mode=${nbx_prior_discover:-unset}; modes: ${nbx_prior_modes:-none read}" \
		"cp /etc/bodega/config.json; bodega policy mode list" 0 ""
}

# ---- phase 0 -----------------------------------------------------------------

nbx_phase0() {
	local n
	nbx_phase "0: egress"
	E2E_HOST=client
	if ! nbx_lock_client; then
		e2e_record NBX-P0-LOCK FAIL "the client's egress is locked to the server" "lock holds" \
			"e2e_egress_lock refused or did not hold; its stderr is in the run output" \
			"e2e_egress_lock client $nbx_server_addr" 1 "test/e2e/lib/egress.sh:269"
		return 1
	fi
	e2e_record NBX-P0-LOCK PASS "the client's egress is locked to the server" "lock holds" "lock holds" \
		"e2e_egress_lock client $nbx_server_addr" 0 "test/e2e/lib/egress.sh:269"

	e2e_on client "curl -m 5 -sS -o /dev/null https://pypi.org/simple/" || true
	nbx_rc_fails NBX-P0-PYPI "the client cannot reach pypi.org" "test/e2e/lib/egress.sh" \
		"curl -m 5 https://pypi.org/simple/"
	e2e_on client "getent hosts pypi.org" || true
	nbx_rc_fails NBX-P0-DNS "the client cannot resolve pypi.org" "test/e2e/lib/egress.sh" "getent hosts pypi.org"
	e2e_http client "/healthz" || true
	check_eq NBX-P0-HEALTH "the client reaches bodega's /healthz" "200" "$E2E_OUT" \
		"internal/server/server.go:748" "curl $E2E_BASE_URL/healthz"

	# The two probes above were dropped on purpose, so this phase's count is
	# the opposite assertion: the counter moved. Every later phase asserts 0,
	# and a counter that never moves would pass all of them.
	n="$(nbx_drops_now client)"
	if [ "${E2E_DRY_RUN:-no}" = yes ] || [ "${n:-0}" -gt "$nbx_drops_base" ]; then
		e2e_record NBX-P0-DROPS PASS "the drop counter counts the probes phase 0 sent upstream" "> $nbx_drops_base" \
			"${n:-0}" "e2e_egress_drops client" 0 "test/e2e/lib/egress.sh:334"
	else
		e2e_record NBX-P0-DROPS FAIL "the drop counter counts the probes phase 0 sent upstream" "> $nbx_drops_base" \
			"${n:-unreadable}" "e2e_egress_drops client" 1 "test/e2e/lib/egress.sh:334"
	fi
	nbx_drops_base="${n:-0}"
	nbx_drops_acc=0
}

# ---- phase 1 -----------------------------------------------------------------

# nbx_apt_mirror_prog — the jq that adds an apt_upstreams entry for each of
# the client's codenames the server does not mirror, from the client's own
# sources, so the install meets the archive and pockets the client was built
# from. -updates and -security matter: a -dev package from the release pocket
# depends on the exact runtime version, and the client's runtime is newer.
nbx_apt_mirror_prog() {
	local uri="$1" comps="$2" s prog="."
	shift 2
	for s in "$@"; do
		prog="$prog | .apt_upstreams[\"$s\"] //= [{\"url\": \"$uri\", \"components\": $comps}]"
	done
	printf '%s' "$prog"
}

# nbx_git_entry — the release-mode git entry the tarball route serves, built
# on the server unless it already holds it. A release entry is a hosted
# artifact, so nothing can proxy it in on first request the way pypi does.
nbx_git_entry() {
	local f="${E2E_ARTIFACT_DIR:-/tmp}/nbx-git.json"
	E2E_HOST=server
	e2e_on server "curl -s -o /dev/null -w '%{http_code}' --max-time 60 http://127.0.0.1:8080/git/netbox/netbox-$NBX_TAG.tar.gz" || true
	if [ "$E2E_OUT" != 200 ]; then
		jq -n --arg tag "$NBX_TAG" '[{config_version: 1, name: "netbox", type: "git",
			description: "e2e suite 58: the NetBox release tarball",
			versions: [{version: $tag, url: "https://github.com/netbox-community/netbox.git", ref: $tag, source: "release"}]}]' >"$f"
		e2e_put server "$f" /tmp/nbx-git.json || true
		e2e_bodega server "pkg import --merge /tmp/nbx-git.json" || true
		nbx_long server "sudo bodega build fetch git netbox && sudo bodega build upload git netbox; rc=\$?; sudo chown -R ${E2E_SERVICE_USER:-bodega} /var/lib/bodega /var/log/bodega; exit \$rc" || true
		e2e_reload server || true
		sleep 2
		e2e_on server "curl -s -o /dev/null -w '%{http_code}' --max-time 60 http://127.0.0.1:8080/git/netbox/netbox-$NBX_TAG.tar.gz" || true
	fi
	check_eq NBX-P1-GIT-ENTRY "the server serves the NetBox $NBX_TAG release tarball" "200" "$E2E_OUT" \
		"internal/server/git.go:27" "pkg import a release-mode git entry; build fetch git netbox; build upload git netbox"
}

nbx_phase1() {
	local suites uri comps t s
	nbx_phase "1: log-only"
	E2E_HOST=client
	e2e_on client "awk '/^URIs:/ {print \$2; exit}' /etc/apt/sources.list.d/ubuntu.sources" || true
	uri="${E2E_OUT:-http://ports.ubuntu.com/ubuntu-ports}"
	e2e_on client "awk '/^Suites:/ {for (i = 2; i <= NF; i++) print \$i; exit}' /etc/apt/sources.list.d/ubuntu.sources" || true
	suites="$(printf '%s\n' "$E2E_OUT" | tr '\n' ' ')"
	e2e_on client "awk '/^Components:/ {for (i = 2; i <= NF; i++) print \$i; exit}' /etc/apt/sources.list.d/ubuntu.sources" || true
	comps="$(printf '%s\n' "${E2E_OUT:-main}" | jq -R . | jq -sc .)"
	# All three land in a jq program run as root on the server.
	case "$uri" in
	http://* | https://*) [[ "$uri" =~ ^https?://[A-Za-z0-9./_-]+$ ]] || uri="" ;;
	*) uri="" ;;
	esac
	for s in $suites; do
		[[ "$s" =~ ^[a-z0-9-]+$ ]] || suites=""
	done
	if [ "${E2E_DRY_RUN:-no}" != yes ] && { [ -z "$uri" ] || [ -z "$suites" ]; }; then
		E2E_HOST=client
		e2e_record NBX-P1-SOURCES FAIL "the client's own apt sources name an archive and its codenames" \
			"a URI and one or more codenames" "$(e2e_excerpt "$E2E_OUT")" \
			"awk /etc/apt/sources.list.d/ubuntu.sources" 1 ""
		return 1
	fi

	E2E_HOST=server
	# shellcheck disable=SC2086  # one codename per word
	e2e_config_set server ".discover_mode = \"observe\" | .proxy_cache_enabled = true | $(nbx_apt_mirror_prog "$uri" "$comps" $suites)" || true
	e2e_restart server || true
	e2e_config_get server '.discover_mode' || true
	check_eq NBX-P1-OBSERVE "discover_mode is observe after the restart" "observe" "$E2E_OUT" \
		"internal/server/discovery.go:341" "jq .discover_mode=observe; systemctl restart bodega"

	for t in $NBX_TYPES; do
		e2e_bodega server "policy mode set $t open" || true
		nbx_rc "NBX-P1-MODE-$t" "$t admission mode is open" "cmd/bodega/cmd_policy_rollout.go:52" \
			"bodega policy mode set $t open"
	done

	e2e_bodega server "profile create $NBX_PROFILE --description 'e2e suite 58: NetBox v4.7.2'" || true
	[ "$E2E_RC" = 0 ] && nbx_profile_made=yes
	nbx_rc NBX-P1-PROFILE "profile $NBX_PROFILE is created" "cmd/bodega/cmd_profile.go:131" \
		"bodega profile create $NBX_PROFILE"
	if [ "$nbx_profile_made" != yes ] && [ "${E2E_DRY_RUN:-no}" != yes ]; then
		return 1
	fi
	for t in $NBX_TYPES; do
		e2e_bodega server "profile set $NBX_PROFILE $t --membership closed --expansion warn" || true
		nbx_rc "NBX-P1-SET-$t" "$t is closed at expansion warn" "cmd/bodega/cmd_profile.go:913" \
			"bodega profile set $NBX_PROFILE $t --membership closed --expansion warn"
	done
	e2e_bodega server "identity bind cidr $nbx_client_addr/32 $NBX_IDENTITY --comment 'e2e suite 58'" || true
	[ "$E2E_RC" = 0 ] && nbx_cidr_bound=yes
	e2e_bodega server "profile bind $NBX_PROFILE $NBX_IDENTITY" || true
	e2e_reload server || true
	sleep 3
	e2e_bodega server "profile show $NBX_PROFILE" || true
	check_contains NBX-P1-BIND "the profile is bound to the client's /32" "$NBX_IDENTITY" "$E2E_OUT" \
		"cmd/bodega/cmd_profile.go:786" "bodega identity bind cidr $nbx_client_addr/32 $NBX_IDENTITY; bodega profile bind"

	nbx_p1_since="$(nbx_now server)"

	# Every apt source but bodega's is set aside, so apt has no second place to
	# look; the lock would refuse it anyway, and an index apt cannot refresh
	# fails `apt-get update` for a reason that is not bodega's.
	E2E_HOST=client
	nbx_client_configured=yes
	e2e_on client "mkdir -p $NBX_WORK/orig &&
		for f in /etc/apt/sources.list.d/bodega.sources /etc/pip.conf; do [ -f \$f ] && cp -p \$f $NBX_WORK/orig/; done
		for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
			[ -f \"\$f\" ] && [ \"\$f\" != /etc/apt/sources.list.d/bodega.sources ] && sudo mv \"\$f\" \"\$f.e2e-netbox-off\"
		done; true" || true
	e2e_on client "sudo bodega doctor --configure apt,pypi --apply --url $E2E_BASE_URL --allow-plaintext" || true
	nbx_rc NBX-P1-CONFIGURE "bodega doctor configures apt and pip on the client" "cmd/bodega/cmd_doctor.go" \
		"sudo bodega doctor --configure apt,pypi --apply --url $E2E_BASE_URL --allow-plaintext"

	nbx_git_entry
	nbx_install NBX-P1
	nbx_evidence
	nbx_phase_drops 1
}

# nbx_evidence — R5: every package the client fetched in phase 1 has a row
# from the client's address. A package with none is a fetch bodega did not
# see, which is the bypass the lock is meant to make impossible.
nbx_evidence() {
	local apt_src pypi_names rows missing
	nbx_p1_until="$(nbx_now server)"
	E2E_HOST=client

	# apt's pool gate names the source package (aptPoolSourceName), so each
	# binary the transaction installed is mapped to its source before the
	# comparison: libpq-dev's row is postgresql-NN's.
	if [ -n "$nbx_apt_fetched" ]; then
		e2e_on client "dpkg-query -W -f='\${source:Package}\n' $(printf '%s\n' "$nbx_apt_fetched" | tr '\n' ' ')" || true
		apt_src="$(printf '%s\n' "$E2E_OUT" | sed '/^$/d' | sort -u)"
	else
		apt_src=""
	fi
	nbx_set_apt="$apt_src"

	# pip's report lists what it installed; the log adds what a build fetched
	# into an isolated environment (setuptools for an sdist), which installs
	# nothing into the venv and is still a fetch.
	e2e_on client "jq -r '.install[].metadata.name' $NBX_WORK/pip-report.json; sed -n -E 's/.*Collecting ([A-Za-z0-9][A-Za-z0-9._-]*).*/\\1/p' $NBX_WORK/pip.log" || true
	pypi_names="$(printf '%s\n' "$E2E_OUT" | nbx_canon)"
	nbx_set_pypi="$pypi_names"
	e2e_on client "jq -r '.install[] | \"\\(.metadata.name) \\(.metadata.version)\"' $NBX_WORK/pip-report.json" || true
	nbx_pypi_versions="$E2E_OUT"
	nbx_set_git="netbox"

	E2E_HOST=server
	for t in apt pypi git; do
		rows="$(nbx_rows "$t" denied "$nbx_p1_since" "$nbx_p1_until" | jq -r '.[].pkg_name' | nbx_canon_for "$t")"
		case "$t" in
		apt) missing="$(comm -23 <(printf '%s\n' "$nbx_set_apt" | sed '/^$/d' | sort -u) <(printf '%s\n' "$rows"))" ;;
		pypi) missing="$(comm -23 <(printf '%s\n' "$nbx_set_pypi" | sed '/^$/d') <(printf '%s\n' "$rows"))" ;;
		git) missing="$(comm -23 <(printf '%s\n' "$nbx_set_git") <(printf '%s\n' "$rows"))" ;;
		esac
		missing="$(printf '%s' "$missing" | tr '\n' ' ' | sed 's/ $//')"
		check_eq "NBX-P1-EVID-$t" "every $t package the client fetched has a discovery row from its address" \
			"" "$missing" \
			"internal/server/profile.go:342; a name listed here installed with no row, so bodega did not see its fetch" \
			"bodega discover export json $t, rows decided denied from $nbx_client_addr since $nbx_p1_since"
	done
}

# nbx_canon_for <type> — the comparison form of a name: PEP 503 for pypi, as
# written for the rest.
nbx_canon_for() {
	if [ "$1" = pypi ]; then nbx_canon; else sed '/^$/d' | sort -u; fi
}

# ---- phase 2 -----------------------------------------------------------------

nbx_phase2() {
	local t cmd failed="" name version want got seen
	nbx_phase "2: learn"
	E2E_HOST=server
	for t in $NBX_TYPES; do
		seen=" "
		while IFS= read -r cmd; do
			[ -n "$cmd" ] || continue
			case "$cmd" in
			"bodega profile add $NBX_PROFILE $t "*) ;;
			*) continue ;;
			esac
			name="${cmd##* }"
			if ! nbx_safe "$name"; then
				failed="$failed unsafe:$name"
				continue
			fi
			# pip asks for one distribution under more than one spelling, and
			# each spelling is its own row; the profile holds it once.
			[ "$t" = pypi ] && name="$(printf '%s\n' "$name" | nbx_canon)"
			case "$seen" in *" $name "*) continue ;; esac
			seen="$seen$name "
			e2e_bodega server "${cmd#bodega } --reason '$NBX_REASON'" >/dev/null 2>&1 || failed="$failed $cmd"
		done < <(nbx_rows "$t" denied "$nbx_p1_since" "$nbx_p1_until" | jq -r '[.[].pattern_hint] | unique | .[]')
	done
	check_eq NBX-P2-ADD "every denied row's own profile add command applies" "" "${failed# }" \
		"internal/server/profile.go:369" "the bodega profile add each phase 1 row's pattern carries"

	for t in $NBX_TYPES; do
		e2e_bodega server "profile set $NBX_PROFILE $t --expansion block" || true
		nbx_rc "NBX-P2-BLOCK-$t" "$t is set to expansion block" "cmd/bodega/cmd_profile.go:913" \
			"bodega profile set $NBX_PROFILE $t --expansion block"
	done
	e2e_bodega server "profile set $NBX_PROFILE pypi --version-default pinned" || true
	nbx_rc NBX-P2-PINNED "pypi's version default is pinned" "cmd/bodega/cmd_profile.go:913" \
		"bodega profile set $NBX_PROFILE pypi --version-default pinned"

	# The version each distribution installed at, from pip's report; a build
	# dependency is in no report, so its version is the one its wheel row
	# recorded.
	failed=""
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		version="$(printf '%s\n' "$nbx_pypi_versions" | awk -v n="$name" '
			{ k = tolower($1); gsub(/[-_.]+/, "-", k) } k == n { print $2; exit }')"
		if [ -z "$version" ]; then
			version="$(nbx_rows pypi denied "$nbx_p1_since" "$nbx_p1_until" | jq -r --arg n "$name" \
				'[.[] | select((.pkg_name | ascii_downcase | gsub("[-_.]+"; "-")) == $n and .pkg_version != "")]
				 | sort_by(.last_seen) | last | .pkg_version // empty')"
		fi
		if [ -z "$version" ] || ! nbx_safe "$name" || ! nbx_safe "$version"; then
			failed="$failed $name(${version:-no version})"
			continue
		fi
		e2e_bodega server "profile pin $NBX_PROFILE pypi $name $version --reason '$NBX_REASON'" >/dev/null 2>&1 ||
			failed="$failed $name==$version"
	done <<<"$nbx_set_pypi"
	check_eq NBX-P2-PIN "every pypi package is pinned at the version phase 1 installed" "" "${failed# }" \
		"cmd/bodega/cmd_profile.go:1193" "bodega profile pin $NBX_PROFILE pypi <name> <version>"

	for t in $NBX_TYPES; do
		case "$t" in
		apt) want="$nbx_set_apt" ;;
		pypi) want="$nbx_set_pypi" ;;
		git) want="$nbx_set_git" ;;
		esac
		want="$(printf '%s\n' "$want" | nbx_canon_for "$t")"
		got="$(nbx_profile_entries "$t" | nbx_canon_for "$t")"
		check_eq "NBX-P2-SET-$t" "the profile's $t entries are exactly the phase 1 set" \
			"missing: ; extra: " \
			"missing: $(comm -23 <(printf '%s\n' "$want") <(printf '%s\n' "$got") | tr '\n' ' ' | sed 's/ $//'); extra: $(comm -13 <(printf '%s\n' "$want") <(printf '%s\n' "$got") | tr '\n' ' ' | sed 's/ $//')" \
			"cmd/bodega/cmd_profile.go:677" "bodega profile show $NBX_PROFILE, Entries, against phase 1's fetches"
	done
	e2e_reload server || true
	sleep 3
	nbx_phase_drops 2
}

# ---- phase 3 -----------------------------------------------------------------

# nbx_no_denials <id> <since> — no row decided denied from the client inside
# the window.
nbx_no_denials() {
	local id="$1" since="$2" until rows t
	until="$(nbx_now server)"
	E2E_HOST=server
	rows=""
	for t in $NBX_TYPES; do
		rows="$rows $(nbx_rows "$t" denied "$since" "$until" | jq -r '.[] | "\(.registry_type)/\(.pkg_name)@\(.pkg_version)"' | tr '\n' ' ')"
	done
	rows="$(printf '%s' "$rows" | tr -s ' ' | sed 's/^ //; s/ $//')"
	check_eq "$id" "the learned profile refused nothing the reinstall fetched" "" "$rows" \
		"internal/server/profile.go:342" "bodega discover export json, rows decided denied from $nbx_client_addr since $since"
}

nbx_phase3() {
	local since
	nbx_phase "3: restricted reinstall"
	nbx_lock_client || true
	since="$(nbx_now server)"
	nbx_remove NBX-P3
	nbx_install NBX-P3
	nbx_no_denials NBX-P3-NODENY "$since"
	nbx_phase_drops 3
}

# ---- phase 4 -----------------------------------------------------------------

# Nautobot is NetBox's nearest neighbor: the same problem, many of the same
# dependencies, and some it does not share. pip stops at nautobot's own index,
# which the profile refuses, so it never reads a dependency; the dependencies
# are therefore read directly, one NetBox shares (django) and one it does not
# (celery, which nautobot's task queue is built on and NetBox's rq replaces).
NBX_SHARED_DEP=django
NBX_UNSHARED_DEP=celery
NBX_APT_OUTSIDE=docker.io

nbx_phase4() {
	local since until rows src code n
	nbx_phase "4: refusal"
	nbx_lock_client || true
	since="$(nbx_now server)"
	E2E_HOST=client

	nbx_long client "rm -rf $NBX_WORK/p4-venv && python3 -m venv $NBX_WORK/p4-venv &&
		$nbx_pip_env $NBX_WORK/p4-venv/bin/pip install --dry-run nautobot" || true
	nbx_rc_fails NBX-P4-PIP "pip install --dry-run nautobot fails under the learned profile" \
		"internal/server/profile.go:308" "venv/bin/pip install --dry-run nautobot"

	for n in nautobot "$NBX_UNSHARED_DEP"; do
		e2e_on client "curl -s -o /dev/null -w '%{http_code}' --max-time 60 '$E2E_BASE_URL/pypi/simple/$n/'" || true
		check_eq "NBX-P4-403-$n" "$n, which NetBox does not use, is refused with 403" "403" "$E2E_OUT" \
			"internal/server/profile.go:308" "GET /pypi/simple/$n/ from the client"
	done
	e2e_on client "curl -s -o /dev/null -w '%{http_code}' --max-time 60 '$E2E_BASE_URL/pypi/simple/$NBX_SHARED_DEP/'" || true
	check_eq NBX-P4-SHARED "$NBX_SHARED_DEP, a nautobot dependency NetBox also uses, is served" "200" "$E2E_OUT" \
		"internal/server/pypi.go:110" "GET /pypi/simple/$NBX_SHARED_DEP/ from the client"

	# apt is filtered at the index rather than gated per request, and a
	# mirrored codename the profile names no base for is served whole, so a
	# package outside the set is either absent from what the client reads or
	# refused at the pool. The check id says which one happened.
	e2e_on client "apt-cache show $NBX_APT_OUTSIDE 2>/dev/null | awk '/^Source:/ {print \$2; exit}'" || true
	src="${E2E_OUT:-$NBX_APT_OUTSIDE}"
	e2e_on client "apt-cache policy $NBX_APT_OUTSIDE | awk '/Candidate:/ {print \$2}'" || true
	code="$E2E_OUT"
	nbx_long client "sudo DEBIAN_FRONTEND=noninteractive apt-get install --download-only -y $NBX_APT_OUTSIDE" || true
	nbx_rc_fails NBX-P4-APT "apt-get install --download-only $NBX_APT_OUTSIDE fails" \
		"internal/server/apt_profile.go:619" "apt-get install --download-only -y $NBX_APT_OUTSIDE"
	# A dry run reads no index, so it lists both ids rather than one branch.
	if [ "${E2E_DRY_RUN:-no}" = yes ] || [ -z "$code" ] || [ "$code" = "(none)" ]; then
		e2e_record NBX-P4-APT-INDEX PASS "$NBX_APT_OUTSIDE is absent from the index the client reads" \
			"no candidate" "${code:-no candidate}" "apt-cache policy $NBX_APT_OUTSIDE" 0 "internal/server/apt_profile.go:347"
	fi
	if [ "${E2E_DRY_RUN:-no}" = yes ] || { [ -n "$code" ] && [ "$code" != "(none)" ]; }; then
		check_contains NBX-P4-APT-POOL "$NBX_APT_OUTSIDE is listed and refused at the pool with 403" "403" \
			"$E2E_OUT$E2E_ERR" "internal/server/apt_profile.go:619" "apt-get install --download-only -y $NBX_APT_OUTSIDE"
	fi

	until="$(nbx_now server)"
	E2E_HOST=server
	rows="$(nbx_rows pypi denied "$since" "$until" | jq -r '.[].pkg_name' | nbx_canon)"
	for n in nautobot "$NBX_UNSHARED_DEP"; do
		check_contains "NBX-P4-ROW-$n" "the refusal of $n wrote a denied row naming it" "$n" "$rows" \
			"internal/server/profile.go:342" "bodega discover export json pypi, denied from $nbx_client_addr"
	done
	if [ -z "$code" ] || [ "$code" = "(none)" ]; then
		e2e_skip NBX-P4-ROW-apt "the refusal of $NBX_APT_OUTSIDE wrote a denied row naming it" \
			"$NBX_APT_OUTSIDE never reached the pool, so there is no fetch to have refused" "internal/server/apt_profile.go:619"
	else
		rows="$(nbx_rows apt denied "$since" "$until" | jq -r '.[].pkg_name')"
		check_contains NBX-P4-ROW-apt "the refusal of $NBX_APT_OUTSIDE wrote a denied row naming it" "$src" "$rows" \
			"internal/server/apt_profile.go:619; the pool gate names the source package" \
			"bodega discover export json apt, denied from $nbx_client_addr"
	fi
	nbx_phase_drops 4
}

# ---- phase 5 -----------------------------------------------------------------

nbx_phase5() {
	local since pinned newest code id
	nbx_phase "5: version pin"
	E2E_HOST=client
	e2e_on client "sed -n -E 's/^[Dd]jango==([^[:space:];]+).*/\\1/p' $NBX_ROOT/requirements.txt" || true
	pinned="$E2E_OUT"
	# The server reads pypi.org, because the client cannot: it is locked.
	E2E_HOST=server
	e2e_on server "curl -fsS --max-time 30 https://pypi.org/pypi/Django/json | jq -r .info.version" || true
	newest="$E2E_OUT"
	if [ "${E2E_DRY_RUN:-no}" != yes ] &&
		{ [ -z "$pinned" ] || [ -z "$newest" ] || [ "$pinned" = "$newest" ]; }; then
		for id in NBX-P5-PIP NBX-P5-403 NBX-P5-AUDIT; do
			e2e_skip "$id" "a Django newer than NetBox's pin is refused" \
				"NetBox pins django ${pinned:-unread} and PyPI's newest is ${newest:-unread}, so there is no newer version to ask for" \
				"internal/server/profile.go:314"
		done
		nbx_phase_drops 5
		return 0
	fi
	e2e_record NBX-P5-VERSIONS PASS "PyPI has a Django newer than NetBox's pin" "newer than ${pinned:-?}" \
		"${newest:-?}" "requirements.txt; curl https://pypi.org/pypi/Django/json" 0 ""

	nbx_lock_client || true
	since="$(nbx_now server)"
	E2E_HOST=client
	nbx_long client "rm -rf $NBX_WORK/p5-venv && python3 -m venv $NBX_WORK/p5-venv &&
		$nbx_pip_env $NBX_WORK/p5-venv/bin/pip install --dry-run 'django==$newest'" || true
	nbx_rc_fails NBX-P5-PIP "pip install --dry-run django==$newest fails under the pin" \
		"internal/server/pypi.go:110" "venv/bin/pip install --dry-run django==$newest"

	# A pinned index lists the pinned version alone, so pip never asks for the
	# newer wheel and its failure is "no matching distribution". The refusal
	# with 403 is the wheel route's, read directly.
	e2e_on client "curl -s -o /dev/null -w '%{http_code}' --max-time 60 '$E2E_BASE_URL/pypi/wheels/django-$newest-py3-none-any.whl'" || true
	code="$E2E_OUT"
	check_eq NBX-P5-403 "a Django wheel newer than the pin is refused with 403" "403" "$code" \
		"internal/server/profile.go:314" "GET /pypi/wheels/django-$newest-py3-none-any.whl from the client"

	# audit events has no --json (97-machine-readable counts it), so the table
	# is filtered to this one refusal and read for the name.
	E2E_HOST=server
	e2e_bodega server "audit events --type denied --client $nbx_client_addr --name django --since $since --limit 20" || true
	check_contains NBX-P5-AUDIT "the refusal is in the audit trail from the client's address" "profile_constraint" \
		"$E2E_OUT" "internal/server/profile.go:328" \
		"bodega audit events --type denied --client $nbx_client_addr --name django --since $since"
	nbx_phase_drops 5
}

# ---- phase 6 -----------------------------------------------------------------

nbx_phase6() {
	local ws
	nbx_phase "6: upstream outage"
	E2E_HOST=server
	# shellcheck disable=SC2016  # expanded by the server's shell
	e2e_on server 'printf "%s" "${SSH_CONNECTION%% *}"' || true
	ws="${E2E_OUT:-192.0.2.3}"
	# The server's own address first: the lock's self-check connects to the
	# first address on 8080, and only the server listens there. Traffic to
	# its own address leaves through lo, which the lock already accepts, so
	# naming it widens nothing.
	if ! e2e_egress_lock server "$nbx_server_addr" "$nbx_client_addr" "$ws"; then
		e2e_record NBX-P6-LOCK FAIL "the server is cut off from every upstream" "lock holds" \
			"e2e_egress_lock refused or did not hold; its stderr is in the run output" \
			"e2e_egress_lock server $nbx_server_addr $nbx_client_addr $ws" 1 "test/e2e/lib/egress.sh:269"
		nbx_phase_drops 6
		return 0
	fi
	nbx_locked_server=yes
	e2e_record NBX-P6-LOCK PASS "the server is cut off from every upstream" "lock holds" "lock holds" \
		"e2e_egress_lock server $nbx_server_addr $nbx_client_addr $ws" 0 "test/e2e/lib/egress.sh:269"
	e2e_on server "curl -m 5 -sS -o /dev/null https://pypi.org/simple/" || true
	nbx_rc_fails NBX-P6-CUT "the server cannot reach pypi.org" "test/e2e/lib/egress.sh" \
		"curl -m 5 https://pypi.org/simple/ on the server"

	nbx_lock_client || true
	nbx_remove NBX-P6
	nbx_install NBX-P6

	E2E_HOST=server
	e2e_egress_unlock server || true
	nbx_rc NBX-P6-UNLOCK "the server's lock is removed before the restore" "test/e2e/lib/egress.sh:317" \
		"e2e_egress_unlock server"
	[ "$E2E_RC" = 0 ] && nbx_locked_server=no
	nbx_phase_drops 6
}

# ---- phase 7 -----------------------------------------------------------------

nbx_phase7() {
	local t m want n role
	nbx_phase "7: restore"
	nbx_cleanup

	for role in client server; do
		E2E_HOST="$role"
		n="$(e2e_egress_drops "$role" 2>&1)"
		case "${E2E_DRY_RUN:-no}:$n" in
		yes:* | *"no egress lock on"*)
			e2e_record "NBX-RESTORE-LOCK-$role" PASS "the $role carries no egress lock" "no lock" "no lock" \
				"e2e_egress_drops $role" 0 "test/e2e/lib/egress.sh:334"
			;;
		*)
			e2e_record "NBX-RESTORE-LOCK-$role" FAIL "the $role carries no egress lock" "no lock" \
				"$(e2e_excerpt "$n")" "e2e_egress_drops $role" 1 "test/e2e/lib/egress.sh:334"
			;;
		esac
	done

	E2E_HOST=server
	e2e_config_get server '.discover_mode // ""' || true
	check_eq NBX-RESTORE-DISCOVER "discover_mode is what it was before the run" "$nbx_prior_discover" "$E2E_OUT" \
		"test/e2e/suites/58-realworld-netbox.sh" "jq .discover_mode /etc/bodega/config.json"
	e2e_bodega server "policy mode list" || true
	for t in $NBX_TYPES; do
		want=""
		for m in $nbx_prior_modes; do
			[ "${m%%=*}" = "$t" ] && want="${m#*=}"
		done
		check_eq "NBX-RESTORE-MODE-$t" "$t's admission mode is what it was before the run" "$want" \
			"$(printf '%s\n' "$E2E_OUT" | awk -v t="$t" '$1 == t { print $2 }')" \
			"cmd/bodega/cmd_policy_rollout.go:93" "bodega policy mode list"
	done
	e2e_bodega server "identity list" || true
	check_lacks NBX-RESTORE-CIDR "the client's /32 is unbound" "$nbx_client_addr/32" "$E2E_OUT" \
		"cmd/bodega/cmd_identity.go" "bodega identity list"
	e2e_bodega server "profile list" || true
	check_lacks NBX-RESTORE-PROFILE "profile $NBX_PROFILE is gone" "$NBX_PROFILE " "$E2E_OUT" \
		"cmd/bodega/cmd_profile.go:27; there is no profile delete (F72)" "bodega profile delete $NBX_PROFILE; bodega profile list"

	E2E_HOST=client
	e2e_on client "test -e $NBX_ROOT && echo $NBX_ROOT; test -e $NBX_WORK && echo $NBX_WORK;
		command -v psql >/dev/null 2>&1 && (cd /tmp && sudo -u postgres psql -tAc \"SELECT 'netbox database' FROM pg_database WHERE datname = 'netbox'\" 2>/dev/null); true" || true
	check_eq NBX-RESTORE-NETBOX "no NetBox tree, venv or database is left on the client" "" "$E2E_OUT" \
		"test/e2e/suites/58-realworld-netbox.sh" "test -e $NBX_ROOT; psql -c 'SELECT datname FROM pg_database'"
}

# ---- run ---------------------------------------------------------------------

nbx_main() {
	nbx_preflight || return 0
	trap nbx_on_exit EXIT
	trap 'exit 130' INT TERM
	if nbx_phase0 && nbx_phase1; then
		nbx_phase2
		nbx_phase3
		nbx_phase4
		nbx_phase5
		nbx_phase6
	else
		E2E_HOST=local
		e2e_block NBX-BLOCK "phases 2 to 6" "the lock or the profile phase 1 builds on was not in place; see the FAIL above"
	fi
	nbx_phase7
}

nbx_main
nbx_cleanup
nbx_restore_traps
unset -f nbx_main nbx_on_exit nbx_restore_traps
