# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
#
# Locks a guest's outbound traffic to named addresses, so a client that fetched
# through bodega can be told from one that fell back to upstream. Without it
# every guest has an open route to the internet and a passing `pip install`
# says nothing about where the bytes came from.
#
# The lock lives in the guest, because the guests run under UTM on the
# workstation and there is no network between them the harness controls:
# nftables on Linux, pf on FreeBSD. DNS is blocked with the rest of UDP on
# purpose. 10-ship-install writes /etc/hosts for every name a suite uses, so a
# resolver query during a locked run is a client reaching for upstream.
#
# Every lock arms a deadman on the guest that removes it after 30 minutes, so a
# harness that dies mid-run leaves a guest that heals itself instead of one
# that answers ssh and nothing else.

[ -n "${E2E_LIB_EGRESS:-}" ] && return 0
E2E_LIB_EGRESS=1

# shellcheck source=remote.sh
. "${BASH_SOURCE[0]%/*}/remote.sh"

E2E_EGRESS_DEADMAN_UNIT="bodega-e2e-egress-deadman"
# pf keeps nothing on disk across a reboot, and neither does /var/run.
E2E_EGRESS_PF_STATE="/var/run/bodega-e2e-egress"
# An address the guest would reach unlocked, so a probe that fails is a probe
# the lock stopped rather than one no route could carry.
E2E_EGRESS_PROBE_IP="${E2E_EGRESS_PROBE_IP:-1.1.1.1}"
E2E_EGRESS_PROBE_PORT="${E2E_EGRESS_PROBE_PORT:-443}"

# Every address reaches a rule file loaded as root, so anything but digits,
# dots and colons is refused before a rule is printed.
e2e_egress_check_ips() {
	local ip o
	if [ "$#" -eq 0 ]; then
		printf 'e2e: egress lock needs at least one allowed address\n' >&2
		return 2
	fi
	for ip in "$@"; do
		case "$ip" in
		'' | *[!0-9.:]*)
			printf 'e2e: egress lock refuses %q: an address holds only digits, dots and colons\n' "$ip" >&2
			return 2
			;;
		*:*) continue ;;
		esac
		if ! [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
			printf 'e2e: egress lock refuses %q: not a dotted-quad IPv4 address\n' "$ip" >&2
			return 2
		fi
		for o in ${ip//./ }; do
			if [ "$((10#$o))" -gt 255 ]; then
				printf 'e2e: egress lock refuses %q: octet %s is out of range\n' "$ip" "$o" >&2
				return 2
			fi
		done
	done
}

e2e_egress_rules_nft() {
	e2e_egress_check_ips "$@" || return 2
	local ip
	printf 'table inet bodega_e2e {\n'
	printf '\tcounter dropped {\n\t}\n'
	printf '\tchain output {\n'
	printf '\t\ttype filter hook output priority filter; policy drop;\n'
	printf '\t\toifname "lo" accept\n'
	printf '\t\tct state established,related accept\n'
	for ip in "$@"; do
		case "$ip" in
		*:*)
			printf '\t\tip6 daddr %s meta l4proto ipv6-icmp accept\n' "$ip"
			printf '\t\tip6 daddr %s meta l4proto tcp accept\n' "$ip"
			;;
		*)
			printf '\t\tip daddr %s meta l4proto icmp accept\n' "$ip"
			printf '\t\tip daddr %s meta l4proto tcp accept\n' "$ip"
			;;
		esac
	done
	printf '\t\tcounter name "dropped" drop\n'
	printf '\t}\n}\n'
}

# pf has no "established" match; its state table is that. A connection opened
# before the lock (the ssh session applying it, above all) has no state when pf
# was off, so the inbound pass creates state from any packet, and sloppy
# tracking accepts a flow whose handshake it never saw. Without it the guest's
# replies to that session hit the block and the harness loses the guest.
e2e_egress_rules_pf() {
	e2e_egress_check_ips "$@" || return 2
	local ip
	printf 'pass in quick all flags any keep state (sloppy)\n'
	printf 'pass out quick on lo0 all\n'
	for ip in "$@"; do
		case "$ip" in
		*:*)
			printf 'pass out quick inet6 proto icmp6 to %s keep state\n' "$ip"
			printf 'pass out quick inet6 proto tcp to %s keep state\n' "$ip"
			;;
		*)
			printf 'pass out quick inet proto icmp to %s keep state\n' "$ip"
			printf 'pass out quick inet proto tcp to %s keep state\n' "$ip"
			;;
		esac
	done
	printf 'block drop out quick all\n'
}

# remote.sh spells the second FreeBSD guest freebsd-server; accept either.
e2e_egress_alias() { printf '%s' "${1//_/-}"; }

# Read from the guest, never inferred from the role. A dry run reaches no guest
# and takes Linux.
e2e_egress_os() {
	local alias="$1"
	if [ "${E2E_DRY_RUN:-no}" = yes ]; then
		printf 'Linux'
		return 0
	fi
	e2e_on "$alias" "uname -s" >/dev/null 2>&1 || {
		printf 'e2e: could not read uname -s on %s (%s): rc=%s %s\n' \
			"$alias" "$(e2e_host_for "$alias")" "$E2E_RC" "$E2E_ERR" >&2
		return 1
	}
	case "$E2E_OUT" in
	Linux | FreeBSD) printf '%s' "$E2E_OUT" ;;
	*)
		printf 'e2e: %s (%s) runs %q; the egress lock knows Linux and FreeBSD\n' \
			"$alias" "$(e2e_host_for "$alias")" "$E2E_OUT" >&2
		return 1
		;;
	esac
}

e2e_egress_unlock_script_linux() {
	cat <<E2EEGRESS
systemctl stop $E2E_EGRESS_DEADMAN_UNIT.timer $E2E_EGRESS_DEADMAN_UNIT.service 2>/dev/null
systemctl reset-failed $E2E_EGRESS_DEADMAN_UNIT.timer $E2E_EGRESS_DEADMAN_UNIT.service 2>/dev/null
if nft list table inet bodega_e2e >/dev/null 2>&1; then
	nft delete table inet bodega_e2e
fi
E2EEGRESS
}

# The deadman runs this same text, so it must not kill itself: it removes the
# pidfile before it gets here.
e2e_egress_unlock_script_freebsd() {
	cat <<E2EEGRESS
dir=$E2E_EGRESS_PF_STATE
if [ -f "\$dir/deadman.pid" ]; then
	kill "\$(cat "\$dir/deadman.pid")" 2>/dev/null
fi
pfctl -a bodega_e2e -F all 2>/dev/null
if [ "\$(cat "\$dir/hook_added" 2>/dev/null)" = yes ]; then
	pfctl -sr 2>/dev/null | grep -v '^anchor "bodega_e2e"' | pfctl -R -f -
fi
if [ "\$(cat "\$dir/pf_was_enabled" 2>/dev/null)" = no ]; then
	pfctl -d 2>/dev/null
fi
rm -rf "\$dir"
true
E2EEGRESS
}

# The deadman is armed before the rules load, so a lock that half-applies is
# still removed on time. One transaction replaces the table: declaring it first
# makes the delete safe on a guest with no lock yet.
e2e_egress_lock_script_linux() {
	local rules="$1"
	cat <<E2EEGRESS
set -eu
nft=\$(command -v nft) || { echo "nft is not installed" >&2; exit 1; }
systemctl stop $E2E_EGRESS_DEADMAN_UNIT.timer $E2E_EGRESS_DEADMAN_UNIT.service 2>/dev/null || true
systemctl reset-failed $E2E_EGRESS_DEADMAN_UNIT.timer $E2E_EGRESS_DEADMAN_UNIT.service 2>/dev/null || true
systemd-run --quiet --on-active=30m --unit=$E2E_EGRESS_DEADMAN_UNIT "\$nft" delete table inet bodega_e2e
"\$nft" -f - <<'E2EEGRESSRULES'
table inet bodega_e2e
delete table inet bodega_e2e
$rules
E2EEGRESSRULES
E2EEGRESS
}

# pf_was_enabled and hook_added are written by the first lock only: a second
# lock would otherwise record the state the first one created, and unlock would
# leave pf on.
e2e_egress_lock_script_freebsd() {
	local rules="$1"
	cat <<E2EEGRESS
set -eu
dir=$E2E_EGRESS_PF_STATE
mkdir -p "\$dir"
if [ -f "\$dir/deadman.pid" ]; then
	kill "\$(cat "\$dir/deadman.pid")" 2>/dev/null || true
	rm -f "\$dir/deadman.pid"
fi
kldstat -q -m pf || kldload pf
if [ ! -f "\$dir/pf_was_enabled" ]; then
	if pfctl -s info 2>/dev/null | grep -q '^Status: Enabled'; then echo yes; else echo no; fi >"\$dir/pf_was_enabled"
fi
if [ ! -f "\$dir/hook_added" ]; then
	if pfctl -sr 2>/dev/null | grep -q '^anchor "bodega_e2e"'; then
		echo no >"\$dir/hook_added"
	else
		{ pfctl -sr 2>/dev/null; echo 'anchor "bodega_e2e"'; } | pfctl -R -f -
		echo yes >"\$dir/hook_added"
	fi
fi
cat >"\$dir/remove.sh" <<'E2EEGRESSREMOVE'
$(e2e_egress_unlock_script_freebsd)
E2EEGRESSREMOVE
cat >"\$dir/deadman.sh" <<'E2EEGRESSDEADMAN'
trap 'kill "\$!" 2>/dev/null; exit 0' TERM
sleep 1800 &
wait "\$!"
rm -f $E2E_EGRESS_PF_STATE/deadman.pid
exec sh $E2E_EGRESS_PF_STATE/remove.sh
E2EEGRESSDEADMAN
daemon -f -p "\$dir/deadman.pid" sh "\$dir/deadman.sh"
pfctl -a bodega_e2e -f - <<'E2EEGRESSRULES'
$rules
E2EEGRESSRULES
pfctl -e 2>/dev/null || true
E2EEGRESS
}

# Prints the drop count, or exits 3 when no lock is loaded.
e2e_egress_drops_script() {
	case "$1" in
	Linux)
		cat <<'E2EEGRESS'
out=$(nft list counter inet bodega_e2e dropped 2>/dev/null) || exit 3
printf '%s\n' "$out" | awk '$1 == "packets" { print $2; exit }'
E2EEGRESS
		;;
	FreeBSD)
		cat <<'E2EEGRESS'
n=$(pfctl -a bodega_e2e -vsr 2>/dev/null | awk '
	/^block drop out/ { f = 1; next }
	f { for (i = 1; i < NF; i++) if ($i == "Packets:") { print $(i + 1); exit } }')
[ -n "$n" ] || exit 3
printf '%s\n' "$n"
E2EEGRESS
		;;
	esac
}

# A dropped SYN is never answered, so the 5-second timeout is how a locked
# connect fails.
e2e_egress_connects() {
	local alias="$1" os="$2" ip="$3" port="$4"
	case "$os" in
	Linux) e2e_on "$alias" "timeout 5 bash -c 'exec 3<>/dev/tcp/$ip/$port'" >/dev/null 2>&1 ;;
	FreeBSD) e2e_on "$alias" "timeout 5 nc -z -w 5 $ip $port" >/dev/null 2>&1 ;;
	esac
}

# e2e_egress_lock <role> <ip>...
#
# A ruleset that loads cleanly can still fail to hold: a quick rule in pf's
# main ruleset ahead of the anchor passes everything, and a drop in another
# nftables table stops bodega's own port. A lock that leaks turns every later
# "fetched through bodega" check into a vacuous pass, and one that over-blocks
# reads as a bodega outage, so both directions are probed before returning and
# a lock that fails either is removed.
e2e_egress_lock() {
	local alias host os rules ip observed=""
	alias="$(e2e_egress_alias "${1:?e2e_egress_lock <role> <ip>...}")"
	shift
	host="$(e2e_host_for "$alias")" || return 2
	e2e_egress_check_ips "$@" || return 2
	for ip in "$@"; do
		if [ "$ip" = "$E2E_EGRESS_PROBE_IP" ]; then
			printf 'e2e: egress lock on %s (%s): the probe address %s is in the allowed set; set E2E_EGRESS_PROBE_IP to one outside it\n' \
				"$alias" "$host" "$ip" >&2
			return 2
		fi
	done
	os="$(e2e_egress_os "$alias")" || return 1

	case "$os" in
	Linux)
		rules="$(e2e_egress_rules_nft "$@")"
		e2e_on "$alias" "sudo sh -s" <<<"$(e2e_egress_lock_script_linux "$rules")" >/dev/null 2>&1 || true
		;;
	FreeBSD)
		rules="$(e2e_egress_rules_pf "$@")"
		e2e_on "$alias" "sudo sh -s" <<<"$(e2e_egress_lock_script_freebsd "$rules")" >/dev/null 2>&1 || true
		;;
	esac
	if [ "$E2E_RC" -ne 0 ]; then
		observed="applying the rules exited $E2E_RC: $E2E_ERR"
	fi

	[ "${E2E_DRY_RUN:-no}" = yes ] && return 0

	if [ -z "$observed" ] && e2e_egress_connects "$alias" "$os" "$E2E_EGRESS_PROBE_IP" "$E2E_EGRESS_PROBE_PORT"; then
		observed="a TCP connect to $E2E_EGRESS_PROBE_IP:$E2E_EGRESS_PROBE_PORT, outside the allowed set, succeeded"
	fi
	if [ -z "$observed" ] && ! e2e_egress_connects "$alias" "$os" "$1" 8080; then
		observed="a TCP connect to the allowed $1:8080 did not complete within 5s"
	fi
	[ -z "$observed" ] && return 0

	local removed="was removed"
	e2e_egress_unlock "$alias" || removed="could not be removed; the deadman clears it within 30 minutes"
	printf 'e2e: egress lock on %s (%s, %s) did not hold and %s: %s\nrules:\n%s\n' \
		"$alias" "$host" "$os" "$removed" "$observed" "$rules" >&2
	return 1
}

# e2e_egress_unlock <role> — also disarms the deadman. Succeeds on a guest with
# no lock.
e2e_egress_unlock() {
	local alias host os
	alias="$(e2e_egress_alias "${1:?e2e_egress_unlock <role>}")"
	host="$(e2e_host_for "$alias")" || return 2
	os="$(e2e_egress_os "$alias")" || return 1
	case "$os" in
	Linux) e2e_on "$alias" "sudo sh -s" <<<"$(e2e_egress_unlock_script_linux)" >/dev/null 2>&1 || true ;;
	FreeBSD) e2e_on "$alias" "sudo sh -s" <<<"$(e2e_egress_unlock_script_freebsd)" >/dev/null 2>&1 || true ;;
	esac
	if [ "$E2E_RC" -ne 0 ]; then
		printf 'e2e: removing the egress lock on %s (%s) exited %s: %s\n' "$alias" "$host" "$E2E_RC" "$E2E_ERR" >&2
		return 1
	fi
}

# e2e_egress_drops <role> — one integer on stdout: packets dropped since the
# lock was applied, since a second lock reloads the counter at zero.
e2e_egress_drops() {
	local alias host os
	alias="$(e2e_egress_alias "${1:?e2e_egress_drops <role>}")"
	host="$(e2e_host_for "$alias")" || return 2
	os="$(e2e_egress_os "$alias")" || return 1
	if [ "${E2E_DRY_RUN:-no}" = yes ]; then
		printf '0\n'
		return 0
	fi
	e2e_on "$alias" "sudo sh -s" <<<"$(e2e_egress_drops_script "$os")" >/dev/null 2>&1 || true
	case "$E2E_RC:$E2E_OUT" in
	0:[0-9]*) printf '%s\n' "$E2E_OUT" ;;
	3:*)
		printf 'e2e: no egress lock on %s (%s)\n' "$alias" "$host" >&2
		return 1
		;;
	*)
		printf 'e2e: could not read the egress drop count on %s (%s): rc=%s out=%q %s\n' \
			"$alias" "$host" "$E2E_RC" "$E2E_OUT" "$E2E_ERR" >&2
		return 1
		;;
	esac
}
