#!/bin/sh
# bodega client setup. Served at GET /client/setup.sh.
#
# Applies the plan GET /client/plan.txt returns for this host. The script is
# the same bytes for every host and decides nothing itself: which files, where
# they go and what they hold all come from the plan, and every file is checked
# against the plan's SHA-256 before anything on this host changes. Compare
# this file's SHA-256 with client_setup_sha256 in /api/v1/status before
# running it.
#
# Needs only sh, curl or fetch(1), sha256sum or sha256(1), awk, diff and cmp.

set -eu
umask 022

prog=bodega-setup

usage() {
	cat <<'EOF'
usage: sh setup.sh --url <bodega base URL> [--apply] [--systems a,b] [--allow-plaintext]

  --url <base>        where bodega answers, e.g. https://bodega.internal
                      (or set BODEGA_URL)
  --apply             back up each file that differs, then write it.
                      Without it the script prints a diff and writes nothing.
  --systems a,b       only these systems; the plan lists the rest
  --allow-plaintext   permit an http:// URL. Without TLS the plan and the
                      files could be rewritten in transit, digests included.

A host identified by a token reads it from BODEGA_TOKEN, so the token never
appears in a process listing. A host bound by address needs none.
EOF
}

die() {
	printf '%s: %s\n' "$prog" "$*" >&2
	exit 1
}

base=${BODEGA_URL:-}
token=${BODEGA_TOKEN:-}
apply=no
plaintext=no
systems=

while [ $# -gt 0 ]; do
	case $1 in
	--url)
		[ $# -ge 2 ] || die "--url needs a value, e.g. --url https://bodega.internal"
		base=$2
		shift
		;;
	--url=*) base=${1#--url=} ;;
	--systems)
		[ $# -ge 2 ] || die "--systems needs a comma-separated list, e.g. --systems pypi,npm"
		systems=$2
		shift
		;;
	--systems=*) systems=${1#--systems=} ;;
	--apply) apply=yes ;;
	--allow-plaintext) plaintext=yes ;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown argument: $1. Run with --help for the options" ;;
	esac
	shift
done

[ -n "$base" ] || die "no bodega URL. Pass --url https://bodega.internal, or set BODEGA_URL"
base=${base%/}

case $token in
*[!A-Za-z0-9_.-]*) die "BODEGA_TOKEN holds characters no bodega token has; check what was pasted into it" ;;
esac

# The same rule `bodega serve` applies: plain http only when asked for, and a
# token never over it unless asked for.
case $base in
https://*) ;;
http://*)
	if [ "$plaintext" != yes ]; then
		if [ -n "$token" ]; then
			die "refusing to send BODEGA_TOKEN to $base over plain http: anything on the path can read it. Use https, or pass --allow-plaintext on a link you trust"
		fi
		die "refusing plain http to $base: the plan and its files could be rewritten in transit, digests included. Use https, or pass --allow-plaintext on a link you trust"
	fi
	;;
*) die "$base is not an http:// or https:// URL. Pass --url https://bodega.internal" ;;
esac

# ---- what this host is -----------------------------------------------------
#
# The server cannot see these, so the host states them. lsb_release is absent
# from minimal images; /etc/os-release is not.

os=$(uname -s | tr '[:upper:]' '[:lower:]')
abi=
codename=
case $os in
linux)
	if [ -r /etc/os-release ]; then
		codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release | tr -d "\"'" | sed -n 1p)
	fi
	case $codename in
	*[!a-z0-9.+-]*)
		printf '%s: ignoring VERSION_CODENAME=%s from /etc/os-release, which is not an apt suite name\n' "$prog" "$codename" >&2
		codename=
		;;
	esac
	;;
freebsd)
	# stdin closed: on a host where pkg is not bootstrapped yet, the stub asks
	# whether to install it and would otherwise wait for an answer.
	abi=$(pkg config abi </dev/null 2>/dev/null || true)
	case $abi in
	'' | *[!A-Za-z0-9:._-]*)
		printf '%s: pkg config abi gave no ABI, so the plan cannot name a pkg repository for this host\n' "$prog" >&2
		abi=
		;;
	esac
	;;
*) die "this host runs $(uname -s), and bodega configures two operating systems: linux and freebsd" ;;
esac

query="os=$os"
[ -z "$abi" ] || query="$query&abi=$abi"
[ -z "$codename" ] || query="$query&codename=$(printf '%s' "$codename" | sed 's/+/%2B/g')"

# ---- tools -----------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
	fetcher=curl
elif command -v fetch >/dev/null 2>&1; then
	fetcher=fetch
else
	die "neither curl nor fetch is on PATH. Install curl; FreeBSD has fetch(1) in its base system"
fi
if command -v sha256sum >/dev/null 2>&1; then
	sha256_of() { sha256sum <"$1" | cut -d ' ' -f 1; }
elif command -v sha256 >/dev/null 2>&1; then
	sha256_of() { sha256 -q "$1"; }
else
	die "neither sha256sum nor sha256 is on PATH, so no file could be checked against the plan"
fi
for t in diff cmp; do
	command -v "$t" >/dev/null 2>&1 || die "$t is not on PATH; it ships in the base system of every host bodega configures"
done

work=$(mktemp -d "${TMPDIR:-/tmp}/bodega-setup.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# get <url> <file>. Every URL passes the plain-http rule, not only the base:
# the plan's URLs carry the server's public_url, which can differ from --url.
get() {
	case $1 in
	https://*) ;;
	http://*)
		[ "$plaintext" = yes ] ||
			die "the plan names $1, which is plain http, and --allow-plaintext is not set. Set public_url on the server to https, or pass --allow-plaintext on a link you trust"
		;;
	*) die "the plan names $1, which is not an http or https URL; refusing to fetch it" ;;
	esac
	if [ "$fetcher" = curl ]; then
		# The header goes in on stdin as curl configuration, so the token is
		# never an argument ps can show.
		if ! code=$(
			if [ -n "$token" ]; then printf 'header = "Authorization: Bearer %s"\n' "$token"; fi |
				curl --silent --show-error --proto =http,https --max-time 120 \
					--config - --output "$2" --write-out '%{http_code}' "$1"
		); then
			die "could not reach $1. Check that $base answers from this host"
		fi
		if [ "$code" != 200 ]; then
			printf '%s: GET %s answered %s:\n' "$prog" "$1" "$code" >&2
			sed -n '1,20s/^/  /p' "$2" >&2
			exit 1
		fi
	elif [ -n "$token" ]; then
		HTTP_AUTH="basic:*:bodega:$token" fetch -q -A -o "$2" "$1" ||
			die "GET $1 failed; fetch printed why above. Re-run with curl installed to see the server's own explanation"
	else
		fetch -q -A -o "$2" "$1" ||
			die "GET $1 failed; fetch printed why above. Re-run with curl installed to see the server's own explanation"
	fi
}

# dec reverses plan.txt's field encoding: "-" is empty, anything else is
# printf %b escapes.
dec() {
	if [ "$1" = - ]; then
		printf ''
	else
		printf '%b' "$1"
	fi
}

# keep <system> <existing> <planned> <out> writes planned to out with the credential
# `bodega doctor --write-credentials` placed in existing carried over, on the
# two files it shares with the plan: npm's fenced block or bare
# //host/npm/:_authToken= line, and helm's repository item named bodega when
# it carries a password. Without this the plan's whole-file write erases the
# token and npm and helm go on working unattributed. The result is what that
# writer would make of the planned file, so the two converge in either order.
# internal/clientconf KeepCredential is the same rule, held to it by a test.
keep() {
	case $1 in
	npm | helm) ;;
	*)
		cat "$3" >"$4"
		return
		;;
	esac
	if [ ! -s "$2" ]; then
		cat "$3" >"$4"
		return
	fi
	rc=0
	awk -v sys="$1" '
	function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
	function isbegin(s) { return index(trim(s), "# BEGIN bodega credential") == 1 }
	function isend(s) { return index(trim(s), "# END bodega credential") == 1 }
	function indent(s) { match(s, /^ */); return RLENGTH }
	function field(s) { s = trim(s); sub(/^-/, "", s); return trim(s) }
	# itemend(a, n, i): the index past the sequence item opening at a[i], or i.
	function itemend(a, n, i,    e, d) {
		if (substr(trim(a[i]), 1, 1) != "-") return i
		d = indent(a[i])
		for (e = i + 1; e <= n && trim(a[e]) != "" && indent(a[e]) > d; e++) ;
		return e
	}
	function named(a, i, e,    k, v) {
		for (k = i; k < e; k++) {
			v = field(a[k])
			if (index(v, "name:") == 1) {
				v = trim(substr(v, 6)); gsub(/^["\047]|["\047]$/, "", v)
				return v == "bodega"
			}
		}
		return 0
	}
	function haspw(a, i, e,    k) {
		for (k = i; k < e; k++) if (index(field(a[k]), "password:") == 1) return 1
		return 0
	}
	FILENAME == ARGV[1] { old[++n] = $0; next }
	{ plan[++m] = $0 }
	END {
		kc = 0
		if (sys == "npm") {
			for (i = 1; i <= n; i++) {
				if (isbegin(old[i])) {
					for (j = i + 1; j <= n && !isend(old[j]); j++) ;
					if (j <= n) { for (k = i; k <= j; k++) kept[++kc] = old[k]; i = j; continue }
				}
				if (trim(old[i]) ~ /^\/\/[^ \t]+\/npm\/:_authToken=/) kept[++kc] = old[i]
			}
			for (i = 1; i <= m; i++) out[++oc] = plan[i]
		} else {
			for (i = 1; i <= n; ) {
				e = itemend(old, n, i)
				if (e == i) { i++; continue }
				if (named(old, i, e) && haspw(old, i, e)) {
					s = i; t = e - 1
					if (i > 1 && e <= n && isbegin(old[i - 1]) && isend(old[e])) { s = i - 1; t = e }
					for (k = s; k <= t; k++) kept[++kc] = old[k]
					break
				}
				i = e
			}
			for (i = 1; i <= m; ) {
				e = itemend(plan, m, i)
				if (e == i) { out[++oc] = plan[i]; i++; continue }
				if (!named(plan, i, e)) for (k = i; k < e; k++) out[++oc] = plan[k]
				i = e
			}
		}
		if (kc == 0) exit 3
		for (i = 1; i <= oc; i++) print out[i]
		for (i = 1; i <= kc; i++) print kept[i]
	}' "$2" "$3" >"$4" || rc=$?
	case $rc in
	0) ;;
	3) cat "$3" >"$4" ;;
	*) die "could not read $2 to carry its credential over; nothing was written" ;;
	esac
}

# redact <file> prints it with every secret replaced by <redacted>: the
# password of a user:pass@ URL, keeping the user; the whole userinfo of an
# http or https URL with no password, which is a token (an ssh:// user is an
# account name and stays); everything after an Authorization: header name but
# the scheme, anywhere in the line; and the value of a YAML `key: value` or an
# ini `key = value` whose key, case folded, ends in password, passwd, token,
# secret, _auth or _key, or is apikey. The diff lands in a terminal and often
# a CI log, and the host's file can hold a credential bodega never wrote.
# internal/clientconf Redact is the same rule, and a test runs both over one
# table of lines.
redact() {
	awk '
	function secret(k) {
		k = tolower(k); gsub(/^["\047]|["\047]$/, "", k)
		return k ~ /(password|passwd|token|secret|_auth|_key)$/ || k == "apikey"
	}
	{
		line = $0; out = ""
		while (match(line, /:\/\/[^\/:@ \t]+:[^\/@ \t]+@/)) {
			seg = substr(line, RSTART, RLENGTH)
			user = substr(seg, 4); user = substr(user, 1, index(user, ":") - 1)
			out = out substr(line, 1, RSTART - 1) "://" user ":<redacted>@"
			line = substr(line, RSTART + RLENGTH)
		}
		line = out line; out = ""
		while (match(line, /[Hh][Tt][Tt][Pp][Ss]?:\/\/[^\/?#:@ \t]+@/)) {
			seg = substr(line, RSTART, RLENGTH)
			out = out substr(line, 1, RSTART - 1) substr(seg, 1, index(seg, "://") + 2) "<redacted>@"
			line = substr(line, RSTART + RLENGTH)
		}
		line = out line
		if (match(tolower(line), /authorization[ \t]*:[ \t]*/)) {
			head = substr(line, 1, RSTART + RLENGTH - 1); rest = substr(line, RSTART + RLENGTH)
			if (match(rest, /^[A-Za-z][A-Za-z0-9._~+-]*[ \t]+[^ \t]/)) {
				head = head substr(rest, 1, RLENGTH - 1); rest = substr(rest, RLENGTH)
			}
			if (rest ~ /^[^ \t]/) line = head "<redacted>"
		}
		head = ""
		if (match(line, /^[ \t]*(-[ \t]+)?[A-Za-z0-9_.-]+[ \t]*:([ \t]|$)/)) {
			head = substr(line, 1, RLENGTH); key = head
			sub(/^[ \t]*(-[ \t]+)?/, "", key); sub(/[ \t]*:[ \t]*$/, "", key)
		} else if ((eq = index(line, "=")) > 0) {
			head = substr(line, 1, eq); key = substr(line, 1, eq - 1)
			sub(/^[ \t]+/, "", key); sub(/[ \t]+$/, "", key)
		}
		if (head != "") {
			rest = substr(line, length(head) + 1)
			match(rest, /^[ \t]*/)
			if (RLENGTH < length(rest) && secret(key)) line = head substr(rest, 1, RLENGTH) "<redacted>"
		}
		print line
	}' "$1"
}

# ---- the plan --------------------------------------------------------------

get "$base/client/plan.txt?$query" "$work/plan.txt"

tab=$(printf '\t')
all=
header=
while IFS=$tab read -r identity profile match system action path url sha reason <&3; do
	case $system in
	'' | *[!a-z0-9_-]*) die "the plan holds a record for system '$system', which is not a system name; refusing to read the rest of it" ;;
	esac
	case " $all " in
	*" $system "*) ;;
	*) all="${all:+$all }$system" ;;
	esac
	if [ -z "$header" ]; then
		prof="profile $(dec "$profile")"
		[ "$profile" != - ] || prof="no profile"
		header="Plan for $(dec "$identity") ($prof, matched by $(dec "$match")) from $base"
	fi
done 3<"$work/plan.txt"
[ -n "$all" ] || die "$base returned an empty plan; check the server's log for the request"
printf '%s\n\n' "$header"

want=
if [ -n "$systems" ]; then
	for s in $(printf '%s' "$systems" | tr ',' ' '); do
		case " $all " in
		*" $s "*) want="$want $s" ;;
		*) die "the plan lists no system named $s. It lists: $(printf '%s' "$all" | sed 's/ /, /g')" ;;
		esac
	done
fi
selected() {
	[ -z "$want" ] && return 0
	case "$want " in
	*" $1 "*) return 0 ;;
	esac
	return 1
}

# Refusals first, before any fetch. A system named on --systems that the plan
# will not install stops the run: the operator asked for it by name.
blocked=
while IFS=$tab read -r identity profile match system action path url sha reason <&3; do
	selected "$system" || continue
	case $action in
	install) ;;
	refuse | skip)
		if [ -n "$want" ]; then
			blocked="$blocked
  $system ($action): $(dec "$reason")"
		else
			printf '%-8s %-10s %s\n' "$action" "$system" "$(dec "$reason")"
		fi
		;;
	*) die "the plan holds action '$action' for $system, which this script does not know. Fetch the script again from $base/client/setup.sh" ;;
	esac
done 3<"$work/plan.txt"
if [ -n "$blocked" ]; then
	die "the plan installs nothing for a system you named, so nothing was written:$blocked"
fi

# Every file is fetched and checked before any is compared or written, so a
# mismatch anywhere leaves the host as it was.
n=0
: >"$work/changes"
while IFS=$tab read -r identity profile match system action path url sha reason <&3; do
	selected "$system" || continue
	[ "$action" = install ] || continue
	n=$((n + 1))
	path=$(dec "$path")
	url=$(dec "$url")
	case $sha in
	*[!0-9a-f]* | '') die "the plan gives $system no SHA-256 for $path, so the file could not be checked; nothing was written" ;;
	esac
	# shellcheck disable=SC2088 # the plan's literal ~, expanded below
	case $path in
	'~/'*)
		[ -n "${HOME:-}" ] || die "the plan puts $system in $path and HOME is unset"
		target=$HOME/${path#"~/"}
		;;
	/*) target=$path ;;
	*) die "the plan puts $system at $path, which is not an absolute path; refusing to write it" ;;
	esac
	get "$url" "$work/$n"
	got=$(sha256_of "$work/$n")
	if [ "$got" != "$sha" ]; then
		die "$system: $url does not match the plan, so nothing on this host was changed.
  plan says:  $sha
  file is:    $got
  The file changed between the plan and the fetch, or something between this host and $base rewrote it.
  Re-run to rule out the first. If it repeats, fetch $url from another host and compare before trusting this path"
	fi
	printf '%s\t%s\t%s\n' "$n" "$system" "$target" >>"$work/changes"
done 3<"$work/plan.txt"

# ---- compare ---------------------------------------------------------------

changed=0
: >"$work/writes"
while IFS=$tab read -r n system target <&3; do
	if [ -e "$target" ] && [ ! -f "$target" ]; then
		die "$target exists and is not a regular file; move it aside, then re-run. Nothing was written"
	fi
	old=/dev/null
	[ ! -f "$target" ] || old=$target
	keep "$system" "$old" "$work/$n" "$work/$n.new"
	if [ -f "$target" ] && cmp -s "$target" "$work/$n.new"; then
		printf 'unchanged  %-10s %s\n' "$system" "$target"
		continue
	fi
	shown=/dev/null
	if [ -f "$target" ]; then
		shown=$work/$n.old.shown
		redact "$target" >"$shown"
	fi
	redact "$work/$n.new" >"$work/$n.new.shown"
	printf '\n'
	if diff -u -L "$target" -L "$target (bodega)" "$shown" "$work/$n.new.shown"; then
		:
	else
		[ $? -eq 1 ] || die "diff could not compare $target with the planned file"
	fi
	changed=$((changed + 1))
	printf '%s\t%s\t%s\n' "$n" "$system" "$target" >>"$work/writes"
done 3<"$work/changes"

if [ "$changed" -eq 0 ]; then
	printf '\nNothing to change: every file already matches the plan.\n'
	exit 0
fi
if [ "$apply" != yes ]; then
	printf '\nDry run: nothing was written. Re-run with --apply to back up and write the %s file(s) above.\n' "$changed"
	exit 0
fi

# ---- apply -----------------------------------------------------------------

# Every target is checked writable before the first write, so a run that
# lacks root for /etc stops before it has changed ~ and left /etc behind.
while IFS=$tab read -r n system target <&3; do
	probe=$(dirname "$target")
	while [ ! -d "$probe" ]; do probe=$(dirname "$probe"); done
	if [ ! -w "$probe" ] || { [ -e "$target" ] && [ ! -w "$target" ]; }; then
		die "cannot write $target as $(id -un). Nothing was written. Re-run as the account that owns it, or as root for paths under /etc and /usr/local/etc"
	fi
done 3<"$work/writes"

# Reversed, because the plan lists a system's own file before the companion
# it depends on: the keyring a Signed-By: line names, the check make.conf
# includes. Writing the dependency first means a failure leaves the old
# configuration working rather than pointing at a file that is not there.
stamp=$(date -u +%Y%m%dT%H%M%SZ)
sed -n '1!G;h;$p' "$work/writes" >"$work/order"
written=
while IFS=$tab read -r n system target <&3; do
	mkdir -p "$(dirname "$target")" || die "could not create $(dirname "$target").${written:+ Already written, each beside its backup:$written}"
	if [ -e "$target" ]; then
		cp -p "$target" "$target.bodega-$stamp" || die "could not back up $target, so it was not written.${written:+ Already written, each beside its backup:$written}"
		printf 'backed up  %s -> %s\n' "$target" "$target.bodega-$stamp"
	fi
	cat "$work/$n.new" >"$target" || die "writing $target failed; restore it from $target.bodega-$stamp.${written:+ Already written:$written}"
	printf 'wrote      %s\n' "$target"
	written="$written $target"
done 3<"$work/order"

printf '\nApplied %s file(s). Each replaced file sits beside its backup, suffixed .bodega-%s.\n' "$changed" "$stamp"
