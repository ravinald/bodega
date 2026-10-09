#!/bin/sh
# bodega osquery result-log shipper. Served at GET /client/osquery-ship.sh.
#
# For a host whose osquery config belongs to something other than bodega:
# reads osqueryd's filesystem log from the byte offset the last run recorded,
# and posts each new complete line to an osquery source in shipper mode.
# bodega's queries are snapshots, which the filesystem logger writes to
# osqueryd.snapshots.log rather than osqueryd.results.log, so that is the
# default. The offset moves only when bodega answers 2xx, so a failed post is
# retried whole on the next run. Run it from cron, as a user that can read
# the log and write the state file and nothing more. Compare this file's
# SHA-256 with osquery_ship_sha256 in /api/v1/status before running it.
#
# Needs only sh, curl, awk, wc, ls and mkdir.

set -eu
umask 077

prog=bodega-osquery-ship

usage() {
	cat <<'EOF'
usage: sh osquery-ship.sh --endpoint <url> --token-file <path> [options]

  --endpoint <url>     the source's base, the endpoint the plan's osquery
                       section names, e.g.
                       https://bodega.internal/api/v1/inventory/sources/osq-b
                       (or set BODEGA_OSQUERY_ENDPOINT)
  --token-file <path>  an inventory-scoped bodega token, in a file only this
                       user can read (mode 0600 or 0400)
  --log <path>         the osqueryd log bodega's snapshot queries land in
                       (default /var/log/osquery/osqueryd.snapshots.log)
  --state <path>       where the byte offset is kept
                       (default /var/db/bodega/osquery-ship.offset)
  --max-bytes <n>      most bytes one post carries (default 8388608)
  --allow-plaintext    permit an http:// endpoint

Each run posts what is new and exits. When the log shrinks or is replaced,
the next run starts again from the first byte.
EOF
}

die() {
	printf '%s: %s\n' "$prog" "$*" >&2
	exit 1
}

endpoint=${BODEGA_OSQUERY_ENDPOINT:-}
token_file=
log=/var/log/osquery/osqueryd.snapshots.log
state=/var/db/bodega/osquery-ship.offset
max_bytes=8388608
plaintext=no

while [ $# -gt 0 ]; do
	case $1 in
	--endpoint)
		[ $# -ge 2 ] || die "--endpoint needs a value"
		endpoint=$2
		shift 2
		;;
	--token-file)
		[ $# -ge 2 ] || die "--token-file needs a value"
		token_file=$2
		shift 2
		;;
	--log)
		[ $# -ge 2 ] || die "--log needs a value"
		log=$2
		shift 2
		;;
	--state)
		[ $# -ge 2 ] || die "--state needs a value"
		state=$2
		shift 2
		;;
	--max-bytes)
		[ $# -ge 2 ] || die "--max-bytes needs a value"
		max_bytes=$2
		shift 2
		;;
	--allow-plaintext)
		plaintext=yes
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
done

[ -n "$endpoint" ] || die "--endpoint is required: the endpoint in the osquery section of GET /client/plan"
[ -n "$token_file" ] || die "--token-file is required: a file holding a token from \`bodega token create <label> --scope inventory\`"
case $max_bytes in
'' | *[!0-9]*) die "--max-bytes wants a byte count, got $max_bytes" ;;
esac
[ "$max_bytes" -gt 0 ] || die "--max-bytes wants a positive byte count"
endpoint=${endpoint%/}
case $endpoint in
https://*) ;;
http://*)
	[ "$plaintext" = yes ] ||
		die "$endpoint is plain http, and --allow-plaintext is not set. The token would cross the network in the clear"
	;;
*) die "$endpoint is not an http or https URL" ;;
esac
command -v curl >/dev/null 2>&1 || die "curl is not on PATH. Install it (FreeBSD: pkg install curl)"

# The token file is refused when anyone but its owner can read it: the token
# posts inventory as any host the mapping knows, so it is a credential.
[ -r "$token_file" ] || die "cannot read $token_file"
case $(ls -l "$token_file") in
-rw-------* | -r--------*) ;;
*) die "$token_file can be read by users other than its owner. Run: chmod 600 $token_file" ;;
esac
token=$(cat "$token_file")
[ -n "$token" ] || die "$token_file is empty"

[ -r "$log" ] || die "cannot read $log. Check --log, and that this user can read osqueryd's log"

state_dir=$(dirname "$state")
[ -d "$state_dir" ] || die "$state_dir does not exist. Create it, writable by this user"

# One run at a time: two runs reading one offset would post the same lines
# twice. mkdir is atomic, which is the whole of the lock.
lock=$state.lock
if ! mkdir "$lock" 2>/dev/null; then
	die "another run holds $lock. If none is running, remove it"
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/$prog.XXXXXX")
trap 'rm -rf "$work"; rmdir "$lock" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM

# The state file holds the log's inode and the offset into it. A different
# inode is a rotated log, and a size below the offset is a truncated one;
# either way the new file is read from its start.
# POSIX has no stat(1), and ls -i on one named file is the portable read of
# an inode.
# shellcheck disable=SC2012
inode=$(ls -i "$log" | awk '{print $1}')
offset=0
if [ -s "$state" ]; then
	read -r saved_inode saved_offset <"$state" || true
	case ${saved_offset:-} in
	'' | *[!0-9]*) saved_offset=0 ;;
	esac
	if [ "${saved_inode:-}" = "$inode" ]; then
		offset=$saved_offset
	fi
fi
size=$(wc -c <"$log" | awk '{print $1}')
if [ "$size" -lt "$offset" ]; then
	offset=0
fi
if [ "$size" -eq "$offset" ]; then
	printf '%s %s\n' "$inode" "$offset" >"$state"
	exit 0
fi

# Everything past the offset, then only the complete lines of it, up to
# max_bytes. wc -l counts newlines, so a line osqueryd is still writing is
# never one of them. awk runs under LC_ALL=C so length() counts bytes.
tail -c +"$((offset + 1))" "$log" >"$work/new"
lines=$(wc -l <"$work/new" | awk '{print $1}')
if [ "$lines" -eq 0 ]; then
	exit 0
fi
LC_ALL=C awk -v n="$lines" -v max="$max_bytes" '
	NR > n { exit }
	{ b += length($0) + 1; if (b > max && NR > 1) exit; print }
' "$work/new" >"$work/body"
sent=$(wc -c <"$work/body" | awk '{print $1}')

# The token reaches curl as configuration on stdin, so it is never an
# argument a process listing can show.
if ! code=$(
	printf 'header = "Authorization: Bearer %s"\n' "$token" |
		curl --silent --show-error --proto =http,https --max-time 120 \
			--config - --request POST \
			--header 'Content-Type: application/x-ndjson' \
			--data-binary @"$work/body" \
			--output "$work/response" --write-out '%{http_code}' \
			"$endpoint/results"
); then
	die "could not reach $endpoint/results; the offset stays at $offset and the next run retries"
fi
case $code in
2??) ;;
*)
	printf '%s: POST %s/results answered %s; the offset stays at %s:\n' "$prog" "$endpoint" "$code" "$offset" >&2
	sed -n '1,20s/^/  /p' "$work/response" >&2
	exit 1
	;;
esac

printf '%s %s\n' "$inode" "$((offset + sent))" >"$state.tmp"
mv "$state.tmp" "$state"
