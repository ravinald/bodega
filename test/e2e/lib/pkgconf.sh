#!/bin/sh
# save <slot> | restore <slot> | drop | seed | state
#
# Suite 47 ships this to the freebsd guest and runs it there under sudo, so it
# stays POSIX sh. FBSD_PKGCONF_ROOT points it at a scratch tree instead of /,
# which is how the self-test drives everything but `state` on any host.
#
# `doctor --configure` copies a stanza it replaces to bodega.conf.bodega-<UTC
# timestamp> before writing, so those backups belong to the saved set: one the
# suite caused is removed on restore, and one that predates the save comes back.
set -eu
root="${FBSD_PKGCONF_ROOT:-}"
dir="$root/var/tmp/bodega-e2e-pkgconf"
paths="usr/local/etc/pkg/repos/bodega.conf usr/local/etc/pkg/fingerprints/bodega"
backups="usr/local/etc/pkg/repos/bodega.conf.bodega-"
parents="usr/local/etc/pkg/repos usr/local/etc/pkg/fingerprints usr/local/etc/pkg"
slot="$dir/${2:-none}"
case "$1" in
save)
	rm -rf "$slot"
	mkdir -p "$slot"
	: >"$slot/present"
	: >"$slot/parents"
	for p in $parents; do
		if [ -d "$root/$p" ]; then echo "$p" >>"$slot/parents"; fi
	done
	for p in $paths; do
		if [ -e "$root/$p" ] || [ -L "$root/$p" ]; then echo "$p" >>"$slot/present"; fi
	done
	for f in "$root/$backups"*; do
		if [ -e "$f" ] || [ -L "$f" ]; then echo "${f#"$root"/}" >>"$slot/present"; fi
	done
	if [ -s "$slot/present" ]; then
		# shellcheck disable=SC2046 # one word per saved path
		tar -cpf "$slot/saved.tar" -C "${root:-/}" $(cat "$slot/present")
	fi
	: >"$slot/complete"
	;;
restore)
	# Nothing is removed without a complete copy to put back.
	if [ ! -f "$slot/complete" ]; then
		echo "no complete save at $slot, so nothing was removed" >&2
		exit 1
	fi
	for p in $paths; do rm -rf "$root/${p:?}"; done
	for f in "$root/$backups"*; do rm -rf "$f"; done
	if [ -s "$slot/present" ]; then tar -xpf "$slot/saved.tar" -C "${root:-/}"; fi
	for p in $parents; do
		grep -qx "$p" "$slot/parents" || rmdir "$root/$p" 2>/dev/null || true
	done
	;;
drop)
	rm -rf "$dir"
	;;
seed)
	mkdir -p "$root/usr/local/etc/pkg/repos" "$root/usr/local/etc/pkg/fingerprints/bodega/revoked"
	if [ ! -e "$root/usr/local/etc/pkg/repos/bodega.conf" ]; then
		printf '# bodega e2e: a stanza that predates suite 47, which it must restore\n' \
			>"$root/usr/local/etc/pkg/repos/bodega.conf"
	fi
	printf 'function: "sha256";\nfingerprint: "%064d";\n' 0 \
		>"$root/usr/local/etc/pkg/fingerprints/bodega/revoked/bodega-e2e-sentinel"
	;;
state)
	p=usr/local/etc/pkg
	if [ ! -e "$root/$p" ]; then
		echo "$p absent"
		exit 0
	fi
	find "$root/$p" | sort | while IFS= read -r f; do
		m="$(stat -f '%Sp %Su:%Sg' "$f")"
		if [ -f "$f" ]; then m="$m $(sha256 -q "$f")"; fi
		echo "${f#"$root"/} $m"
	done
	;;
*)
	echo "usage: $0 save <slot> | restore <slot> | drop | seed | state" >&2
	exit 2
	;;
esac
