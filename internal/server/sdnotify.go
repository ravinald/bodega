package server

import (
	"net"
	"os"
	"strings"
)

// sd_notify integration: hand-rolled so bodega doesn't pull in
// coreos/go-systemd for ~15 lines of protocol. When $NOTIFY_SOCKET is
// unset (any non-systemd invocation), all helpers are silent no-ops.
//
// Protocol reference: https://www.freedesktop.org/software/systemd/man/sd_notify.html

// sdNotify sends a newline-separated state string to the systemd notification
// socket. Errors are intentionally swallowed — notification is best-effort
// and not a critical path. Abstract-namespace sockets (starting with '@')
// are translated to the leading-NUL form unix(7) expects.
func sdNotify(state string) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	if strings.HasPrefix(sock, "@") {
		sock = "\x00" + sock[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte(state))
}

// sdNotifyReady tells systemd the service has finished startup and is ready
// to handle requests. For Type=notify units, systemd blocks `systemctl start`
// until this is received (or TimeoutStartSec elapses).
func sdNotifyReady() { sdNotify("READY=1") }

// sdNotifyStopping tells systemd the service has started its shutdown
// sequence. Lets systemd distinguish "we're cleaning up" from "we died".
func sdNotifyStopping() { sdNotify("STOPPING=1") }
