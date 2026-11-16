package clientconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	toml "github.com/ravinald/bodega/internal/clientconf/internal/gotoml224"
	tomlu "github.com/ravinald/bodega/internal/clientconf/internal/gotoml224/unstable"
	"github.com/ravinald/bodega/internal/plannedfs"
)

// containerdHostFile is one host of a hosts.toml as containerd decodes it:
// hostFileConfig in core/remotes/docker/config/hosts.go at containerd v2.2.0,
// every field with its TOML tag and Go type. Fields doctor never edits are
// here because containerd discards the whole file over a wrong type in any of
// them, and then pulls as if the registry had no hosts.toml.
type containerdHostFile struct {
	Capabilities []string       `toml:"capabilities"`
	CACert       any            `toml:"ca"`
	Client       any            `toml:"client"`
	SkipVerify   *bool          `toml:"skip_verify"`
	Header       map[string]any `toml:"header"`
	OverridePath bool           `toml:"override_path"`
	DialTimeout  string         `toml:"dial_timeout"`
}

// ContainerdHostsFile is a hosts.toml containerd loads: its host tables in
// file order, which is the order containerd tries them in, then the server
// the file's top level names, which containerd tries last.
type ContainerdHostsFile struct {
	Hosts []ContainerdRegistryHost
}

// ContainerdRegistryHost is one endpoint containerd resolved from a
// hosts.toml.
type ContainerdRegistryHost struct {
	// Key is the host table's key as the file writes it, or the value of
	// server for the top-level entry, where it may be empty: containerd then
	// asks the registry the directory is named for.
	Key string
	// Server marks the top-level entry.
	Server bool
	// Scheme, Host and Path are the URL containerd sends to.
	Scheme, Host, Path string
	// Pull reports whether containerd pulls from this host: capabilities
	// names pull, or names nothing and so grants everything.
	Pull bool
	// CA is the files containerd adds to the system roots for this host,
	// each absolute.
	CA []string
	// SkipVerify is skip_verify, nil where the file does not set it.
	SkipVerify *bool
	// ClientPairs are the client certificates containerd presents to this
	// host, each a certificate file and its key file, absolute. An empty key
	// file is a key held in the certificate's own file.
	ClientPairs [][2]string
}

// TLSError is the check containerd v2.2.0 runs on the files a hosts.toml
// names when it builds the client for a registry: updateTLSConfigFromHost in
// core/remotes/docker/config/hosts.go, lines 241-288, called for every host
// of the file by ConfigureHosts (lines 171-181), which returns the first
// error for the whole registry. Each ca file must read and hold at least one
// PEM certificate, and each client pair must read and load as a key pair. One
// host that fails is a registry containerd resolves no host for, the ones
// that would have loaded included, so the error is for the file.
//
// planned names the host table whose ca a plan is about to replace, by its
// key: that table's ca files are not read, since the file the plan names does
// not exist until the plan is applied. "" reads every one.
func (f *ContainerdHostsFile) TLSError(planned string) error {
	if f == nil {
		return nil
	}
	for _, h := range f.Hosts {
		if h.Key != planned || planned == "" {
			for _, ca := range h.CA {
				data, err := plannedfs.ReadFile(ca)
				if err != nil {
					return fmt.Errorf("unable to read CA cert %q: %w", ca, err)
				}
				if !x509.NewCertPool().AppendCertsFromPEM(data) {
					return fmt.Errorf("unable to load CA cert %q", ca)
				}
			}
		}
		for _, pair := range h.ClientPairs {
			cert, err := plannedfs.ReadFile(pair[0])
			if err != nil {
				return fmt.Errorf("unable to read CERT file %q: %w", pair[0], err)
			}
			key := cert
			if pair[1] != "" {
				if key, err = plannedfs.ReadFile(pair[1]); err != nil {
					return fmt.Errorf("unable to read CERT file %q: %w", pair[1], err)
				}
			}
			if _, err := tls.X509KeyPair(cert, key); err != nil {
				return fmt.Errorf("failed to load X509 key pair %q: %w", pair[0], err)
			}
		}
	}
	return nil
}

// ParseContainerdHostsFile decodes data as containerd's parseHostsFile does
// for a hosts.toml in dir: go-toml v2.2.4 fills the structs, then each host goes
// through the conversions of parseHostConfig. Any error is one containerd
// logs before discarding the file whole, so nothing in a file that fails here
// is a setting containerd runs with.
func ParseContainerdHostsFile(dir string, data []byte) (*ContainerdHostsFile, error) {
	var doc struct {
		containerdHostFile
		Server string                        `toml:"server"`
		Host   map[string]containerdHostFile `toml:"host"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	f := new(ContainerdHostsFile)
	for _, key := range containerdHostOrder(data) {
		h, err := containerdHost(key, dir, doc.Host[key])
		if err != nil {
			return nil, err
		}
		f.Hosts = append(f.Hosts, h)
	}
	h, err := containerdHost(doc.Server, dir, doc.containerdHostFile)
	if err != nil {
		return nil, err
	}
	h.Server = true
	f.Hosts = append(f.Hosts, h)
	return f, nil
}

// containerdHostOrder is getSortedHosts: the host tables in the order the
// file opens them. A table reopened after another host is listed again, as
// containerd lists it.
func containerdHostOrder(data []byte) []string {
	var p tomlu.Parser
	p.Reset(data)
	var out []string
	last := ""
	for p.NextExpression() {
		e := p.Expression()
		if e.Kind != tomlu.Table {
			continue
		}
		var parts []string
		for it := e.Key(); it.Next(); {
			parts = append(parts, string(it.Node().Data))
		}
		if len(parts) < 2 || parts[0] != "host" || parts[1] == last {
			continue
		}
		last = parts[1]
		out = append(out, last)
	}
	return out
}

// containerdHost is parseHostConfig: the conversions containerd applies to
// one decoded host, each of which can fail the file.
func containerdHost(server, dir string, c containerdHostFile) (ContainerdRegistryHost, error) {
	h := ContainerdRegistryHost{Key: server, SkipVerify: c.SkipVerify}
	if server != "" {
		if !strings.HasPrefix(server, "http") {
			server = "https://" + server
		}
		u, err := url.Parse(server)
		if err != nil {
			return h, fmt.Errorf("unable to parse server %v: %w", server, err)
		}
		h.Scheme, h.Host = u.Scheme, u.Host
		if len(u.Path) > 0 {
			u.Path = path.Clean(u.Path)
			if !strings.HasSuffix(u.Path, "/v2") && !c.OverridePath {
				u.Path += "/v2"
			}
		} else if !c.OverridePath {
			u.Path = "/v2"
		}
		h.Path = u.Path
	}
	h.Pull = len(c.Capabilities) == 0
	for _, capability := range c.Capabilities {
		switch strings.ToLower(capability) {
		case "pull":
			h.Pull = true
		case "resolve", "push", "referrers":
		default:
			return h, fmt.Errorf("unknown capability %v", capability)
		}
	}
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	stringsOf := func(list []any) ([]string, error) {
		out := make([]string, len(list))
		for i, v := range list {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("unable to cast %v to string", v)
			}
			out[i] = s
		}
		return out, nil
	}
	switch ca := c.CACert.(type) {
	case nil:
	case string:
		h.CA = []string{abs(ca)}
	case []any:
		files, err := stringsOf(ca)
		if err != nil {
			return h, err
		}
		for _, f := range files {
			h.CA = append(h.CA, abs(f))
		}
	default:
		return h, fmt.Errorf("invalid type %v for \"ca\"", ca)
	}
	switch client := c.Client.(type) {
	case nil:
	case string:
		h.ClientPairs = [][2]string{{abs(client), ""}}
	case []any:
		for _, pair := range client {
			switch p := pair.(type) {
			case string:
				h.ClientPairs = append(h.ClientPairs, [2]string{abs(p), ""})
			case []any:
				files, err := stringsOf(p)
				if err != nil {
					return h, err
				}
				if len(files) != 2 {
					return h, fmt.Errorf("invalid pair %v for \"client\"", p)
				}
				h.ClientPairs = append(h.ClientPairs, [2]string{abs(files[0]), abs(files[1])})
			default:
				return h, fmt.Errorf("invalid type %T for \"client\"", p)
			}
		}
	default:
		return h, fmt.Errorf("invalid type %v for \"client\"", client)
	}
	for key, v := range c.Header {
		switch value := v.(type) {
		case string:
		case []any:
			if _, err := stringsOf(value); err != nil {
				return h, err
			}
		default:
			return h, fmt.Errorf("invalid type %v for header %q", v, key)
		}
	}
	if c.DialTimeout != "" {
		if _, err := time.ParseDuration(c.DialTimeout); err != nil {
			return h, err
		}
	}
	return h, nil
}

// LoadContainerdHostsFile reads the hosts.toml at path the way containerd's
// loadHostDir does. A missing or empty file is a registry with no hosts.toml:
// nil and no error. Any other failure is a file containerd discards, falling
// back to the registry's own server, and the error names the file.
func LoadContainerdHostsFile(path string) (*ContainerdHostsFile, error) {
	data, err := plannedfs.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && len(data) == 0) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f, err := ParseContainerdHostsFile(filepath.Dir(path), data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// ContainerdHostsFiles lists the hosts.toml files containerd loads under
// root for a config_path of roots, existing or not: for each registry
// directory, the one in the first root holding that directory. An empty
// roots is containerd's default directory.
func ContainerdHostsFiles(root string, roots []string) []string {
	if len(roots) == 0 {
		roots = []string{ContainerdCertsDir}
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		dirs, _ := plannedfs.Glob(filepath.Join(root, r, "*"))
		for _, dir := range dirs {
			if info, err := plannedfs.Stat(dir); err != nil || !info.IsDir() || seen[filepath.Base(dir)] {
				continue
			}
			seen[filepath.Base(dir)] = true
			out = append(out, filepath.Join(dir, "hosts.toml"))
		}
	}
	return out
}
