// Package config loads tool configuration from flags, environment variables,
// and one config file. Priority (highest first): flags > env vars > config
// file > built-in defaults.
//
// Exactly one file is ever in force, and ConfigPath is the only thing that
// decides which. Load reads it, Save writes it, EnsureConfigFile creates it.
package config

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/audit"
)

const (
	DefaultRegion          = "us-west-2"
	DefaultBuildRoot       = "/opt/bodega"
	DefaultLogDir          = "/var/log/bodega"
	DefaultLogWindowHeight = 12
	DefaultLogLevel        = 0
	DefaultListenAddr      = ":8080"

	// DefaultTLSMinVersion is the floor bodega's own listener negotiates down
	// to. 1.3 rather than the Go default of 1.2: a deployment that must serve
	// an older client is expected to put a terminator in front rather than
	// lower the floor for every other client at the same time.
	DefaultTLSMinVersion = "1.3"

	// DefaultStoragePath is the local backend's root when storage_path is
	// unset. internal/storage applies the same value; the built-in manifest
	// directory is derived from it, so the two must not drift.
	DefaultStoragePath = "/var/lib/bodega"

	EnvBucket      = "REPO_BUCKET"
	EnvRegion      = "AWS_REGION"
	EnvBuildRoot   = "BOOTSTRAP_BUILD_ROOT"
	EnvManifestDir = "BODEGA_MANIFEST_DIR"
	EnvLogLevel    = "BODEGA_LOG_LEVEL"
	EnvConfigFile  = "BODEGA_CONFIG_FILE"
	EnvListenAddr  = "BODEGA_LISTEN_ADDR"
	EnvPublicURL   = "BODEGA_PUBLIC_URL"
	EnvServerURL   = "BODEGA_SERVER"
	EnvToken       = "BODEGA_TOKEN"

	SystemConfigFile = "/etc/bodega/config.json"
)

// Test seams for the two standard locations and the root check. Nothing
// outside internal/config's own tests reassigns them; the resolution matrix
// cannot be exercised against real /etc.
var (
	systemConfigFile = SystemConfigFile
	userConfigFile   = defaultUserConfigFile
	runningAsRoot    = func() bool { return os.Geteuid() == 0 }
)

// Config holds resolved runtime configuration and is the on-disk shape of
// config.json. There is deliberately no second struct for the file: a field
// added here is read, resolved and written back with no other edit, and the
// two runtime-only fields opt out with `json:"-"`.
type Config struct {
	Bucket            string   `json:"bucket"`
	Region            string   `json:"region"`
	BuildRoot         string   `json:"build_root"`
	ManifestDir       string   `json:"manifest_dir"`
	LogDir            string   `json:"log_dir"`
	LogWindowHeight   int      `json:"logwindow_height"`
	LogLevel          int      `json:"log_level"` // --log-level and $BODEGA_LOG_LEVEL are resolved by the caller, not by Load
	CustomPaths       bool     `json:"custom_paths"`
	AptRoot           string   `json:"apt_root,omitempty"`
	GitRoot           string   `json:"git_root,omitempty"`
	PypiRoot          string   `json:"pypi_root,omitempty"`
	BinaryRoot        string   `json:"binary_root,omitempty"`
	TLSCert           string   `json:"tls_cert,omitempty"`
	TLSKey            string   `json:"tls_key,omitempty"`
	ListenAddr        string   `json:"listen_addr,omitempty"` // see ResolveListenAddr for the full precedence chain
	PublicURL         string   `json:"public_url,omitempty"`  // external base URL clients reach the server at; see ResolvePublicURL
	ServerURL         string   `json:"server_url,omitempty"`  // bodega server this host pushes catalogs to; see ResolveServerURL
	Token             string   `json:"token,omitempty"`       // bearer token for that server; $BODEGA_TOKEN wins
	ProxyCacheEnabled bool     `json:"proxy_cache_enabled"`
	MetadataTTL       string   `json:"metadata_ttl,omitempty"`
	GomodUpstream     string   `json:"gomod_upstream,omitempty"`
	NpmUpstream       string   `json:"npm_upstream,omitempty"`
	PypiUpstream      string   `json:"pypi_upstream,omitempty"`  // PEP 503 index root; the server reads /simple/{dist}/ under it to learn where a wheel lives
	CargoUpstream     string   `json:"cargo_upstream,omitempty"` // sparse index host, which serves the index and nothing else
	CargoDLUpstream   string   `json:"cargo_dl_upstream,omitempty"`
	DiscoverMode      string   `json:"discover_mode,omitempty"` // "" or "observe" — see internal/server/discovery.go
	GomodRoot         string   `json:"gomod_root,omitempty"`
	HelmRoot          string   `json:"helm_root,omitempty"`
	NpmRoot           string   `json:"npm_root,omitempty"`
	CargoRoot         string   `json:"cargo_root,omitempty"`
	AuditDB           string   `json:"audit_db,omitempty"`
	DenyList          []string `json:"deny_list,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`          // display timezone, e.g. "America/Los_Angeles"; default UTC
	AuditEvents       []string `json:"audit_events,omitempty"`      // event types to record; empty = all
	AuditSink         string   `json:"audit_sink,omitempty"`        // where the event stream goes: "sqlite" (default), "postgres", "syslog", "jsonl"
	AuditSinkDSN      string   `json:"audit_sink_dsn,omitempty"`    // destination for the sink; see validateAuditSink for the per-sink meaning
	StorageBackend    string   `json:"storage_backend,omitempty"`   // driver for the "default" backend: "local" (default), "s3"
	StoragePath       string   `json:"storage_path,omitempty"`      // root directory for local backend
	AptCodename       string   `json:"apt_codename,omitempty"`      // default suite for apt entries that name none (default "noble")
	AptSuites         []string `json:"apt_suites,omitempty"`        // suites served under /apt/dists/; always includes AptCodename
	AptSigningName    string   `json:"apt_signing_name,omitempty"`  // UID name on a key made by `bodega apt key generate`
	AptSigningEmail   string   `json:"apt_signing_email,omitempty"` // UID email on a key made by `bodega apt key generate`
	AdminPermitCIDR   []string `json:"admin_permit_cidr,omitempty"` // CIDRs allowed to hit mutation API; default ["127.0.0.0/8","::1/128"]

	// TrustedProxies names the peers whose X-Real-IP, X-Forwarded-For and
	// X-Forwarded-Proto bodega will believe. It is deliberately tri-state and
	// carries no omitempty, so the distinction survives a Save:
	//
	//	absent   (nil)            built-in default: loopback + RFC 1918
	//	[]       (empty non-nil)  trust nobody; every request is its peer
	//	["..."]  (populated)      trust exactly these
	//
	// Never collapse the first two with len() == 0. An operator who writes an
	// empty list is disabling header trust on purpose, and reading that as
	// "unset" hands the default back to a deployment that asked to have none.
	TrustedProxies []string `json:"trusted_proxies"`

	// AllowPlaintext authorizes an unencrypted listener. Without it, empty
	// tls_cert/tls_key mean "nothing was configured" and bodega refuses to
	// start rather than binding in the clear on whatever listen_addr names.
	//
	// The path to an accidental empty pair is a config write, not a hand
	// edit: a cert path cleared in the TUI is written back as cleared, and
	// reaches the listener with nothing between.
	// Set this on a loopback listener behind a proxy that terminates TLS.
	AllowPlaintext bool `json:"allow_plaintext,omitempty"`

	// TLSMinVersion is the floor for bodega's own listener, "1.2" or "1.3",
	// defaulting to 1.3. It governs nothing when a proxy terminates TLS, which
	// is the supported way to serve a client that cannot reach the floor.
	TLSMinVersion string `json:"tls_min_version,omitempty"`

	// StorageBackends maps a backend *name* to its parameters. The name is
	// what an artifact records in the manifest, so it has to be stable and
	// distinguishable from a driver — see the reserved-word check in Load.
	StorageBackends map[string]StorageSpec `json:"storage_backends,omitempty"`

	// StorageByType maps a package type to a backend *name*. It decides where
	// the next write for that type goes. It never decides where an artifact
	// already written lives: that is the name recorded on the version entry.
	StorageByType map[string]string `json:"storage_by_type,omitempty"`

	// GitUpstreams maps a namespace under /git/ onto an upstream forge. It
	// exists because one flat gomod_upstream-style key cannot express two
	// forges at once, and a corporate GitLab and github.com are the same
	// protocol under different trust: one is bounded by who can publish to
	// it, the other is the whole public internet.
	GitUpstreams map[string]GitUpstream `json:"git_upstreams,omitempty"`

	// BinaryUpstreams maps a namespace under /binaries/ onto an upstream
	// download host, in the same shape as GitUpstreams. Binaries are the type
	// most likely to come from many vendors at once — a releases host, a forge
	// serving release assets, a vendor CDN — so a single flat key of the
	// gomod_upstream kind cannot name what an install actually pulls from.
	BinaryUpstreams map[string]BinaryUpstream `json:"binary_upstreams,omitempty"`

	// AptUpstreams maps an apt codename onto the upstream archives that serve
	// it, mirroring their dists/ tree byte-for-byte under /apt/dists/<codename>/.
	// A codename here is served entirely from upstream, signature included, and
	// may not also appear in AptSuites: see MirroredAptCodenames.
	//
	// Several upstreams per codename because a real suite is split across
	// archive, security and updates hosts, and a client fetching one Packages
	// file has no way to say which of them a later pool request came from.
	AptUpstreams map[string][]AptUpstream `json:"apt_upstreams,omitempty"`

	LocalConfig bool `json:"-"`
	Verbose     bool `json:"-"`

	// snapshot is what Load read and what Load resolved. Save needs both to
	// tell an operator's setting from a value a flag, an environment variable
	// or a built-in default supplied. A Config built in code has none, and
	// Save writes such a Config whole.
	snapshot *fileSnapshot
}

// fileSnapshot is one config file as Load found it, beside the values Load
// produced from it.
//
// raw carries every top-level key including the ones Config has no field for:
// the _comment_ blocks that carry the guidance bodega ships, and any key
// written by a newer release than the binary doing the save. order is their
// position in the file, so a comment stays beside the key it describes.
type fileSnapshot struct {
	raw      map[string]json.RawMessage
	order    []string
	spaced   map[string]bool // keys the file separates from the one above with a blank line
	resolved map[string]json.RawMessage
	pinned   map[string]bool // keys Pin marked as chosen, written whether or not they differ
}

// legacyKeyAliases maps a retired config key onto the one that replaced it. A
// file carrying an alias is migrated by the next Save rather than keeping the
// old key alive forever, so the promotion Load already performs is recorded.
var legacyKeyAliases = map[string]string{"shell_height": "logwindow_height"}

// Namespaced-upstream modes. An absent or empty mode loads as
// UpstreamModeCatalog: an operator who adds a namespace without reading the
// docs gets the posture that cannot be induced into fetching upstream content
// nobody cataloged.
const (
	// UpstreamModeOpen composes the upstream URL for any path under the
	// namespace and fetches it. On a public host that means any client which
	// can reach bodega can make bodega fetch arbitrary upstream content. That
	// is a deliberate posture for an internal forge or release server, where
	// publishing is already controlled, and a way to be used as an open proxy
	// anywhere else.
	UpstreamModeOpen = "open"

	// UpstreamModeCatalog resolves only paths a manifest entry already names.
	// Everything else 404s and is recorded for an operator to promote.
	UpstreamModeCatalog = "catalog"
)

// Upstream is one namespace's upstream and trust posture.
//
// Only public, unauthenticated upstreams are supported. Nothing here carries a
// credential and nothing reads one from the environment, so a private forge or
// release endpoint answers bodega the way it answers any anonymous client: the
// fetch fails and the client sees a 404, indistinguishable from a typo in the
// path. An operator debugging that has to check the upstream by hand.
type Upstream struct {
	URL  string `json:"url"`            // upstream base, https, ends in "/"
	Mode string `json:"mode,omitempty"` // UpstreamModeOpen or UpstreamModeCatalog; empty means catalog
}

// GitUpstream and BinaryUpstream are aliases rather than distinct structs so
// that one validator can take either map without a conversion pass. Two
// structs of identical shape would need either two validators or a copy in and
// a copy out, and a second validator is a second answer to what a legal
// namespace is.
type (
	GitUpstream    = Upstream
	BinaryUpstream = Upstream
)

// upstreamNamespacePattern is what a namespace key may look like. The key is
// both a URL segment and a directory name in the storage layout, so it carries
// no slash, no dot and no leading digit.
var upstreamNamespacePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

// reservedPathElements are the names a namespace key may not take, each with
// the reason it is spoken for. A key that shadows a route makes bodega answer
// its own URL with an upstream fetch; one that shadows a storage element
// writes into a tree something else owns.
//
// The route half is enumerated from (*Server).registerRoutes in
// internal/server/server.go, the storage half from the key prefixes in
// internal/manifest/keys.go. This package sits below both and cannot import
// either, so the list is maintained by hand against those two files.
var reservedPathElements = map[string]string{
	"api":       "served route",
	"apt":       "served route and apt storage element",
	"binaries":  "served route and binary storage root",
	"cargo":     "served route and cargo storage root",
	"git":       "served route",
	"go":        "served route",
	"healthz":   "served route",
	"helm":      "served route",
	"npm":       "served route and npm storage root",
	"pypi":      "served route and pypi storage root",
	"charts":    "helm storage root",
	"crates":    "cargo crate storage element",
	"dists":     "generated apt index element",
	"gomod":     "gomod storage root",
	"index":     "cargo index storage element",
	"manifests": "manifest directory",
	"packages":  "apt storage root",
	"pool":      "apt pool storage element",
	"repos":     "git bundle storage root",
	"wheels":    "pypi wheel storage element",
}

// validateUpstreams refuses a malformed namespaced-upstream block and fills in
// the default mode on the loaded map. key is the config key the block came
// from ("git_upstreams", "binary_upstreams"), and appears in every message so
// an operator with both blocks set knows which one to edit. route is the URL
// prefix the namespace becomes a segment under, named for the same reason.
//
// One function serves every such block. A second copy would be a second answer
// to what a legal namespace is, and the two would diverge the first time
// either grew a rule.
//
// The mode default lands here rather than in the handler that reads Mode,
// because the handlers are plural: the git proxy, the binary proxy and
// anything that renders the config all have to agree on what an empty mode
// means, and a default that lives in one `if` is a default the next reader
// does not share.
func validateUpstreams(key, route string, ups map[string]Upstream) error {
	for ns, up := range ups {
		switch {
		case !upstreamNamespacePattern.MatchString(ns):
			return fmt.Errorf("invalid %s key %q: must match %s — the key becomes a URL segment under %s and a directory name", key, ns, upstreamNamespacePattern, route)
		case reservedPathElements[strings.ToLower(ns)] != "":
			// Folded before the lookup: the key becomes a directory name, and
			// on a case-insensitive filesystem "Repos/" and the "repos/"
			// bundle root are one directory. On Linux they are two, and an
			// operator still reads the pair as shadowing.
			folded := strings.ToLower(ns)
			return fmt.Errorf("invalid %s key %q: %q is a %s — pick a name bodega does not already serve or store under", key, ns, folded, reservedPathElements[folded])
		}

		u, err := url.Parse(up.URL)
		switch {
		case up.URL == "":
			return fmt.Errorf("%s[%q]: url is required (e.g. \"https://github.com/\")", key, ns)
		case err != nil:
			return fmt.Errorf("%s[%q]: url %q does not parse: %v", key, ns, up.URL, err)
		case u.Scheme != "https":
			return fmt.Errorf("%s[%q]: url %q must use the https scheme", key, ns, up.URL)
		case u.Host == "":
			return fmt.Errorf("%s[%q]: url %q names no host", key, ns, up.URL)
		case !strings.HasSuffix(up.URL, "/"):
			return fmt.Errorf("%s[%q]: url %q must end in \"/\" — the request path is appended to it", key, ns, up.URL)
		case u.User != nil:
			// The credential would land in every upstream_url column, log line
			// and error message that carries the composed URL, and bodega
			// documents that it reads no credential from this file.
			return fmt.Errorf("%s[%q]: url carries userinfo before the host — bodega reads no credential from this file and would copy it into discovery rows, logs and error messages. Remove everything between \"//\" and %q", key, ns, u.Host)
		case u.RawQuery != "":
			return fmt.Errorf("%s[%q]: url %q carries a query string — the request path is appended to it, which would land after the \"?\"", key, ns, up.URL)
		case u.Fragment != "":
			return fmt.Errorf("%s[%q]: url %q carries a fragment — the request path is appended to it, which would land after the \"#\"", key, ns, up.URL)
		case u.Path != cleanUpstreamPath(u.Path):
			return fmt.Errorf("%s[%q]: url path %q is not in cleaned form (%q) — a \"..\" here escapes the intended root, the same refusal the request half already gets", key, ns, u.Path, cleanUpstreamPath(u.Path))
		}

		switch up.Mode {
		case "":
			up.Mode = UpstreamModeCatalog
			ups[ns] = up
		case UpstreamModeOpen, UpstreamModeCatalog:
		default:
			return fmt.Errorf("%s[%q]: invalid mode %q (want %q or %q; empty means %q)", key, ns, up.Mode, UpstreamModeOpen, UpstreamModeCatalog, UpstreamModeCatalog)
		}
	}
	return nil
}

// cleanUpstreamPath is path.Clean with the trailing slash kept, which the
// caller has already required: path.Clean("/a/b/") is "/a/b", so comparing
// against it unmodified would refuse every legal upstream.
func cleanUpstreamPath(p string) string {
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// AptUpstream is one upstream archive serving a mirrored codename.
//
// There is no Mode field, and that is the decision rather than an omission.
// catalog mode resolves only paths a manifest entry names, and apt clients
// choose what to request by reading a Packages index: the first Depends: chain
// reaching a package nobody cataloged would 404 mid-install with apt reporting
// a broken dependency rather than a policy refusal. Constraint for apt is the
// host-level allow-list ("bodega policy add apt archive.ubuntu.com"), which
// bounds which archives bodega will talk to at all.
type AptUpstream struct {
	// URL is the archive root, the directory holding dists/ and pool/, e.g.
	// "https://archive.ubuntu.com/ubuntu". Load trims any trailing slash so
	// every composition site appends the same way.
	URL string `json:"url"`
}

// aptCodenamePattern is what an apt_upstreams key may look like. It is
// narrower than upstreamNamespacePattern because the key is a suite name apt
// itself parses: lowercase, digits and hyphens, which covers every Debian and
// Ubuntu suite including the "-updates" and "-security" forms.
var aptCodenamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// validateAptUpstreams refuses a malformed apt_upstreams block and normalizes
// each URL to a form with no trailing slash.
//
// It does not share validateUpstreams: that validator requires a trailing
// slash because its callers concatenate a request path directly, while an apt
// URL has "/dists/" or "/pool/" appended and an operator copies the archive
// root from a mirror list with no slash on it. Two rules that look alike and
// differ in one character are worse apart than a second short function.
func validateAptUpstreams(ups map[string][]AptUpstream) error {
	for codename, list := range ups {
		if !aptCodenamePattern.MatchString(codename) {
			return fmt.Errorf("invalid apt_upstreams key %q: must match %s — the key is the suite name apt requests under /apt/dists/", codename, aptCodenamePattern)
		}
		if len(list) == 0 {
			return fmt.Errorf("apt_upstreams[%q]: names no upstream — remove the key or give it at least one {\"url\": ...}", codename)
		}
		for i, up := range list {
			u, err := url.Parse(up.URL)
			switch {
			case up.URL == "":
				return fmt.Errorf("apt_upstreams[%q][%d]: url is required (e.g. \"https://archive.ubuntu.com/ubuntu\")", codename, i)
			case err != nil:
				return fmt.Errorf("apt_upstreams[%q][%d]: url %q does not parse: %v", codename, i, up.URL, err)
			case u.Scheme != "https":
				return fmt.Errorf("apt_upstreams[%q][%d]: url %q must use the https scheme", codename, i, up.URL)
			case u.Host == "":
				return fmt.Errorf("apt_upstreams[%q][%d]: url %q names no host", codename, i, up.URL)
			case u.RawQuery != "" || u.Fragment != "":
				return fmt.Errorf("apt_upstreams[%q][%d]: url %q carries a query or fragment — bodega appends \"/dists/...\" and \"/pool/...\" to it, which would land after them", codename, i, up.URL)
			}
			list[i].URL = strings.TrimRight(up.URL, "/")
		}
	}
	return nil
}

// MirrorsAptCodename reports whether a codename is served from upstream rather
// than generated. Load guarantees the two sets are disjoint, so a true answer
// here is also a guarantee that no generated suite answers for it.
func (c *Config) MirrorsAptCodename(codename string) bool {
	_, ok := c.AptUpstreams[codename]
	return ok
}

// MirroredAptCodenames returns the mirrored codenames in sorted order, for the
// emitters that list what an instance serves.
func (c *Config) MirroredAptCodenames() []string {
	out := make([]string, 0, len(c.AptUpstreams))
	for codename := range c.AptUpstreams {
		out = append(out, codename)
	}
	sort.Strings(out)
	return out
}

// AptPoolUpstreams returns every configured archive root once, sorted.
//
// A pool path carries no codename, so the archive a client's apt update
// pinned is not recoverable from the request: the candidate set is the union
// across codenames and the probe order has to come from somewhere stable.
// Sorted, so two servers on the same config probe in the same order and an
// operator reading the log can predict which host answered.
func (c *Config) AptPoolUpstreams() []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range c.AptUpstreams {
		for _, up := range list {
			if up.URL == "" || seen[up.URL] {
				continue
			}
			seen[up.URL] = true
			out = append(out, up.URL)
		}
	}
	sort.Strings(out)
	return out
}

// DefaultStorageName is the reserved name of the backend defined by
// storage_backend / storage_path / bucket / region. Every artifact uploaded
// before named backends existed lives there.
const DefaultStorageName = "default"

// StorageSpec is one named backend's parameters. Driver is the same namespace
// as storage_backend; every other field is read only by the driver that needs
// it.
type StorageSpec struct {
	Driver string `json:"driver"`
	Path   string `json:"path,omitempty"`   // local: filesystem root
	Bucket string `json:"bucket,omitempty"` // s3
	Region string `json:"region,omitempty"` // s3
	Prefix string `json:"prefix,omitempty"` // key prefix within the backend
}

// StorageDrivers reports the storage driver names the binary has registered.
// internal/storage installs the real lookup from its init; it imports this
// package, so the dependency can only point that way. A binary that never
// links internal/storage has no drivers for a backend name to collide with,
// which makes the check below vacuous rather than wrong.
var StorageDrivers = func() []string { return nil }

// RootForType returns the effective build root for a given source type.
func (c *Config) RootForType(typ string) string {
	if !c.CustomPaths {
		return c.BuildRoot
	}
	switch typ {
	case "apt":
		if c.AptRoot != "" {
			return c.AptRoot
		}
	case "git":
		if c.GitRoot != "" {
			return c.GitRoot
		}
	case "pypi":
		if c.PypiRoot != "" {
			return c.PypiRoot
		}
	case "binary":
		if c.BinaryRoot != "" {
			return c.BinaryRoot
		}
	case "gomod":
		if c.GomodRoot != "" {
			return c.GomodRoot
		}
	case "helm":
		if c.HelmRoot != "" {
			return c.HelmRoot
		}
	case "npm":
		if c.NpmRoot != "" {
			return c.NpmRoot
		}
	case "cargo":
		if c.CargoRoot != "" {
			return c.CargoRoot
		}
	}
	return c.BuildRoot
}

// ValidateAptSuite is the rule for a suite name this server can serve, applied
// both to the configured set and to the suites a manifest entry names. An
// entry naming a suite refused here reaches no index under any configuration,
// because the name could never be added to apt_suites.
func ValidateAptSuite(suite string) error {
	if suite == "" {
		return fmt.Errorf("invalid apt suite: empty name")
	}
	if strings.Contains(suite, "/") {
		return fmt.Errorf("invalid apt suite %q (must not contain \"/\")", suite)
	}
	return nil
}

// ServedAptSuites returns the apt suites the server answers for. Load
// normalizes AptSuites, so this only has to cover a Config built by hand.
func (c *Config) ServedAptSuites() []string {
	if len(c.AptSuites) > 0 {
		return c.AptSuites
	}
	if c.AptCodename == "" {
		return nil
	}
	return []string{c.AptCodename}
}

// ServesAptSuite reports whether suite is one of the served apt suites.
func (c *Config) ServesAptSuite(suite string) bool {
	for _, s := range c.ServedAptSuites() {
		if s == suite {
			return true
		}
	}
	return false
}

// legacyConfig holds config.json keys under names that predate the current
// ones. It is unmarshalled from the same bytes as Config so an alias can be
// read without ever appearing in what Save writes back.
type legacyConfig struct {
	// Legacy field — read but not written.
	ShellHeight int `json:"shell_height,omitempty"`
}

// Load builds a Config by merging sources in priority order.
func Load(manifestDir, flagBucket, flagRegion, flagBuildRoot string, localConfig, verbose bool) (*Config, error) {
	cfg, legacy, snap, err := loadFileConfig()
	if err != nil {
		return nil, err
	}
	cfg.LocalConfig = localConfig
	cfg.Verbose = verbose

	cfg.Bucket = firstNonEmpty(flagBucket, os.Getenv(EnvBucket), cfg.Bucket)
	cfg.Region = firstNonEmpty(flagRegion, os.Getenv(EnvRegion), cfg.Region, DefaultRegion)
	cfg.BuildRoot = firstNonEmpty(flagBuildRoot, os.Getenv(EnvBuildRoot), cfg.BuildRoot, DefaultBuildRoot)
	cfg.ManifestDir = firstNonEmpty(manifestDir, os.Getenv(EnvManifestDir), cfg.ManifestDir, defaultManifestDir(cfg.StoragePath))
	cfg.LogDir = firstNonEmpty(cfg.LogDir, DefaultLogDir)

	// Log window height: new field, fall back to legacy shell_height.
	if cfg.LogWindowHeight <= 0 {
		cfg.LogWindowHeight = legacy.ShellHeight
	}
	if cfg.LogWindowHeight <= 0 {
		cfg.LogWindowHeight = DefaultLogWindowHeight
	}

	// Proxy/cache.
	cfg.MetadataTTL = firstNonEmpty(cfg.MetadataTTL, "1h")
	cfg.GomodUpstream = firstNonEmpty(cfg.GomodUpstream, "https://proxy.golang.org")
	cfg.NpmUpstream = firstNonEmpty(cfg.NpmUpstream, "https://registry.npmjs.org")
	cfg.PypiUpstream = firstNonEmpty(cfg.PypiUpstream, "https://pypi.org")
	cfg.CargoUpstream = firstNonEmpty(cfg.CargoUpstream, "https://index.crates.io")

	// crates.io publishes the index and the tarballs on separate hosts, and
	// the index's own config.json is where the download root is named. Reading
	// it at startup would make `bodega serve` fail to bind because a registry
	// was unreachable, so the value is configuration and the default is what
	// that document says today. An operator mirroring the index is not thereby
	// mirroring the downloads, and needs to name both.
	cfg.CargoDLUpstream = firstNonEmpty(cfg.CargoDLUpstream, "https://static.crates.io/crates")

	// Discover mode: "" or "observe" — typo'd values fail loudly so operators
	// don't silently lose observability. "learn" is named separately because a
	// config file carrying it worked on the previous release, and the operator
	// needs to know where the capability went rather than that a value is bad.
	switch cfg.DiscoverMode {
	case "", "observe":
	case "learn":
		return nil, errors.New(`discover_mode "learn" was removed: it suppressed the upstream allow-list and recorded nothing "observe" does not. ` +
			`Use "observe", which logs every upstream request with enforcement left on, and bootstrap the catalog with "bodega pkg convert <type> | bodega pkg import -" from a host that already has the packages installed`)
	default:
		return nil, fmt.Errorf("invalid discover_mode %q (want \"\" or \"observe\")", cfg.DiscoverMode)
	}

	// Audit.
	cfg.AuditDB = firstNonEmpty(cfg.AuditDB, filepath.Join(cfg.LogDir, "audit.db"))
	cfg.AuditSink = firstNonEmpty(cfg.AuditSink, audit.SinkSQLite)
	if err := validateAuditSink(cfg.AuditSink, cfg.AuditSinkDSN); err != nil {
		return nil, err
	}

	// Storage backend.
	cfg.StorageBackend = firstNonEmpty(cfg.StorageBackend, "local")

	// APT suites. apt_codename is the default suite for entries that name
	// none; apt_suites is the served set and always contains it, so an entry
	// written before suites existed can never be orphaned. A "/" in a suite
	// name would misroute in handleAptDists, which splits the dists path on
	// "/" and counts segments, so reject it at load like discover_mode.
	cfg.AptCodename = firstNonEmpty(cfg.AptCodename, "noble")
	cfg.AptSigningName = firstNonEmpty(cfg.AptSigningName, "bodega archive signing key")
	suites := make([]string, 0, len(cfg.AptSuites)+1)
	seen := map[string]bool{}
	for _, s := range append([]string{cfg.AptCodename}, cfg.AptSuites...) {
		if err := ValidateAptSuite(s); err != nil {
			return nil, err
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		suites = append(suites, s)
	}
	cfg.AptSuites = suites

	// apt_upstreams mirrors a codename from upstream, signature included.
	// Generated and mirrored codenames are disjoint by construction: the two
	// indexes describe different package sets, and one URL can serve only one
	// of them, so a shared name would hand a client an InRelease whose digests
	// do not cover the Packages it is served next. See
	// docs-internal/DESIGN_apt-suites-and-signing_2026_08_25.md.
	if err := validateAptUpstreams(cfg.AptUpstreams); err != nil {
		return nil, err
	}
	for _, suite := range cfg.AptSuites {
		if cfg.MirrorsAptCodename(suite) {
			return nil, fmt.Errorf("apt codename %q is in both apt_suites and apt_upstreams: bodega generates and signs one, mirrors the other, and one URL can serve only one of them. "+
				"Drop it from apt_suites to mirror it, or from apt_upstreams to keep serving your own .debs under that name — a mirrored suite needs a name of its own", suite)
		}
	}

	if err := cfg.validateStorage(); err != nil {
		return nil, err
	}

	if err := validateUpstreams("git_upstreams", "/git/", cfg.GitUpstreams); err != nil {
		return nil, err
	}

	if err := validateUpstreams("binary_upstreams", "/binaries/", cfg.BinaryUpstreams); err != nil {
		return nil, err
	}

	// Mutation allow-list: default to localhost only.
	if len(cfg.AdminPermitCIDR) == 0 {
		cfg.AdminPermitCIDR = []string{"127.0.0.0/8", "::1/128"}
	}

	if cfg.TLSMinVersion == "" {
		cfg.TLSMinVersion = DefaultTLSMinVersion
	}
	if _, err := cfg.ResolveTLSMinVersion(); err != nil {
		return nil, err
	}
	if err := cfg.ValidateTLSPair(); err != nil {
		return nil, err
	}

	cfg.snapshot = snap
	cfg.MarkResolved()
	return cfg, nil
}

// MarkResolved records the current values as the resolved baseline, so Save
// treats them as supplied rather than chosen. Load calls it; a caller that
// finishes resolution afterwards — cmd/bodega resolves log_level from
// --log-level, $BODEGA_LOG_LEVEL and --verbose — calls it again, or the next
// TUI save pins its flag into the file for every later run.
func (c *Config) MarkResolved() {
	if c.snapshot == nil {
		return
	}
	resolved, err := marshalKeys(c)
	if err != nil {
		return
	}
	c.snapshot.resolved = resolved
}

// Pin marks config keys as values the operator chose, so the next Save writes
// them even when they match what Load resolved.
//
// Save's diff against the resolved baseline is what stops a flag from being
// recorded as a setting, and it cannot tell "left alone" from "typed back in":
// `bodega --manifest-dir /srv/m shell` prefills the form field with /srv/m, so
// an operator who retypes it to make it stick produces a diff of zero. Pinning
// is the caller saying which keys were chosen rather than inherited; a key
// nobody touched is not pinned and stays out of the file.
func (c *Config) Pin(keys ...string) {
	if c.snapshot == nil {
		return
	}
	if c.snapshot.pinned == nil {
		c.snapshot.pinned = make(map[string]bool, len(keys))
	}
	for _, k := range keys {
		c.snapshot.pinned[k] = true
	}
}

// RawFileValue returns a top-level key exactly as the config file carries it,
// whatever Config does with it. Save preserves keys it did not parse, so a key
// this release stopped reading survives in the file and goes on looking to the
// operator like a setting that is in force. Reading it back is how startup can
// say the value is being ignored instead of ignoring it silently.
//
// Reports false when no file was read, so a host with no config never learns
// that the shipped template mentions something.
func (c *Config) RawFileValue(key string) (json.RawMessage, bool) {
	if c.snapshot == nil || c.snapshot.raw == nil {
		return nil, false
	}
	v, ok := c.snapshot.raw[key]
	return v, ok
}

// ValidateTLSPair rejects half a certificate pair. One path set with the other
// empty is a typo or a truncated edit, never a request for plaintext, and the
// listener cannot tell the difference: it skips TLS on both empty and one
// empty alike.
//
// Load calls it so a broken file fails before any command runs.
// internal/server calls it again from Start, because --tls-cert and --tls-key
// are written into the Config after Load returns and can create the same
// half pair from a clean file.
func (c *Config) ValidateTLSPair() error {
	switch {
	case c.TLSCert != "" && c.TLSKey == "":
		return fmt.Errorf("tls_cert is set (%s) but tls_key is empty: set tls_key to the matching private key PEM, or clear tls_cert and set allow_plaintext to serve without TLS", c.TLSCert)
	case c.TLSKey != "" && c.TLSCert == "":
		return fmt.Errorf("tls_key is set (%s) but tls_cert is empty: set tls_cert to the matching certificate PEM, or clear tls_key and set allow_plaintext to serve without TLS", c.TLSKey)
	}
	return nil
}

// validateAuditSink refuses an audit_sink bodega cannot build, at load rather
// than at the first write. Only the event stream is pluggable: ACLs, tokens,
// checksums and the policy tables stay in audit_db under every sink, because
// the request path reads them to decide and a sink that cannot answer a query
// cannot hold them.
//
// audit_sink_dsn means something different per sink, so it is checked here
// rather than left to fail inside the sink: a postgres URL with no host and a
// jsonl path that is relative both produce a running server whose audit trail
// goes nowhere, which is the state this whole design refuses.
func validateAuditSink(sink, dsn string) error {
	if !audit.ValidSink(sink) {
		return fmt.Errorf("invalid audit_sink %q (want one of: %s). Only the event stream is pluggable — ACLs, tokens, checksums and policies stay in audit_db under every sink",
			sink, strings.Join(audit.Sinks(), ", "))
	}
	switch sink {
	case audit.SinkSQLite:
		if dsn != "" {
			return fmt.Errorf("audit_sink %q takes no audit_sink_dsn (got %q): it writes the event stream into audit_db, the same file the ACLs and tokens live in. Clear audit_sink_dsn, or set audit_sink to one of: %s",
				audit.SinkSQLite, dsn, strings.Join(audit.Sinks()[1:], ", "))
		}
	case audit.SinkPostgres:
		if dsn == "" {
			return fmt.Errorf("audit_sink %q needs audit_sink_dsn: a libpq connection string, e.g. \"postgres://bodega@db.internal:5432/bodega?sslmode=verify-full\"", audit.SinkPostgres)
		}
	case audit.SinkJSONL:
		if dsn == "" {
			return fmt.Errorf("audit_sink %q needs audit_sink_dsn: the absolute path of the file to append to, e.g. \"/var/log/bodega/audit.jsonl\"", audit.SinkJSONL)
		}
		if !filepath.IsAbs(dsn) {
			return fmt.Errorf("audit_sink_dsn %q for audit_sink %q must be absolute: bodega serve runs from whatever working directory the unit file chooses, so a relative path names a different file per invocation", dsn, audit.SinkJSONL)
		}
	case audit.SinkSyslog:
		// An empty dsn is the local daemon, which is the common case. A
		// non-empty one is scheme://address and the sink owns that grammar.
		if dsn != "" {
			if err := audit.ValidateSyslogDSN(dsn); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateStorage rejects the two ways the driver and name namespaces can be
// confused, and the one way a placement rule can point at nothing.
//
// A dangling storage_by_type value is fatal here rather than at the write that
// would use it: discovered mid-upload it has already decided where an artifact
// went, and a name recorded against a backend nobody defined cannot be read
// back.
//
// Two entries resolving to one bucket or directory is deliberately neither
// rejected nor warned about. It is a supported way to stage a migration, and
// the identity that decides sameness is ObjectStore.Label(): comparing the
// configured strings here would miss a symlink, a trailing slash or a relative
// path, and fire on a path two different drivers happen to share. A second,
// weaker definition of "same location" that disagrees with the one the move
// path enforces is worse than none, and 'bodega pkg move' is the only command
// the collision can destroy anything through.
//
// That argument used to add "which exists only once a driver has normalized
// its spec", and no driver did. newLocalFromSpec took storage_path verbatim,
// so two spellings of one directory produced two labels, the move refusal did
// not fire, and --delete-source removed the only copy of the artifact (#136).
// The normalization is now a property the local driver has rather than one it
// was assumed to have: storage.canonicalRoot, applied at construction. Deleting
// it puts this check back on the table.
func (c *Config) validateStorage() error {
	drivers := StorageDrivers()
	isDriver := make(map[string]bool, len(drivers))
	for _, d := range drivers {
		isDriver[d] = true
	}
	driverList := strings.Join(drivers, ", ")

	for name, spec := range c.StorageBackends {
		switch {
		case name == "":
			return fmt.Errorf("invalid storage_backends key: empty name")
		case name == DefaultStorageName:
			return fmt.Errorf("invalid storage_backends key %q: reserved for the backend defined by storage_backend/storage_path/bucket/region", name)
		case isDriver[name]:
			return fmt.Errorf("invalid storage_backends key %q: that is a storage driver, not a backend name (drivers: %s)", name, driverList)
		}
		if spec.Driver == "" {
			return fmt.Errorf("storage_backends[%q]: driver is required (drivers: %s)", name, driverList)
		}
		if len(drivers) > 0 && !isDriver[spec.Driver] {
			return fmt.Errorf("storage_backends[%q]: unknown driver %q (drivers: %s)", name, spec.Driver, driverList)
		}
	}

	for typ, name := range c.StorageByType {
		if name == "" {
			return fmt.Errorf("storage_by_type[%q]: empty backend name", typ)
		}
		if name == DefaultStorageName {
			continue
		}
		if _, ok := c.StorageBackends[name]; !ok {
			return fmt.Errorf("storage_by_type[%q] names undefined storage backend %q (defined: %s)", typ, name, c.definedStorageNames())
		}
	}
	return nil
}

// definedStorageNames lists every usable backend name, sorted, with the
// reserved default first so an error message reads as the full menu.
func (c *Config) definedStorageNames() string {
	names := make([]string, 0, len(c.StorageBackends)+1)
	for name := range c.StorageBackends {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(append([]string{DefaultStorageName}, names...), ", ")
}

// Save writes the current config to the file in force and returns the path it
// wrote. It never falls back to a second path: an edit that lands somewhere
// Load will not read is worse than a failure, because it reports success.
//
// It rewrites the file rather than replacing it. See marshalForFile.
func (c *Config) Save() (string, error) {
	path, _, err := c.SaveReport()
	return path, err
}

// SaveReport is Save, and also names the config keys the write changed, sorted.
//
// Save rewrites only what differs from the resolved baseline, so "it returned
// no error" and "your edit reached the file" are different facts, and a caller
// that reports the first as the second tells an operator their setting is
// pinned when the key was never touched. An empty list means the file on disk
// already said what the Config says.
func (c *Config) SaveReport() (string, []string, error) {
	data, changed, err := c.marshalForFile()
	if err != nil {
		return "", nil, err
	}

	path := ConfigPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, fmt.Errorf("create config dir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", nil, fmt.Errorf("write config %s: %w", path, err)
	}
	return path, changed, nil
}

// marshalForFile renders what belongs on disk.
//
// A Config that came from Load carries the file it came from, so Save edits
// that file: every key the operator wrote stays as they wrote it, every key
// Config has no field for survives (the _comment_ blocks that carry bodega's
// shipped guidance, and any key a newer release wrote), and only the keys whose
// value now differs from what Load resolved are rewritten.
//
// Writing the resolved Config instead is what made a save destructive twice
// over. It deleted the comments, including the one saying that "mode": "open"
// on a public forge lets any client make bodega fetch arbitrary upstream
// repositories. And it recorded every flag and built-in default as though the
// operator had typed it, so `bodega --manifest-dir /tmp/x shell` plus one save
// pinned /tmp/x, log_dir, audit_db, metadata_ttl and apt_codename permanently:
// a later change to any of those defaults could never reach that host again.
//
// A Config built in code has no such file and is written whole. LocalConfig and
// Verbose stay out via `json:"-"`, and omitempty keeps unset optional keys
// absent.
//
// The second return names the keys whose bytes in the file changed, so a caller
// can report what it wrote rather than that it wrote.
func (c *Config) marshalForFile() ([]byte, []string, error) {
	if c.snapshot == nil {
		data, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("marshal config: %w", err)
		}
		return append(data, '\n'), nil, nil
	}

	current, err := marshalKeys(c)
	if err != nil {
		return nil, nil, err
	}

	// Values from the file are re-emitted byte for byte, so a key an operator
	// wrote on one line stays on one line. Only a rewritten key is re-indented.
	out := make(map[string]json.RawMessage, len(c.snapshot.raw))
	for k, v := range c.snapshot.raw {
		out[k] = v
	}
	for k, v := range current {
		prev, ok := c.snapshot.resolved[k]
		if ok && bytes.Equal(prev, v) && !c.snapshot.pinned[k] {
			continue
		}
		indented, err := indentValue(v)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal config key %q: %w", k, err)
		}
		out[k] = indented
	}
	// A key the caller cleared drops out of current entirely, because every
	// optional key is omitempty. Deleting it is the difference between the TUI
	// emptying a deny list and the TUI leaving one alone.
	for k := range c.snapshot.resolved {
		if _, ok := current[k]; !ok {
			delete(out, k)
		}
	}
	order := append([]string(nil), c.snapshot.order...)
	for old, replacement := range legacyKeyAliases {
		if _, ok := c.snapshot.raw[old]; !ok {
			continue
		}
		delete(out, old)
		v, ok := current[replacement]
		if !ok {
			continue
		}
		indented, err := indentValue(v)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal config key %q: %w", replacement, err)
		}
		out[replacement] = indented
		order = append(order, replacement)
	}

	data, err := encodeOrdered(out, order, c.snapshot.spaced)
	if err != nil {
		return nil, nil, err
	}
	return data, changedKeys(c.snapshot.raw, out), nil
}

// changedKeys names the top-level keys whose value the write altered, sorted.
// A key is changed when it was added, removed, or re-emitted with different
// bytes; re-indenting a value the operator wrote on one line counts, because
// that is a change the file carries.
func changedKeys(before, after map[string]json.RawMessage) []string {
	var changed []string
	for k, v := range after {
		if prev, ok := before[k]; !ok || !bytes.Equal(compactJSON(prev), compactJSON(v)) {
			changed = append(changed, k)
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)
	return changed
}

// compactJSON strips insignificant whitespace so a re-indented value does not
// read as an edit. It returns the input unchanged when it will not parse, which
// leaves the comparison a byte one for anything malformed.
func compactJSON(v json.RawMessage) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, v); err != nil {
		return v
	}
	return buf.Bytes()
}

// indentValue re-indents one value to sit under a two-space top-level key.
func indentValue(v json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, v, "  ", "  "); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// marshalKeys renders a Config as its top-level JSON keys, so two of them can
// be compared key by key rather than as one blob.
func marshalKeys(c *Config) (map[string]json.RawMessage, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return keys, nil
}

// encodeOrdered writes obj as a JSON object, emitting the keys named in order
// first and anything left over sorted after them, with a blank line before each
// key spaced names. Values are written as given, already indented.
func encodeOrdered(obj map[string]json.RawMessage, order []string, spaced map[string]bool) ([]byte, error) {
	seen := make(map[string]bool, len(obj))
	keys := make([]string, 0, len(obj))
	for _, k := range order {
		if _, ok := obj[k]; ok && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	rest := make([]string, 0, len(obj)-len(keys))
	for k := range obj {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	keys = append(keys, rest...)

	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, k := range keys {
		name, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("marshal config key %q: %w", k, err)
		}
		if i > 0 && spaced[k] {
			buf.WriteByte('\n')
		}
		buf.WriteString("  ")
		buf.Write(name)
		buf.WriteString(": ")
		buf.Write(obj[k])
		if i < len(keys)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("}\n")
	return buf.Bytes(), nil
}

// ConfigPath returns the config file in force. It is the single answer to
// "which file is the config": loadFileConfig reads it, Save writes it and
// EnsureConfigFile creates it, so all four agree for the same host state.
//
// The rule, in order:
//
//  1. $BODEGA_CONFIG_FILE when set, whether or not that path exists. A caller
//     pointing the override at a scratch path gets the scratch path for every
//     one of the four operations, including creation.
//  2. The first of /etc/bodega/config.json and ~/.config/bodega/config.json
//     that exists. Existence decides — not readability, not parseability. A
//     file the operator can see is the file they will edit, and one the
//     process cannot read is an error to report, never a reason to silently
//     read a different file.
//  3. Neither exists: the system path when running as root, the user path
//     otherwise.
//
// There is deliberately no writability probe. Probing is what let the four
// callers disagree: Save took the first path it could write while Load took
// the first it could parse, so an edit landed in ~/.config while the process
// went on reading /etc and the setting never took effect.
func ConfigPath() string {
	if override := os.Getenv(EnvConfigFile); override != "" {
		return override
	}
	user := userConfigFile()
	candidates := []string{systemConfigFile}
	if user != "" {
		candidates = append(candidates, user)
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if user == "" || runningAsRoot() {
		return systemConfigFile
	}
	return user
}

// defaultUserConfigFile returns the per-user config path, or "" when the home
// directory cannot be determined.
func defaultUserConfigFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "bodega", "config.json")
}

// EnsureConfigAndLogDir creates the config file (if needed) and the log directory.
// Returns the config file path and any error.
func EnsureConfigAndLogDir() (string, error) {
	// Config file.
	configPath, err := EnsureConfigFile()
	if err != nil {
		return "", err
	}

	// Log directory. Tolerate a Load failure (e.g. a misconfigured
	// discover_mode) — best-effort directory creation should not block the
	// rest of startup; the actual `bodega` command path will surface the
	// validation error to the user.
	cfg, _ := Load("", "", "", "", false, false)
	logDir := DefaultLogDir
	if cfg != nil && cfg.LogDir != "" {
		logDir = cfg.LogDir
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		// Non-fatal: log dir creation may fail without root.
		// Fall back silently — logs go to stderr.
		_ = err
	}

	return configPath, nil
}

// EnsureConfigFile creates a config file with documented defaults at the path
// in force, and returns that path. It writes where ConfigPath says, including
// under $BODEGA_CONFIG_FILE: a client pointing the override at a scratch path
// used to get a file written into the location it was avoiding and then read
// built-in defaults.
func EnsureConfigFile() (string, error) {
	path := ConfigPath()
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create config dir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, defaultConfigContent(), 0o600); err != nil {
		return "", fmt.Errorf("write config %s: %w", path, err)
	}
	return path, nil
}

func defaultConfigContent() []byte {
	content := `{
  "_comment": "bodega configuration — all fields are optional, shown here with defaults",
  "_comment_priority": "flags > env vars > this file > built-in defaults",

  "_comment_storage": "storage_backend: \"local\" (default) stores artifacts under storage_path; \"s3\" stores them in bucket + region. Together these define the backend named \"default\".",
  "storage_backend": "local",
  "storage_path": "/var/lib/bodega",

  "_comment_storage_named": "storage_backends: additional backends by name; a name may not be \"default\" or a driver name. storage_by_type: which named backend the NEXT write of each package type goes to. Neither moves what is already uploaded — every version records the backend it was written to, and an unset value means \"default\".",
  "storage_backends": {},
  "storage_by_type": {},

  "bucket": "",
  "region": "us-west-2",
  "build_root": "/opt/bodega",

  "_comment_manifest_dir": "manifest_dir: where manifests live on the local backend. Empty means {storage_path}/manifests, so a backup of storage_path is a backup of the whole repository. Set an absolute path; a relative one resolves against the process working directory, which under systemd is /. Nothing else is probed: a manifests/ directory beside the binary, or one level above it, is read only when this key, $BODEGA_MANIFEST_DIR or --manifest-dir names it. Upgrading an install whose manifests were written relative to the directory bodega was started from, or found beside the binary: move that manifests/ directory into {storage_path}/manifests, or point this key at where it already is.",
  "manifest_dir": "",
  "log_dir": "/var/log/bodega",
  "logwindow_height": 12,
  "log_level": 0,
  "custom_paths": false,
  "apt_root": "",
  "git_root": "",
  "pypi_root": "",
  "binary_root": "",

  "_comment_tls": "TLS: set both tls_cert and tls_key to serve HTTPS. Setting one without the other is an error. bodega has no ACME client; get certificates from certbot or terminate TLS at a proxy in front.",
  "tls_cert": "",
  "tls_key": "",

  "_comment_allow_plaintext": "allow_plaintext: authorize an unencrypted listener. With no cert pair bodega refuses to start unless this is true — set it for local use, or on a loopback listener behind a proxy that terminates TLS. --allow-plaintext=false overrides it back off.",
  "allow_plaintext": false,

  "_comment_listen": "listen_addr: address bodega serve binds; --listen and $BODEGA_LISTEN_ADDR override it",
  "listen_addr": ":8080",

  "_comment_proxy": "Proxy/cache: when enabled, the server fetches from upstream on cache miss",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "gomod_upstream": "https://proxy.golang.org",
  "npm_upstream": "https://registry.npmjs.org",
  "pypi_upstream": "https://pypi.org",

  "_comment_cargo_upstream": "cargo_upstream is the sparse index; cargo_dl_upstream is the separate host the crate tarballs come from. crates.io names the second in its own config.json — bodega does not fetch that at startup, so an instance mirroring the index must name both keys.",
  "cargo_upstream": "https://index.crates.io",
  "cargo_dl_upstream": "https://static.crates.io/crates",

  "_comment_git_upstreams": "git_upstreams: maps a namespace under /git/ onto an upstream forge, e.g. {\"internal\": {\"url\": \"https://git.corp.example/\", \"mode\": \"open\"}}. The key is a URL segment and a directory name: letters, digits, _ and -, starting with a letter, and folded to lower case before the reserved-name check so \"Repos\" is refused with \"repos\". The url must be https, end in \"/\", and carry no userinfo, no query, no fragment and no uncleaned path. A key may share a name with an uploaded git package: /git/{name}/{file} serves the bundle and /git/{ns}/{org}/{repo}.git/... resolves the upstream.",
  "_comment_git_upstreams_mode": "mode is \"catalog\" (default when absent or empty) or \"open\". catalog resolves only paths an existing manifest entry names; anything else 404s and is recorded as no_manifest for 'bodega discover promote'. open composes the upstream URL for any path under the namespace and fetches it, so on a public forge any client that can reach bodega can make bodega fetch arbitrary upstream repositories. Pick open for a forge whose publishing is already controlled.",
  "_comment_git_upstreams_auth": "Only public, unauthenticated upstreams are supported. No credential is read from this file or the environment, so a private forge answers bodega as an anonymous client and the request surfaces as a 404. A url carrying userinfo is refused at load rather than quietly used: it would land in discovery rows, logs and error messages.",
  "git_upstreams": {},

  "_comment_binary_upstreams": "binary_upstreams: maps a namespace under /binaries/ onto an upstream download host, e.g. {\"hashicorp\": {\"url\": \"https://releases.hashicorp.com/\", \"mode\": \"open\"}}. Same key, url and mode rules as git_upstreams, enforced by the same validator. Binaries come from many vendors at once, which is why this is a map rather than one flat key.",
  "_comment_binary_upstreams_paths": "While this is empty, /binaries/{path...} serves from storage exactly as it always has. Once any entry exists, a request whose first segment names no key here 404s and is recorded as no_namespace instead of falling through to a storage read — including a path that used to resolve. Name a namespace for every tree you still serve locally, or leave the block empty.",
  "_comment_binary_upstreams_auth": "Only public, unauthenticated upstreams are supported. A namespace pointing at a private release endpoint fails as a 404 with no credential prompt, which looks identical to a typo in the path — check the upstream by hand before hunting the path.",
  "binary_upstreams": {},

  "_comment_discover": "Discover mode: \"\" off, \"observe\" record every upstream request bodega could not answer from its own manifests. It changes no decision: the allow-list, catalog mode, version constraints and the ACLs enforce the same either way. See bodega discover --help.",
  "discover_mode": "",

  "gomod_root": "",
  "helm_root": "",
  "npm_root": "",
  "cargo_root": "",

  "_comment_apt": "apt_codename: default suite for apt entries that name none. apt_suites: every suite served under /apt/dists/; apt_codename is always included.",
  "apt_codename": "noble",
  "apt_suites": ["noble"],

  "_comment_apt_upstreams": "apt_upstreams: codenames mirrored from an upstream archive instead of generated, e.g. {\"noble\": [{\"url\": \"https://archive.ubuntu.com/ubuntu\"}, {\"url\": \"https://security.ubuntu.com/ubuntu\"}]}. bodega proxies the upstream dists/ tree unchanged, signature included, so clients verify against the distro keyring they already have and need no [trusted=yes]. Empty means every codename is generated, which is what every install without this key does.",
  "_comment_apt_upstreams_disjoint": "A codename may not appear in both apt_suites and apt_upstreams — bodega signs one and forwards the other's signature, and a shared name would serve an index whose digests do not cover the packages beside it. Mirrored suites need names of their own.",
  "_comment_apt_upstreams_pool": "/apt/pool/ carries no codename, so a .deb is resolved by probing every configured archive in sorted order and remembering which one answered. There is no per-package allow-list for apt: constrain it with 'bodega policy add apt <host>'.",
  "apt_upstreams": {},

  "_comment_apt_signing": "apt_signing_name / apt_signing_email: the UID stamped on a key made by 'bodega apt key generate'. They name the key, nothing more — the server loads whatever key it finds and never generates one.",
  "apt_signing_name": "",
  "apt_signing_email": "",

  "_comment_audit": "audit_db defaults to {log_dir}/audit.db. timezone is the display timezone for audit queries (default UTC); audit_events limits which event types are recorded, empty records all.",
  "audit_db": "",
  "timezone": "",
  "audit_events": [],

  "_comment_audit_sink": "audit_sink: where the append-only event stream goes — sqlite (default, same file as audit_db), postgres (a fleet writing at once, and reporting across instances), syslog or jsonl (write-only; they ship events out and keep nothing, so 'bodega audit events', 'bodega discover list' and GET /api/v1/audit refuse by name and 'bodega discover promote' is unavailable). One sink, not a list: teeing to two stores keeps the write rate you switched away from. ACLs, tokens, checksums and policies stay in audit_db under every sink — the request path reads them to decide.",
  "_comment_audit_sink_dsn": "audit_sink_dsn: postgres connection string, syslog scheme://address (empty = the local daemon), or an absolute jsonl path. Unused by sqlite, which refuses it rather than ignoring it.",
  "audit_sink": "sqlite",
  "audit_sink_dsn": "",

  "_comment_deny": "deny_list: CIDR entries (e.g. 10.0.0.5, 192.168.1.0/24, fd00::/8) — bare IPs imply /32 or /128",
  "deny_list": [],

  "_comment_admin": "admin_permit_cidr: CIDRs allowed to reach the mutation API; any entry beyond localhost also requires a bearer token",
  "admin_permit_cidr": ["127.0.0.0/8", "::1/128"],

  "_comment_trusted": "trusted_proxies: peers whose X-Real-IP/X-Forwarded-For/X-Forwarded-Proto are believed. null uses the built-in loopback+RFC1918 default; [] trusts no header from anyone; a list trusts exactly those. Name your proxy here when bodega sits behind one on a shared network.",
  "trusted_proxies": null,

  "_comment_tls_min": "tls_min_version: floor for bodega's own listener, \"1.2\" or \"1.3\" (default 1.3). Irrelevant when a proxy terminates TLS.",
  "tls_min_version": "1.3"
}
`
	return []byte(content)
}

// ResolveTLSMinVersion maps tls_min_version onto a crypto/tls constant.
//
// Only 1.2 and 1.3 are accepted. TLS 1.0 and 1.1 are refused by name rather
// than ignored, because an operator who wrote "1.0" believes the server now
// answers a client it must never answer, and a silently-raised floor would let
// that belief survive until the client on the other end fails for a reason
// nobody connects back to this key.
func (c *Config) ResolveTLSMinVersion() (uint16, error) {
	switch v := strings.TrimSpace(c.TLSMinVersion); v {
	case "", DefaultTLSMinVersion:
		return tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.0", "1.1":
		return 0, fmt.Errorf("tls_min_version %q: TLS below 1.2 is not supported", v)
	default:
		return 0, fmt.Errorf("tls_min_version %q: want \"1.2\" or \"1.3\"", v)
	}
}

// ResolveListenAddr applies the listen-address precedence chain:
//
//	flag → env ($BODEGA_LISTEN_ADDR) → config file → DefaultListenAddr
//
// Lives here so cmd/bodega/cmd_serve.go stays small and so the precedence
// order is the same bodega uses for every other knob (see EnvBucket,
// EnvRegion, EnvBuildRoot handling in Load).
func (c *Config) ResolveListenAddr(flagAddr string) string {
	return firstNonEmpty(flagAddr, os.Getenv(EnvListenAddr), c.ListenAddr, DefaultListenAddr)
}

// ResolvePublicURL returns the base URL clients reach this server at, with no
// trailing slash: --public-url, then $BODEGA_PUBLIC_URL, then public_url in
// the config file.
//
// There is no built-in default, and the empty return is the point. Behind a
// reverse proxy the server sees a loopback listener with no TLS and no
// hostname, so anything it derives from tls_cert/tls_key or the listen address
// describes the proxy's back end rather than the URL an operator would copy.
// Deriving it anyway is what printed "http://" on the sources line of a
// deployment that terminates TLS at Apache. Callers with a request in hand
// answer from the request; callers without one render a placeholder.
func (c *Config) ResolvePublicURL(flagURL string) string {
	return strings.TrimRight(firstNonEmpty(flagURL, os.Getenv(EnvPublicURL), c.PublicURL), "/")
}

// loadFileConfig reads the config file in force into a Config, plus the legacy
// aliases parsed from the same bytes. A file that is absent yields zero values
// for Load's precedence chain to fill; one that is present and cannot be read
// or parsed is an error.
//
// Skipping a broken file used to look harmless and was not: falling back to
// built-in defaults means tls_cert/tls_key empty, so a server that served TLS
// yesterday serves the same URLs with no certificate, and deny_list empty, so
// nothing is denied. The plaintext half now refuses to start rather than
// binding in the clear (see (*Server).guardPlaintext), which turns a silent
// downgrade into a loud one; the deny_list half still fails open.
func loadFileConfig() (*Config, legacyConfig, *fileSnapshot, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Zero values for the precedence chain, but the shipped default as the
		// baseline Save edits: a first save against a host with no file yet
		// then produces the documented, commented config rather than the
		// handful of keys that save happened to touch.
		return &Config{}, legacyConfig{}, newFileSnapshot(defaultConfigContent()), nil
	case err != nil:
		return nil, legacyConfig{}, nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, legacyConfig{}, nil, parseConfigError(path, err)
	}
	var legacy legacyConfig
	_ = json.Unmarshal(data, &legacy)
	return &cfg, legacy, newFileSnapshot(data), nil
}

// newFileSnapshot records a config file's keys and their order. data has
// already been unmarshalled into a Config by every caller, so a second failure
// here is not reachable and an unparsable blob yields an empty snapshot rather
// than a second error path saying the same thing.
func newFileSnapshot(data []byte) *fileSnapshot {
	snap := &fileSnapshot{}
	snap.order, snap.spaced = topLevelKeys(data)
	if err := json.Unmarshal(data, &snap.raw); err != nil {
		snap.raw = nil
		snap.order = nil
		snap.spaced = nil
	}
	return snap
}

// topLevelKeys returns the top-level object keys of a config file in the order
// they appear, and which of them the file sets off with a blank line.
//
// Marshalling a map sorts the keys, which would move every _comment_ block away
// from what it documents into one wall at the top, and JSON carries no blank
// lines, so both have to be read off the original bytes or lost on the first
// save. Twenty-six comment blocks run together is a file nobody reads.
func topLevelKeys(data []byte) ([]string, map[string]bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil
	}
	var keys []string
	spaced := map[string]bool{}
	prevEnd := dec.InputOffset()
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return keys, spaced
		}
		key, ok := tok.(string)
		if !ok {
			return keys, spaced
		}
		// Everything between the previous value and this key: a comma, the
		// line break, and a second one when the file leaves a gap.
		if len(keys) > 0 && bytes.Count(data[prevEnd:dec.InputOffset()], []byte{'\n'}) > 1 {
			spaced[key] = true
		}
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return keys, spaced
		}
		prevEnd = dec.InputOffset()
	}
	return keys, spaced
}

// parseConfigError names the file and, when encoding/json can say it, the key
// and the type it wanted. The common shape is an operator writing a
// single-value list as a bare string ("audit_events": "upload"), and "cannot
// unmarshal string into Go value of type []string" alone does not say which
// of the eight list-valued keys they typed.
func parseConfigError(path string, err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && typeErr.Field != "" {
		return fmt.Errorf("parse config %s: key %q: cannot use %s as %s", path, typeErr.Field, typeErr.Value, typeErr.Type)
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Errorf("parse config %s: %v (byte offset %d)", path, err, syntaxErr.Offset)
	}
	return fmt.Errorf("parse config %s: %w", path, err)
}

// defaultManifestDir returns the built-in manifest directory, always absolute.
//
// A bare relative "manifests" under a unit with no WorkingDirectory= resolves
// to /manifests, which ProtectSystem=strict makes unreadable; the server then
// loads zero packages, answers /healthz 200, and publishes a Release whose
// Packages digest is the SHA-256 of the empty string.
//
// storage_path is the only input. Manifests sit inside the tree the operator
// already told bodega to own, so a backup of storage_path is a backup of the
// whole repository, and the shipped _comment_manifest_dir describes what the
// binary does.
//
// It used to probe <exeDir>/manifests and <exeDir>/../manifests first, for a
// binary built beside a source tree's manifests/. /opt/bodega/bin/bodega beside
// /opt/bodega/manifests is that layout too, so an installed host silently read
// a directory no config named while the file in front of the operator promised
// another one. Either layout names its directory with manifest_dir,
// $BODEGA_MANIFEST_DIR or --manifest-dir.
func defaultManifestDir(storagePath string) string {
	return filepath.Join(firstNonEmpty(storagePath, DefaultStoragePath), "manifests")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ResolveServerURL returns the bodega server a client pushes to, with no
// trailing slash: --server, then $BODEGA_SERVER, then server_url in the config
// file. Empty means no remote is configured and the caller works against the
// local manifest store instead.
//
// It is separate from PublicURL because the two answer opposite questions.
// PublicURL is what a server advertises about itself; this is what a host that
// is not the server has been told to talk to, and on a host being cataloged
// only the second one is set.
func (c *Config) ResolveServerURL(flagURL string) string {
	return strings.TrimRight(firstNonEmpty(flagURL, os.Getenv(EnvServerURL), c.ServerURL), "/")
}

// ResolveToken returns the bearer token a client authenticates with:
// $BODEGA_TOKEN, then the config file. It is read from the environment first
// so a token never has to be written to disk on a host being cataloged.
func (c *Config) ResolveToken() string {
	return firstNonEmpty(os.Getenv(EnvToken), c.Token)
}
