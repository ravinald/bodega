// Package config loads tool configuration from flags, environment variables,
// and one config file. Priority (highest first): flags > env vars > config
// file > built-in defaults.
//
// Exactly one file is ever in force, and ConfigPath is the only thing that
// decides which. Load reads it, Save writes it, EnsureConfigFile creates it.
package config

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

	SystemConfigDir  = "/etc/bodega"
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
	TLSAutocert       bool     `json:"tls_autocert,omitempty"`
	TLSDomain         string   `json:"tls_domain,omitempty"`
	ListenAddr        string   `json:"listen_addr,omitempty"` // see ResolveListenAddr for the full precedence chain
	PublicURL         string   `json:"public_url,omitempty"`  // external base URL clients reach the server at; see ResolvePublicURL
	ProxyCacheEnabled bool     `json:"proxy_cache_enabled"`
	MetadataTTL       string   `json:"metadata_ttl,omitempty"`
	GomodUpstream     string   `json:"gomod_upstream,omitempty"`
	NpmUpstream       string   `json:"npm_upstream,omitempty"`
	CargoUpstream     string   `json:"cargo_upstream,omitempty"`
	DiscoverMode      string   `json:"discover_mode,omitempty"` // "", "observe", "learn" — see internal/server/discovery.go
	GomodRoot         string   `json:"gomod_root,omitempty"`
	HelmRoot          string   `json:"helm_root,omitempty"`
	NpmRoot           string   `json:"npm_root,omitempty"`
	CargoRoot         string   `json:"cargo_root,omitempty"`
	AuditDB           string   `json:"audit_db,omitempty"`
	DenyList          []string `json:"deny_list,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`          // display timezone, e.g. "America/Los_Angeles"; default UTC
	AuditEvents       []string `json:"audit_events,omitempty"`      // event types to record; empty = all
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
	// edit: Save marshals the whole resolved Config back over the file, so a
	// cert path cleared in the TUI reaches the listener with nothing between.
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

	LocalConfig bool `json:"-"`
	Verbose     bool `json:"-"`
}

// Git upstream modes. An absent or empty mode loads as GitModeCatalog: an
// operator who adds a namespace without reading the docs gets the posture that
// cannot be induced into fetching upstream code nobody cataloged.
const (
	// GitModeOpen composes the upstream URL for any path under the namespace
	// and fetches it. On a public forge that means any client which can reach
	// bodega can make bodega fetch arbitrary upstream repositories. That is a
	// deliberate posture for an internal forge, where publishing is already
	// controlled, and a way to be used as an open proxy anywhere else.
	GitModeOpen = "open"

	// GitModeCatalog resolves only paths a manifest entry already names.
	// Everything else 404s and is recorded for an operator to promote.
	GitModeCatalog = "catalog"
)

// GitUpstream is one namespace's upstream and trust posture.
//
// Only public, unauthenticated upstreams are supported. Nothing here carries a
// credential and nothing reads one from the environment, so a private forge
// answers bodega the way it answers any anonymous client: the fetch fails and
// the client sees a 404.
type GitUpstream struct {
	URL  string `json:"url"`            // upstream base, https, ends in "/"
	Mode string `json:"mode,omitempty"` // GitModeOpen or GitModeCatalog; empty means catalog
}

// gitNamespacePattern is what a namespace key may look like. The key is both a
// URL segment under /git/ and a directory name in the storage layout, so it
// carries no slash, no dot and no leading digit.
var gitNamespacePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

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

// validateGitUpstreams refuses a malformed git_upstreams block and fills in the
// default mode on the loaded struct.
//
// The default lands here rather than in the handler that reads Mode, because
// the handlers are plural: the git proxy, the binary proxy that lifts this
// shape and anything that renders the config all have to agree on what an
// empty mode means, and a default that lives in one `if` is a default the next
// reader does not share.
func (c *Config) validateGitUpstreams() error {
	for ns, gu := range c.GitUpstreams {
		switch {
		case !gitNamespacePattern.MatchString(ns):
			return fmt.Errorf("invalid git_upstreams key %q: must match %s — the key becomes a URL segment under /git/ and a directory name", ns, gitNamespacePattern)
		case reservedPathElements[ns] != "":
			return fmt.Errorf("invalid git_upstreams key %q: %s — pick a name bodega does not already serve or store under", ns, reservedPathElements[ns])
		}

		u, err := url.Parse(gu.URL)
		switch {
		case gu.URL == "":
			return fmt.Errorf("git_upstreams[%q]: url is required (e.g. \"https://github.com/\")", ns)
		case err != nil:
			return fmt.Errorf("git_upstreams[%q]: url %q does not parse: %v", ns, gu.URL, err)
		case u.Scheme != "https":
			return fmt.Errorf("git_upstreams[%q]: url %q must use the https scheme", ns, gu.URL)
		case u.Host == "":
			return fmt.Errorf("git_upstreams[%q]: url %q names no host", ns, gu.URL)
		case !strings.HasSuffix(gu.URL, "/"):
			return fmt.Errorf("git_upstreams[%q]: url %q must end in \"/\" — the request path is appended to it", ns, gu.URL)
		}

		switch gu.Mode {
		case "":
			gu.Mode = GitModeCatalog
			c.GitUpstreams[ns] = gu
		case GitModeOpen, GitModeCatalog:
		default:
			return fmt.Errorf("git_upstreams[%q]: invalid mode %q (want %q or %q; empty means %q)", ns, gu.Mode, GitModeOpen, GitModeCatalog, GitModeCatalog)
		}
	}
	return nil
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
	cfg, legacy, err := loadFileConfig()
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
	cfg.CargoUpstream = firstNonEmpty(cfg.CargoUpstream, "https://index.crates.io")

	// Discover mode: "", "observe", or "learn" — typo'd values fail loudly so
	// operators don't silently lose observability.
	switch cfg.DiscoverMode {
	case "", "observe", "learn":
	default:
		return nil, fmt.Errorf("invalid discover_mode %q (want \"\", \"observe\", or \"learn\")", cfg.DiscoverMode)
	}

	// Audit.
	cfg.AuditDB = firstNonEmpty(cfg.AuditDB, filepath.Join(cfg.LogDir, "audit.db"))

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
		if s == "" {
			return nil, fmt.Errorf("invalid apt suite: empty name")
		}
		if strings.Contains(s, "/") {
			return nil, fmt.Errorf("invalid apt suite %q (must not contain \"/\")", s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		suites = append(suites, s)
	}
	cfg.AptSuites = suites

	if err := cfg.validateStorage(); err != nil {
		return nil, err
	}

	if err := cfg.validateGitUpstreams(); err != nil {
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

	return cfg, nil
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
// the identity that decides sameness is ObjectStore.Label(), which exists only
// once a driver has normalized its spec: comparing the configured strings here
// would miss a symlink, a trailing slash or a relative path, and fire on a path
// two different drivers happen to share. A second, weaker definition of "same
// location" that disagrees with the one the move path enforces is worse than
// none, and 'bodega pkg move' is the only command the collision can destroy
// anything through.
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
// It marshals the Config itself, so every JSON-tagged field survives a
// load/save cycle. LocalConfig and Verbose stay out of the file via
// `json:"-"`, and omitempty keeps unset optional keys absent.
func (c *Config) Save() (string, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	path := ConfigPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create config dir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write config %s: %w", path, err)
	}
	return path, nil
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

  "_comment_manifest_dir": "manifest_dir: where manifests live on the local backend. Empty means {storage_path}/manifests. Set an absolute path; a relative one resolves against the process working directory, which under systemd is /.",
  "manifest_dir": "",
  "log_dir": "/var/log/bodega",
  "logwindow_height": 12,
  "log_level": 0,
  "custom_paths": false,
  "apt_root": "",
  "git_root": "",
  "pypi_root": "",
  "binary_root": "",

  "_comment_tls": "TLS: set tls_cert + tls_key for manual certs, or tls_autocert + tls_domain for Let's Encrypt. Setting one of tls_cert/tls_key without the other is an error.",
  "tls_cert": "",
  "tls_key": "",
  "tls_autocert": false,
  "tls_domain": "",

  "_comment_allow_plaintext": "allow_plaintext: authorize an unencrypted listener. With no cert pair bodega refuses to start unless this is true — set it for local use, or on a loopback listener behind a proxy that terminates TLS. --allow-plaintext=false overrides it back off.",
  "allow_plaintext": false,

  "_comment_listen": "listen_addr: address bodega serve binds; --listen and $BODEGA_LISTEN_ADDR override it",
  "listen_addr": ":8080",

  "_comment_proxy": "Proxy/cache: when enabled, the server fetches from upstream on cache miss",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "gomod_upstream": "https://proxy.golang.org",
  "npm_upstream": "https://registry.npmjs.org",
  "cargo_upstream": "https://index.crates.io",

  "_comment_git_upstreams": "git_upstreams: maps a namespace under /git/ onto an upstream forge, e.g. {\"internal\": {\"url\": \"https://git.corp.example/\", \"mode\": \"open\"}}. The key is a URL segment and a directory name: letters, digits, _ and -, starting with a letter. The url must be https and end in \"/\".",
  "_comment_git_upstreams_mode": "mode is \"catalog\" (default when absent or empty) or \"open\". catalog resolves only paths an existing manifest entry names; anything else 404s and is recorded as no_manifest for 'bodega discover promote'. open composes the upstream URL for any path under the namespace and fetches it, so on a public forge any client that can reach bodega can make bodega fetch arbitrary upstream repositories. Pick open for a forge whose publishing is already controlled.",
  "_comment_git_upstreams_auth": "Only public, unauthenticated upstreams are supported. No credential is read from this file or the environment, so a private forge answers bodega as an anonymous client and the request surfaces as a 404.",
  "git_upstreams": {},

  "_comment_discover": "Discover mode: \"\" off, \"observe\" log + still enforce policy, \"learn\" log + bypass policy (loud WARN). See bodega discover --help.",
  "discover_mode": "",

  "gomod_root": "",
  "helm_root": "",
  "npm_root": "",
  "cargo_root": "",

  "_comment_apt": "apt_codename: default suite for apt entries that name none. apt_suites: every suite served under /apt/dists/; apt_codename is always included.",
  "apt_codename": "noble",
  "apt_suites": ["noble"],

  "_comment_apt_signing": "apt_signing_name / apt_signing_email: the UID stamped on a key made by 'bodega apt key generate'. They name the key, nothing more — the server loads whatever key it finds and never generates one.",
  "apt_signing_name": "",
  "apt_signing_email": "",

  "_comment_audit": "audit_db defaults to {log_dir}/audit.db. timezone is the display timezone for audit queries (default UTC); audit_events limits which event types are recorded, empty records all.",
  "audit_db": "",
  "timezone": "",
  "audit_events": [],

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
func loadFileConfig() (*Config, legacyConfig, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &Config{}, legacyConfig{}, nil
	case err != nil:
		return nil, legacyConfig{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, legacyConfig{}, parseConfigError(path, err)
	}
	var legacy legacyConfig
	_ = json.Unmarshal(data, &legacy)
	return &cfg, legacy, nil
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
// The executable-relative probes are the development case, where the binary is
// built beside the source tree's manifests/. Off a source tree the answer is
// derived from storage_path, so the manifests sit inside the tree the operator
// already told bodega to own.
func defaultManifestDir(storagePath string) string {
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, c := range []string{
			filepath.Join(exeDir, "manifests"),
			filepath.Join(exeDir, "..", "manifests"),
		} {
			if fi, err := os.Stat(c); err == nil && fi.IsDir() {
				if abs, err := filepath.Abs(c); err == nil {
					return abs
				}
			}
		}
	}
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
