// Package config loads tool configuration from flags, environment variables,
// and config files. Priority (highest first): flags → env vars → /etc/bodega/config.json
// → ~/.config/bodega/config.json → built-in defaults.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	EnvBucket     = "REPO_BUCKET"
	EnvRegion     = "AWS_REGION"
	EnvBuildRoot  = "BOOTSTRAP_BUILD_ROOT"
	EnvLogLevel   = "BODEGA_LOG_LEVEL"
	EnvConfigFile = "BODEGA_CONFIG_FILE"
	EnvListenAddr = "BODEGA_LISTEN_ADDR"

	SystemConfigDir  = "/etc/bodega"
	SystemConfigFile = "/etc/bodega/config.json"
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

	// StorageBackends maps a backend *name* to its parameters. The name is
	// what an artifact records in the manifest, so it has to be stable and
	// distinguishable from a driver — see the reserved-word check in Load.
	StorageBackends map[string]StorageSpec `json:"storage_backends,omitempty"`

	// StorageByType maps a package type to a backend *name*. It decides where
	// the next write for that type goes. It never decides where an artifact
	// already written lives: that is the name recorded on the version entry.
	StorageByType map[string]string `json:"storage_by_type,omitempty"`

	LocalConfig bool `json:"-"`
	Verbose     bool `json:"-"`
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
	cfg, legacy := loadFileConfig()
	cfg.LocalConfig = localConfig
	cfg.Verbose = verbose

	cfg.Bucket = firstNonEmpty(flagBucket, os.Getenv(EnvBucket), cfg.Bucket)
	cfg.Region = firstNonEmpty(flagRegion, os.Getenv(EnvRegion), cfg.Region, DefaultRegion)
	cfg.BuildRoot = firstNonEmpty(flagBuildRoot, os.Getenv(EnvBuildRoot), cfg.BuildRoot, DefaultBuildRoot)
	cfg.ManifestDir = firstNonEmpty(manifestDir, cfg.ManifestDir, "manifests")
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

	// Mutation allow-list: default to localhost only.
	if len(cfg.AdminPermitCIDR) == 0 {
		cfg.AdminPermitCIDR = []string{"127.0.0.0/8", "::1/128"}
	}

	return cfg, nil
}

// validateStorage rejects the two ways the driver and name namespaces can be
// confused, and the one way a placement rule can point at nothing.
//
// A dangling storage_by_type value is fatal here rather than at the write that
// would use it: discovered mid-upload it has already decided where an artifact
// went, and a name recorded against a backend nobody defined cannot be read
// back.
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

// Save writes the current config to the first writable config path.
//
// It marshals the Config itself, so every JSON-tagged field survives a
// load/save cycle. LocalConfig and Verbose stay out of the file via
// `json:"-"`, and omitempty keeps unset optional keys absent.
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	// Try system path first, fall back to user path.
	for _, path := range configSearchPaths() {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			continue
		}
		return nil
	}
	return fmt.Errorf("could not write config to any path")
}

// ConfigPath returns the path of the config file that is currently in use.
func ConfigPath() string {
	for _, path := range configSearchPaths() {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return SystemConfigFile
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

// EnsureConfigFile creates a config file with documented defaults if none exists.
func EnsureConfigFile() (string, error) {
	for _, path := range configSearchPaths() {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	path, err := createDefaultConfig()
	if err != nil {
		return "", err
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
  "manifest_dir": "manifests",
  "log_dir": "/var/log/bodega",
  "logwindow_height": 12,
  "log_level": 0,
  "custom_paths": false,
  "apt_root": "",
  "git_root": "",
  "pypi_root": "",
  "binary_root": "",

  "_comment_tls": "TLS: set tls_cert + tls_key for manual certs, or tls_autocert + tls_domain for Let's Encrypt",
  "tls_cert": "",
  "tls_key": "",
  "tls_autocert": false,
  "tls_domain": "",

  "_comment_listen": "listen_addr: address bodega serve binds; --listen and $BODEGA_LISTEN_ADDR override it",
  "listen_addr": ":8080",

  "_comment_proxy": "Proxy/cache: when enabled, the server fetches from upstream on cache miss",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "gomod_upstream": "https://proxy.golang.org",
  "npm_upstream": "https://registry.npmjs.org",
  "cargo_upstream": "https://index.crates.io",

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
  "admin_permit_cidr": ["127.0.0.0/8", "::1/128"]
}
`
	return []byte(content)
}

func createDefaultConfig() (string, error) {
	if err := os.MkdirAll(SystemConfigDir, 0o755); err == nil {
		path := SystemConfigFile
		if err := os.WriteFile(path, defaultConfigContent(), 0o600); err == nil {
			return path, nil
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".config", "bodega")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create config dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, defaultConfigContent(), 0o600); err != nil {
		return "", fmt.Errorf("write config %s: %w", path, err)
	}
	return path, nil
}

// configSearchPaths returns the ordered list of paths loadFileConfig tries.
// When BODEGA_CONFIG_FILE is set, only that path is consulted — callers can
// point at a non-standard location, and tests can point at a path that does
// not exist to guarantee a defaults-only load.
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

func configSearchPaths() []string {
	if override := os.Getenv(EnvConfigFile); override != "" {
		return []string{override}
	}
	paths := []string{SystemConfigFile}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "bodega", "config.json"))
	}
	return paths
}

// loadFileConfig reads the first readable config file into a Config, plus the
// legacy aliases parsed from the same bytes. A missing or unparsable file
// yields zero values for Load's precedence chain to fill.
func loadFileConfig() (*Config, legacyConfig) {
	for _, path := range configSearchPaths() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		var legacy legacyConfig
		_ = json.Unmarshal(data, &legacy)
		return &cfg, legacy
	}
	return &Config{}, legacyConfig{}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
