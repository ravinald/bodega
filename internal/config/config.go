// Package config loads tool configuration from flags, environment variables,
// and config files. Priority (highest first): flags → env vars → /etc/bodega/config.json
// → ~/.config/bodega/config.json → built-in defaults.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultRegion          = "us-west-2"
	DefaultBuildRoot       = "/opt/bodega"
	DefaultLogDir          = "/var/log/bodega"
	DefaultLogWindowHeight = 12
	DefaultLogLevel        = 0

	EnvBucket    = "REPO_BUCKET"
	EnvRegion    = "AWS_REGION"
	EnvBuildRoot = "BOOTSTRAP_BUILD_ROOT"
	EnvLogLevel  = "BODEGA_LOG_LEVEL"

	SystemConfigDir  = "/etc/bodega"
	SystemConfigFile = "/etc/bodega/config.json"
)

// Config holds resolved runtime configuration.
type Config struct {
	Bucket            string   `json:"bucket"`
	Region            string   `json:"region"`
	BuildRoot         string   `json:"build_root"`
	ManifestDir       string   `json:"manifest_dir"`
	LogDir            string   `json:"log_dir"`
	LogWindowHeight   int      `json:"logwindow_height"`
	LogLevel          int      `json:"log_level"`
	CustomPaths       bool     `json:"custom_paths"`
	AptRoot           string   `json:"apt_root,omitempty"`
	GitRoot           string   `json:"git_root,omitempty"`
	PypiRoot          string   `json:"pypi_root,omitempty"`
	BinaryRoot        string   `json:"binary_root,omitempty"`
	TLSCert           string   `json:"tls_cert,omitempty"`
	TLSKey            string   `json:"tls_key,omitempty"`
	TLSAutocert       bool     `json:"tls_autocert,omitempty"`
	TLSDomain         string   `json:"tls_domain,omitempty"`
	ProxyCacheEnabled bool     `json:"proxy_cache_enabled"`
	MetadataTTL       string   `json:"metadata_ttl,omitempty"`
	GomodUpstream     string   `json:"gomod_upstream,omitempty"`
	NpmUpstream       string   `json:"npm_upstream,omitempty"`
	GomodRoot         string   `json:"gomod_root,omitempty"`
	HelmRoot          string   `json:"helm_root,omitempty"`
	NpmRoot           string   `json:"npm_root,omitempty"`
	AuditDB           string   `json:"audit_db,omitempty"`
	DenyList          []string `json:"deny_list,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`          // display timezone, e.g. "America/Los_Angeles"; default UTC
	AuditEvents       []string `json:"audit_events,omitempty"`      // event types to record; empty = all
	StorageBackend    string   `json:"storage_backend,omitempty"`   // "local" (default), "s3"
	StoragePath       string   `json:"storage_path,omitempty"`      // root directory for local backend
	GpgEmail          string   `json:"gpg_email,omitempty"`         // GPG signing email for apt repo (default "bodega@localhost")
	GpgName           string   `json:"gpg_name,omitempty"`          // GPG signing name (default "Bodega Package Signing")
	AptCodename       string   `json:"apt_codename,omitempty"`      // codename for generated apt repo (default "noble")
	AdminPermitCIDR   []string `json:"admin_permit_cidr,omitempty"` // CIDRs allowed to hit mutation API; default ["127.0.0.0/8","::1/128"]
	LocalConfig       bool     `json:"-"`
	Verbose           bool     `json:"-"`
}

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
	}
	return c.BuildRoot
}

// fileConfig is the on-disk shape of config.json.
type fileConfig struct {
	Bucket            string   `json:"bucket"`
	Region            string   `json:"region"`
	BuildRoot         string   `json:"build_root"`
	ManifestDir       string   `json:"manifest_dir"`
	LogDir            string   `json:"log_dir"`
	LogWindowHeight   int      `json:"logwindow_height"`
	LogLevel          int      `json:"log_level"`
	CustomPaths       bool     `json:"custom_paths"`
	AptRoot           string   `json:"apt_root,omitempty"`
	GitRoot           string   `json:"git_root,omitempty"`
	PypiRoot          string   `json:"pypi_root,omitempty"`
	BinaryRoot        string   `json:"binary_root,omitempty"`
	TLSCert           string   `json:"tls_cert,omitempty"`
	TLSKey            string   `json:"tls_key,omitempty"`
	TLSAutocert       bool     `json:"tls_autocert,omitempty"`
	TLSDomain         string   `json:"tls_domain,omitempty"`
	ProxyCacheEnabled bool     `json:"proxy_cache_enabled"`
	MetadataTTL       string   `json:"metadata_ttl,omitempty"`
	GomodUpstream     string   `json:"gomod_upstream,omitempty"`
	NpmUpstream       string   `json:"npm_upstream,omitempty"`
	GomodRoot         string   `json:"gomod_root,omitempty"`
	HelmRoot          string   `json:"helm_root,omitempty"`
	NpmRoot           string   `json:"npm_root,omitempty"`
	AuditDB           string   `json:"audit_db,omitempty"`
	DenyList          []string `json:"deny_list,omitempty"`
	StorageBackend    string   `json:"storage_backend,omitempty"`
	StoragePath       string   `json:"storage_path,omitempty"`
	AptCodename       string   `json:"apt_codename,omitempty"`
	AdminPermitCIDR   []string `json:"admin_permit_cidr,omitempty"`

	// Legacy field — read but not written.
	ShellHeight int `json:"shell_height,omitempty"`
}

// Load builds a Config by merging sources in priority order.
func Load(manifestDir, flagBucket, flagRegion, flagBuildRoot string, localConfig, verbose bool) (*Config, error) {
	fc := loadFileConfig()

	cfg := &Config{
		LocalConfig: localConfig,
		Verbose:     verbose,
	}

	cfg.Bucket = firstNonEmpty(flagBucket, os.Getenv(EnvBucket), fc.Bucket)
	cfg.Region = firstNonEmpty(flagRegion, os.Getenv(EnvRegion), fc.Region, DefaultRegion)
	cfg.BuildRoot = firstNonEmpty(flagBuildRoot, os.Getenv(EnvBuildRoot), fc.BuildRoot, DefaultBuildRoot)
	cfg.ManifestDir = firstNonEmpty(manifestDir, fc.ManifestDir, "manifests")
	cfg.LogDir = firstNonEmpty(fc.LogDir, DefaultLogDir)

	// Log window height: new field, fall back to legacy shell_height.
	cfg.LogWindowHeight = fc.LogWindowHeight
	if cfg.LogWindowHeight <= 0 {
		cfg.LogWindowHeight = fc.ShellHeight
	}
	if cfg.LogWindowHeight <= 0 {
		cfg.LogWindowHeight = DefaultLogWindowHeight
	}

	// Log level: file config only (flags and env resolved by caller).
	cfg.LogLevel = fc.LogLevel

	// Per-type build roots.
	cfg.CustomPaths = fc.CustomPaths
	cfg.AptRoot = fc.AptRoot
	cfg.GitRoot = fc.GitRoot
	cfg.PypiRoot = fc.PypiRoot
	cfg.BinaryRoot = fc.BinaryRoot

	// TLS.
	cfg.TLSCert = fc.TLSCert
	cfg.TLSKey = fc.TLSKey
	cfg.TLSAutocert = fc.TLSAutocert
	cfg.TLSDomain = fc.TLSDomain

	// Proxy/cache.
	cfg.ProxyCacheEnabled = fc.ProxyCacheEnabled
	cfg.MetadataTTL = firstNonEmpty(fc.MetadataTTL, "1h")
	cfg.GomodUpstream = firstNonEmpty(fc.GomodUpstream, "https://proxy.golang.org")
	cfg.NpmUpstream = firstNonEmpty(fc.NpmUpstream, "https://registry.npmjs.org")

	// Extra type roots.
	cfg.GomodRoot = fc.GomodRoot
	cfg.HelmRoot = fc.HelmRoot
	cfg.NpmRoot = fc.NpmRoot

	// Audit.
	cfg.AuditDB = firstNonEmpty(fc.AuditDB, filepath.Join(cfg.LogDir, "audit.db"))

	// Deny list.
	cfg.DenyList = fc.DenyList

	// Storage backend.
	cfg.StorageBackend = firstNonEmpty(fc.StorageBackend, "local")
	cfg.StoragePath = fc.StoragePath

	// APT codename.
	cfg.AptCodename = firstNonEmpty(fc.AptCodename, "noble")

	// Mutation allow-list: default to localhost only.
	cfg.AdminPermitCIDR = fc.AdminPermitCIDR
	if len(cfg.AdminPermitCIDR) == 0 {
		cfg.AdminPermitCIDR = []string{"127.0.0.0/8", "::1/128"}
	}

	return cfg, nil
}

// Save writes the current config to the first writable config path.
func (c *Config) Save() error {
	fc := fileConfig{
		Bucket:            c.Bucket,
		Region:            c.Region,
		BuildRoot:         c.BuildRoot,
		ManifestDir:       c.ManifestDir,
		LogDir:            c.LogDir,
		LogWindowHeight:   c.LogWindowHeight,
		LogLevel:          c.LogLevel,
		CustomPaths:       c.CustomPaths,
		AptRoot:           c.AptRoot,
		GitRoot:           c.GitRoot,
		PypiRoot:          c.PypiRoot,
		BinaryRoot:        c.BinaryRoot,
		TLSCert:           c.TLSCert,
		TLSKey:            c.TLSKey,
		TLSAutocert:       c.TLSAutocert,
		TLSDomain:         c.TLSDomain,
		ProxyCacheEnabled: c.ProxyCacheEnabled,
		MetadataTTL:       c.MetadataTTL,
		GomodUpstream:     c.GomodUpstream,
		NpmUpstream:       c.NpmUpstream,
		GomodRoot:         c.GomodRoot,
		HelmRoot:          c.HelmRoot,
		NpmRoot:           c.NpmRoot,
		AuditDB:           c.AuditDB,
		DenyList:          c.DenyList,
		StorageBackend:    c.StorageBackend,
		StoragePath:       c.StoragePath,
		AptCodename:       c.AptCodename,
		AdminPermitCIDR:   c.AdminPermitCIDR,
	}

	data, err := json.MarshalIndent(fc, "", "  ")
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

	// Log directory.
	cfg, _ := Load("", "", "", "", false, false)
	logDir := cfg.LogDir
	if logDir == "" {
		logDir = DefaultLogDir
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

  "_comment_proxy": "Proxy/cache: when enabled, the server fetches from upstream on cache miss",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "gomod_upstream": "https://proxy.golang.org",
  "npm_upstream": "https://registry.npmjs.org",

  "gomod_root": "",
  "helm_root": "",
  "npm_root": "",

  "audit_db": "",

  "_comment_deny": "deny_list: CIDR entries (e.g. 10.0.0.5, 192.168.1.0/24, fd00::/8) — bare IPs imply /32 or /128",
  "deny_list": []
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

func configSearchPaths() []string {
	paths := []string{SystemConfigFile}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "bodega", "config.json"))
	}
	return paths
}

func loadFileConfig() fileConfig {
	for _, path := range configSearchPaths() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var fc fileConfig
		if err := json.Unmarshal(data, &fc); err != nil {
			continue
		}
		return fc
	}
	return fileConfig{}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
