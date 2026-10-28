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
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/distinfo"
	"github.com/ravinald/bodega/internal/manifest"
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

	// DefaultUpstreamConnectTimeout is short against net.Dialer's 30s because
	// an upstream that drops SYNs would otherwise hold a request past the 15s
	// pip gives up at, and the stale fallback behind it would never reach a
	// client.
	DefaultUpstreamConnectTimeout = "5s"
	// DefaultStaleGrace is how long a request holding a stale cached copy waits
	// for the upstream before taking that copy, inside every client's timeout.
	DefaultStaleGrace = "3s"

	// DefaultSpoolMaxArtifactBytes is the largest single upstream artifact the
	// proxy will copy to disk. 8 GiB is roughly twice the biggest thing a real
	// archive publishes as one file — a CUDA .deb or a torch wheel runs 2-4 GB
	// — and it refuses the runaway case, which is bounded only by the 90s
	// upstream timeout times upstream bandwidth: about 11 GB at 1 Gbps.
	DefaultSpoolMaxArtifactBytes int64 = 8 << 30

	// DefaultSpoolMaxTotalBytes is the byte budget shared by every in-flight
	// spool. Bytes rather than a fetch count because bytes are what runs the
	// filesystem out: eight concurrent fetches is 8 MB or 64 GB depending on
	// what was requested, so a count tuned for one artifact size is the wrong
	// bound for the next one. 32 GiB admits four artifacts at the per-artifact
	// ceiling.
	DefaultSpoolMaxTotalBytes int64 = 32 << 30

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
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	BuildRoot       string `json:"build_root"`
	ManifestDir     string `json:"manifest_dir,omitempty"` // unset means {storage_path}/manifests, so clearing it drops the key rather than pinning "" as a setting
	LogDir          string `json:"log_dir"`
	LogWindowHeight int    `json:"logwindow_height"`
	LogLevel        int    `json:"log_level"` // --log-level and $BODEGA_LOG_LEVEL are resolved by the caller, not by Load
	AptRoot         string `json:"apt_root,omitempty"`
	GitRoot         string `json:"git_root,omitempty"`
	PypiRoot        string `json:"pypi_root,omitempty"`
	BinaryRoot      string `json:"binary_root,omitempty"`
	TLSCert         string `json:"tls_cert,omitempty"`
	TLSKey          string `json:"tls_key,omitempty"`
	ListenAddr      string `json:"listen_addr,omitempty"` // see ResolveListenAddr for the full precedence chain
	PublicURL       string `json:"public_url,omitempty"`  // external base URL clients reach the server at; see ResolvePublicURL
	// AttestationPlatformID is ingestionPlatform.id in every attestation this
	// instance signs; see ResolveAttestationPlatformID.
	AttestationPlatformID string `json:"attestation_platform_id,omitempty"`
	// AttestationKeyIDs are the attestation key IDs 'bodega attest verify'
	// trusts when no --key is given. Learned through a channel other than the
	// server whose statements they check.
	AttestationKeyIDs []string `json:"attestation_keyids,omitempty"`
	// SigstoreTrustedRoot names a Sigstore trusted_root.json that upstream
	// provenance is verified against, for a host that cannot reach Sigstore's
	// TUF repository. Empty means fetch it through TUF. serve refuses to
	// start when it names a file that is missing or does not parse.
	SigstoreTrustedRoot    string            `json:"sigstore_trusted_root,omitempty"`
	ServerURL              string            `json:"server_url,omitempty"` // bodega server this host pushes catalogs to; see ResolveServerURL
	Token                  string            `json:"token,omitempty"`      // bearer token for that server; $BODEGA_TOKEN wins
	ProxyCacheEnabled      bool              `json:"proxy_cache_enabled"`
	MetadataTTL            string            `json:"metadata_ttl,omitempty"`
	UpstreamConnectTimeout string            `json:"upstream_connect_timeout,omitempty"` // bound on one TCP connect to an upstream
	StaleGrace             string            `json:"stale_grace,omitempty"`              // how long a request holding a stale cached copy waits on the upstream
	GomodUpstream          string            `json:"gomod_upstream,omitempty"`
	GomodSumdbURL          string            `json:"gomod_sumdb_url,omitempty"` // sum.golang.org, proxied under /go/sumdb/sum.golang.org/ for a host that reaches only bodega
	NpmUpstream            string            `json:"npm_upstream,omitempty"`
	PypiUpstream           string            `json:"pypi_upstream,omitempty"`  // PEP 503 index root; the server reads /simple/{dist}/ under it to learn where a wheel lives
	CargoUpstream          string            `json:"cargo_upstream,omitempty"` // sparse index host, which serves the index and nothing else
	CargoDLUpstream        string            `json:"cargo_dl_upstream,omitempty"`
	MavenUpstream          string            `json:"maven_upstream,omitempty"`         // one repository root; Load folds it into MavenUpstreams and empties it
	MavenUpstreams         []string          `json:"maven_upstreams,omitempty"`        // repository roots in the Maven layout, tried in order; /maven/<path> is appended to each
	RubygemsUpstream       string            `json:"rubygems_upstream,omitempty"`      // serves gem files, the compact index and the full index from one root
	ComposerUpstream       string            `json:"composer_upstream,omitempty"`      // Packagist's metadata root; the archives live where the metadata says
	ComposerDistHosts      []string          `json:"composer_dist_hosts,omitempty"`    // hosts a Packagist dist URL may name; see DefaultComposerDistHosts
	OCIUpstreams           map[string]string `json:"oci_upstreams,omitempty"`          // registry name > fetch URL, served under /v2/; see DefaultOCIUpstreams
	OCITokenHosts          []string          `json:"oci_token_hosts,omitempty"`        // hosts a registry's Bearer realm may name besides its own; see DefaultOCITokenHosts
	RpmUpstreams           map[string]string `json:"rpm_upstreams,omitempty"`          // repository name > base URL with $releasever and $basearch, served under /rpm/; see resolveRpmUpstreams
	PrivateUpstreamHosts   []string          `json:"private_upstream_hosts,omitempty"` // hostnames the SSRF guard lets resolve to RFC 1918 / fc00::/7; see validatePrivateUpstreamHosts
	DiscoverMode           string            `json:"discover_mode,omitempty"`          // "" or "observe" — see internal/server/discovery.go
	GomodRoot              string            `json:"gomod_root,omitempty"`
	HelmRoot               string            `json:"helm_root,omitempty"`
	NpmRoot                string            `json:"npm_root,omitempty"`
	CargoRoot              string            `json:"cargo_root,omitempty"`
	MavenRoot              string            `json:"maven_root,omitempty"`
	RubygemsRoot           string            `json:"rubygems_root,omitempty"`
	ComposerRoot           string            `json:"composer_root,omitempty"`
	OCIRoot                string            `json:"oci_root,omitempty"`
	RpmRoot                string            `json:"rpm_root,omitempty"`
	FreeBSDRoot            string            `json:"freebsd_root,omitempty"`
	DistfilesRoot          string            `json:"distfiles_root,omitempty"` // the DISTDIR 'bodega build fetch distfiles' writes; see DistfilesPortsTree
	AuditDB                string            `json:"audit_db,omitempty"`
	DenyList               []string          `json:"deny_list,omitempty"`
	Timezone               string            `json:"timezone,omitempty"`          // display timezone, e.g. "America/Los_Angeles"; default UTC
	AuditEvents            []string          `json:"audit_events,omitempty"`      // event types to record; empty = all
	AuditSink              string            `json:"audit_sink,omitempty"`        // where the event stream goes: "sqlite" (default), "postgres", "syslog", "jsonl"
	AuditSinkDSN           string            `json:"audit_sink_dsn,omitempty"`    // destination for the sink; see validateAuditSink for the per-sink meaning
	StorageBackend         string            `json:"storage_backend,omitempty"`   // driver for the "default" backend: "local" (default), "s3"
	StoragePath            string            `json:"storage_path,omitempty"`      // root directory for local backend
	AptCodename            string            `json:"apt_codename,omitempty"`      // default suite for apt entries that name none (default "noble")
	AptSuites              []string          `json:"apt_suites,omitempty"`        // suites served under /apt/dists/; always includes AptCodename
	AptSigningName         string            `json:"apt_signing_name,omitempty"`  // UID name on a key made by `bodega apt key generate`
	AptSigningEmail        string            `json:"apt_signing_email,omitempty"` // UID email on a key made by `bodega apt key generate`
	AdminPermitCIDR        []string          `json:"admin_permit_cidr,omitempty"` // CIDRs allowed to hit mutation API; default ["127.0.0.0/8","::1/128"]

	// OSV gate. osv_db_dir holds the per-ecosystem archives `bodega policy osv
	// sync` writes and defaults to {storage_path}/osv, so a connected host
	// needs no configuration and an air-gapped one points the key at wherever
	// the directory was copied. osv_api_fallback authorizes a live
	// api.osv.dev query when the local copy cannot answer; it is off by
	// default because a restricted network should fail visibly rather than
	// stall for the client timeout once per version. osv_db_max_age is how
	// old a synced ecosystem may be before a clean answer warns instead of
	// passing.
	OSVDBDir       string `json:"osv_db_dir,omitempty"`
	OSVAPIFallback bool   `json:"osv_api_fallback,omitempty"`
	OSVDBMaxAge    string `json:"osv_db_max_age,omitempty"`

	// Re-vet. revet_interval is how often `bodega serve` re-runs the
	// per-version checks over every admitted version, cataloged or proxy
	// cached; unset is off.
	// revet_rate caps that sweep in versions per second (default 1), so a
	// catalog of thousands does not turn into a burst against the registries
	// the provenance check reads. revet_on_block is "report" (default) or
	// "hide". revet_webhook_secret keys the HMAC that authenticates POST
	// /api/v1/policy/revet; unset refuses every call.
	RevetInterval      string  `json:"revet_interval,omitempty"`
	RevetRate          float64 `json:"revet_rate,omitempty"`
	RevetOnBlock       string  `json:"revet_on_block,omitempty"`
	RevetWebhookSecret string  `json:"revet_webhook_secret,omitempty"`

	// Overrides. override_max_ttl caps the --expires an override request may
	// ask for (default 30d); override_quorum is how many distinct identities,
	// the requester included, must agree before one applies (default 2).
	OverrideMaxTTL string `json:"override_max_ttl,omitempty"`
	OverrideQuorum int    `json:"override_quorum,omitempty"`

	// Proxy spool. spool_dir is where an upstream artifact is copied on its
	// way to storage and the client; see ResolveSpoolDir for the default. The
	// two ceilings are in bytes, and 0 in either means unbounded.
	SpoolDir              string `json:"spool_dir,omitempty"`
	SpoolMaxArtifactBytes int64  `json:"spool_max_artifact_bytes,omitempty"`
	SpoolMaxTotalBytes    int64  `json:"spool_max_total_bytes,omitempty"`

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

	// StorageByGroup maps a storage *group* name to a backend name. A package
	// joins a group with storage_groups in its manifest, and the group rule
	// sits between the type rule and the package's own storage_policy.
	//
	// It exists because the two neighboring levels are the only ones there
	// were, and forty packages that belong together fit neither: a type rule
	// catches every package of the type, and a per-package policy is forty
	// edits that drift apart the first time one is missed. The mapping lives
	// here rather than in the manifests so that moving the whole set is one
	// edit, and membership lives in the manifest so that a package declares
	// what it belongs to next to everything else it declares.
	StorageByGroup map[string]string `json:"storage_by_group,omitempty"`

	// Ports distfiles. distfiles_ports_tree is the FreeBSD ports tree whose
	// distinfo files decide what the mirror admits: a distfile is fetched
	// only when a distinfo there pins its SHA256 and size, and stored only
	// when the fetched bytes match both. Unset, /distfiles/ serves nothing
	// and the builder refuses every distfiles entry, because there is no
	// digest to hold the bytes to. distfiles_upstream is where a miss is
	// fetched from and defaults to DefaultDistfilesUpstream. It carries no
	// trust: the digest decides, so any host serving the ports distfile
	// layout will do, over http or https.
	DistfilesPortsTree string `json:"distfiles_ports_tree,omitempty"`
	DistfilesUpstream  string `json:"distfiles_upstream,omitempty"`

	// The supported client environment: what a client's make holds that the
	// ports tree does not, and the only thing admission believes about it.
	// distfiles_environment_variables maps a make variable to every value it
	// may hold where a port reads it ([] declares it undefined);
	// distfiles_environment_files maps an absolute client-host path to its
	// alternatives, "absent" or the absolute path of a snapshot on this host.
	// Anything a port reads outside the tree that is not declared here
	// refuses that port. See docs/threat-model.md.
	DistfilesEnvironmentVariables map[string][]string `json:"distfiles_environment_variables,omitempty"`
	DistfilesEnvironmentFiles     map[string][]string `json:"distfiles_environment_files,omitempty"`

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

	// InventorySources maps an inventory source instance name to its
	// settings: "type", "enabled" and whatever keys that type takes. Several
	// instances of one type are allowed, two Falcon tenants for example, so
	// the instance name rather than the type is what a report records.
	InventorySources map[string]InventorySource `json:"inventory_sources,omitempty"`

	// Integrations maps an external check instance name to its settings:
	// "type", "enabled" and whatever keys that type's descriptor declares.
	// internal/integration owns what the keys mean.
	Integrations map[string]Integration `json:"integrations,omitempty"`

	// OsqueryScanDirs names the trees an osquery source scans for language
	// packages on each host, by profile. osquery's python_packages and
	// npm_packages tables read only the directories a query names, so this
	// is the declared extent of what bodega can see of pip and npm installs.
	OsqueryScanDirs OsqueryScanDirs `json:"osquery_scan_dirs,omitzero"`

	// OIDCProviders are the identity providers whose ID tokens POST
	// /api/v1/auth/exchange trades for a bodega token, and oidc_token_ttl is
	// that token's lifetime (default 15m). See OIDCProvider.
	OIDCProviders []OIDCProvider `json:"oidc_providers,omitempty"`
	OIDCTokenTTL  string         `json:"oidc_token_ttl,omitempty"`

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
	cleared  map[string]bool // keys Clear marked for removal, deleted from the file whatever they hold
}

// legacyKeyAliases maps a retired config key onto the one that replaced it. A
// file carrying an alias is migrated by the next Save rather than keeping the
// old key alive forever, so the promotion Load already performs is recorded.
var legacyKeyAliases = map[string]string{"shell_height": "logwindow_height"}

// DefaultDistfilesUpstream is the FreeBSD project's own distfile cache, the
// same host bsd.port.mk names as MASTER_SITE_BACKUP. It is laid out as
// <DIST_SUBDIR>/<file>, which is the distinfo name, so a miss appends that
// name and nothing else.
//
// It is http:// on purpose, as bsd.port.mk's own default is: the host answers
// https with a certificate that does not name it. A distfile is admitted
// against the ports tree's distinfo rather than against the transport, so an
// attacker on the path can make a fetch fail and cannot make one succeed.
const DefaultDistfilesUpstream = "http://distcache.FreeBSD.org/ports-distfiles/"

// DefaultRubygemsUpstream is the RubyGems registry root. rubygems.org serves
// the gem files, Bundler's compact index and the legacy full index from the
// one host, so one key names all three.
const DefaultRubygemsUpstream = "https://rubygems.org"

// DefaultComposerUpstream is Packagist's metadata root. Packagist serves
// metadata only: each version's archive lives at a URL that metadata names.
const DefaultComposerUpstream = "https://repo.packagist.org"

// DefaultComposerDistHosts are the forges Packagist's dist URLs name. A dist
// URL is chosen by whoever publishes the package, so the list is what keeps a
// package's metadata from pointing bodega's fetch at any host it likes.
var DefaultComposerDistHosts = []string{"api.github.com", "codeload.github.com", "gitlab.com", "bitbucket.org"}

// DefaultOCIUpstreams maps each registry a client may name under /v2/ to the
// URL bodega fetches it from. Docker Hub's name and its API host differ.
var DefaultOCIUpstreams = map[string]string{
	"docker.io": "https://registry-1.docker.io",
	"ghcr.io":   "https://ghcr.io",
	"quay.io":   "https://quay.io",
}

// DefaultOCITokenHosts are the token services the default registries' Bearer
// challenges name. A registry chooses its realm, so the list is what keeps an
// upstream from sending bodega's token request, and the credential with it,
// to a host of its choosing.
var DefaultOCITokenHosts = []string{"auth.docker.io", "ghcr.io", "quay.io"}

// DistfilesEnvironment is the declared client environment distfiles admission
// reads ports against.
func (cfg *Config) DistfilesEnvironment() distinfo.EnvironmentSpec {
	return distinfo.EnvironmentSpec{Variables: cfg.DistfilesEnvironmentVariables, Files: cfg.DistfilesEnvironmentFiles}
}

// validateDistfiles refuses a distfiles configuration that would fail on the
// first request rather than at startup. Snapshots are not read here: every
// command loads this file, and one missing snapshot would lock the operator
// out of the command that fixes it. The server and the builder read them, and
// refuse every distfile when they cannot.
func (cfg *Config) validateDistfiles() error {
	if cfg.DistfilesPortsTree != "" && !filepath.IsAbs(cfg.DistfilesPortsTree) {
		return fmt.Errorf("distfiles_ports_tree %q must be an absolute path to the root of a FreeBSD ports tree, such as /usr/ports", cfg.DistfilesPortsTree)
	}
	if err := cfg.DistfilesEnvironment().Validate(); err != nil {
		return err
	}
	up := cfg.DistfilesUpstream
	u, err := url.Parse(up)
	switch {
	case up == "":
		return nil
	case err != nil:
		return fmt.Errorf("distfiles_upstream %q does not parse: %v", up, err)
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("distfiles_upstream %q must use http or https; plain http is accepted here alone, because distinfo rather than the transport decides what is admitted", up)
	case u.Host == "":
		return fmt.Errorf("distfiles_upstream %q names no host", up)
	case !strings.HasSuffix(up, "/"):
		return fmt.Errorf("distfiles_upstream %q must end in \"/\" — the distinfo name is appended to it", up)
	case u.User != nil:
		return fmt.Errorf("distfiles_upstream carries userinfo before the host — bodega reads no credential from this file and would copy it into logs and error messages. Remove everything between \"//\" and %q", u.Host)
	case u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("distfiles_upstream %q carries a query or fragment — the distinfo name is appended to it, which would land after it", up)
	}
	return nil
}

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
	// Revalidate holds path.Match patterns, matched against the path after
	// the namespace, naming the upstream paths that move under a fixed name
	// (rustup's dist/channel-rust-stable.toml). Those follow metadata_ttl;
	// every other path is cached forever. Binary namespaces only: a git
	// namespace caches nothing by path.
	Revalidate []string `json:"revalidate,omitempty"`
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
	"rubygems":  "served route and rubygems storage root",
	"composer":  "served route and composer storage root",
	"v2":        "served route (the OCI registry)",
	"oci":       "oci storage root",
	"rpm":       "served route and rpm storage root",
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

		for _, pat := range up.Revalidate {
			if _, err := path.Match(pat, ""); err != nil {
				return fmt.Errorf("%s[%q]: revalidate pattern %q is malformed: %v (path.Match syntax, matched against the path after %s%s/)", key, ns, pat, err, route, ns)
			}
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

// validateSumdbURL refuses a gomod_sumdb_url the checksum-database proxy
// cannot use. The go command trusts what comes back only because its signed
// tree heads verify against the key it already holds, but a plain-http fetch
// still leaks every module a host resolves to the path.
func validateSumdbURL(raw string) error {
	return validateRootURL("gomod_sumdb_url", raw, "https://sum.golang.org")
}

// validateRootURL holds an upstream key the server appends request paths to:
// https, a host, and nothing a composed URL would carry past the path.
func validateRootURL(key, raw, def string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return fmt.Errorf("%s %q does not parse: %v", key, raw, err)
	case u.Scheme != "https":
		return fmt.Errorf("%s %q must be an https URL (default %s)", key, raw, def)
	case u.Host == "":
		return fmt.Errorf("%s %q names no host", key, raw)
	case u.User != nil, u.RawQuery != "", u.Fragment != "":
		return fmt.Errorf("%s %q carries userinfo, a query or a fragment — the request path is appended to it", key, raw)
	}
	return nil
}

// validateProxyUpstream holds an upstream key the fetch path appends request
// paths to but that may carry a private index's credential in its userinfo,
// which validateRootURL refuses. Every error names the value with the
// password masked, because it reaches the serve log.
func validateProxyUpstream(key, raw, def string) error {
	u, err := url.Parse(raw)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s %q does not parse: %v (default %s)", key, redactUserinfo(raw), err, def)
	}
	shown := raw
	if u.User != nil {
		shown = u.Redacted()
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%s %q must be an https URL (default %s)", key, shown, def)
	case u.Host == "":
		return fmt.Errorf("%s %q names no host (default %s)", key, shown, def)
	case u.RawQuery != "", u.Fragment != "":
		return fmt.Errorf("%s %q carries a query or a fragment — the request path is appended to it (default %s)", key, shown, def)
	}
	return nil
}

// resolveOCIUpstreams fills in and validates oci_upstreams and
// oci_token_hosts. An absent map takes the defaults and a given one is used
// as written, so an operator can drop a registry by leaving it out; an empty
// oci_token_hosts leaves each registry only its own host as a realm.
func resolveOCIUpstreams(cfg *Config) error {
	if cfg.OCIUpstreams == nil {
		cfg.OCIUpstreams = maps.Clone(DefaultOCIUpstreams)
	}
	resolved := make(map[string]string, len(cfg.OCIUpstreams))
	for name, raw := range cfg.OCIUpstreams {
		key := strings.ToLower(strings.TrimSpace(name))
		if !manifest.OCIValidRegistryName(key) {
			return fmt.Errorf("oci_upstreams key %q is not a registry hostname: lowercase, at least one dot, no scheme, port or path, e.g. \"ghcr.io\"", name)
		}
		if _, dup := resolved[key]; dup {
			return fmt.Errorf("oci_upstreams names %q twice once case is folded", key)
		}
		u := strings.TrimRight(strings.TrimSpace(raw), "/")
		def := DefaultOCIUpstreams[key]
		if def == "" {
			def = "https://" + key
		}
		if err := validateProxyUpstream(fmt.Sprintf("oci_upstreams[%q]", key), u, def); err != nil {
			return err
		}
		resolved[key] = u
	}
	cfg.OCIUpstreams = resolved
	if cfg.OCITokenHosts == nil {
		cfg.OCITokenHosts = append([]string(nil), DefaultOCITokenHosts...)
	}
	return validateHostList("oci_token_hosts", cfg.OCITokenHosts)
}

// RpmSampleReleasever and RpmSampleBasearch are what resolveRpmUpstreams
// substitutes into a base URL to validate it, since the URL bodega fetches
// exists only once a request names both.
const (
	RpmSampleReleasever = "9"
	RpmSampleBasearch   = "x86_64"
)

// resolveRpmUpstreams validates rpm_upstreams. There is no default: an
// operator names the repositories bodega serves, and an absent map serves
// none. A base URL may carry $releasever and $basearch, which a request
// supplies; any other dnf variable ($contentdir, $stream) would reach the
// upstream as literal text, so it is refused here rather than as a 404 from
// the mirror.
func resolveRpmUpstreams(cfg *Config) error {
	resolved := make(map[string]string, len(cfg.RpmUpstreams))
	for name, raw := range cfg.RpmUpstreams {
		key := strings.TrimSpace(name)
		if !manifest.RpmValidRepoName(key) {
			return fmt.Errorf("rpm_upstreams key %q is not a repository name: letters, digits, '.', '_' and '-', up to 64, not starting with '.' or '-', e.g. \"rocky-baseos\"", name)
		}
		if _, dup := resolved[key]; dup {
			return fmt.Errorf("rpm_upstreams names %q twice once whitespace is trimmed", key)
		}
		u := strings.TrimRight(strings.TrimSpace(raw), "/") + "/"
		sample := strings.NewReplacer("$releasever", RpmSampleReleasever, "$basearch", RpmSampleBasearch).Replace(u)
		field := fmt.Sprintf("rpm_upstreams[%q]", key)
		if err := validateProxyUpstream(field, sample, "https://dl.rockylinux.org/pub/rocky/$releasever/BaseOS/$basearch/os/"); err != nil {
			return err
		}
		if strings.Contains(sample, "$") {
			return fmt.Errorf("%s names a variable other than $releasever and $basearch, which bodega does not substitute: write the value it stands for", field)
		}
		resolved[key] = u
	}
	cfg.RpmUpstreams = resolved
	return nil
}

// RpmRepoNames is the rpm_upstreams keys, sorted.
func (cfg *Config) RpmRepoNames() []string {
	return slices.Sorted(maps.Keys(cfg.RpmUpstreams))
}

// redactUserinfo masks the password in a URL url.Parse refused, which
// Redacted cannot reach: everything between the first ':' and the last '@'
// of the authority.
func redactUserinfo(raw string) string {
	rest, scheme := raw, ""
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, rest = raw[:i+3], raw[i+3:]
	}
	auth, path := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		auth, path = rest[:i], rest[i:]
	}
	at := strings.LastIndex(auth, "@")
	if at < 0 {
		return raw
	}
	user := auth[:at]
	if c := strings.Index(user, ":"); c >= 0 {
		user = user[:c] + ":xxxxx"
	}
	return scheme + user + auth[at:] + path
}

// CanonicalHost is the form private_upstream_hosts is matched in: lower case,
// and an IP literal in its shortest spelling so "FD00:0::5" and "fd00::5" name
// one host.
func CanonicalHost(h string) string {
	h = strings.ToLower(h)
	if a, err := netip.ParseAddr(h); err == nil && a.Zone() == "" {
		return a.String()
	}
	return h
}

var hostLabelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// validatePrivateUpstreamHosts canonicalizes each entry in place and refuses
// one that is not a bare hostname or IP literal. A URL, a port or a path here
// would match no upstream, and the operator would see the private-address
// refusal they listed the host to clear.
func validatePrivateUpstreamHosts(hosts []string) error {
	return validateHostList("private_upstream_hosts", hosts)
}

// validateHostList canonicalizes each entry of a host-list key in place and
// refuses one that is not a bare hostname or IP literal.
func validateHostList(key string, hosts []string) error {
	for i, raw := range hosts {
		h := CanonicalHost(strings.TrimSpace(raw))
		if a, err := netip.ParseAddr(h); err == nil {
			if a.Zone() != "" {
				return fmt.Errorf("%s entry %q carries an IPv6 zone; name the address alone", key, raw)
			}
			hosts[i] = h
			continue
		}
		ok := h != "" && len(h) <= 253
		for _, label := range strings.Split(h, ".") {
			ok = ok && hostLabelRE.MatchString(label)
		}
		if !ok {
			return fmt.Errorf("%s entry %q is not a hostname or IP literal (no scheme, port or path), e.g. \"registry.internal.example\"", key, raw)
		}
		hosts[i] = h
	}
	return nil
}

// DefaultMavenUpstream is Maven Central's repository root.
const DefaultMavenUpstream = "https://repo.maven.apache.org/maven2"

// DefaultGradlePluginPortal is the Gradle Plugin Portal's Maven repository,
// where every community plugin's marker artifact
// (<id>:<id>.gradle.plugin) is published and Maven Central carries none.
const DefaultGradlePluginPortal = "https://plugins.gradle.org/m2"

// DefaultMavenUpstreams is the list /maven/ reads when neither maven_upstream
// nor maven_upstreams is set: Central first, so the Portal is asked only for
// what Central does not publish.
func DefaultMavenUpstreams() []string {
	return []string{DefaultMavenUpstream, DefaultGradlePluginPortal}
}

// resolveMavenUpstreams folds maven_upstream into maven_upstreams, applies the
// default and validates each entry. Both keys set is refused rather than
// merged: no order between them is one the operator wrote.
func resolveMavenUpstreams(cfg *Config) error {
	switch {
	case cfg.MavenUpstream != "" && cfg.MavenUpstreams != nil:
		return fmt.Errorf("maven_upstream and maven_upstreams are both set; keep maven_upstreams and add %q to it where it belongs in the order", cfg.MavenUpstream)
	case cfg.MavenUpstream != "":
		cfg.MavenUpstreams = []string{cfg.MavenUpstream}
	case cfg.MavenUpstreams == nil:
		cfg.MavenUpstreams = DefaultMavenUpstreams()
	case len(cfg.MavenUpstreams) == 0:
		return fmt.Errorf("maven_upstreams is an empty list, which leaves /maven/ no repository to read; remove the key for the default (%s)", strings.Join(DefaultMavenUpstreams(), ", "))
	}
	key := "maven_upstreams entry"
	if cfg.MavenUpstream != "" {
		key = "maven_upstream"
	}
	cfg.MavenUpstream = ""
	seen := make(map[string]bool, len(cfg.MavenUpstreams))
	for i, raw := range cfg.MavenUpstreams {
		root := strings.TrimRight(strings.TrimSpace(raw), "/")
		if err := validateMavenUpstream(key, root); err != nil {
			return err
		}
		if seen[root] {
			return fmt.Errorf("maven_upstreams names %q twice; a repository asked again after its 404 answers the same", root)
		}
		seen[root] = true
		cfg.MavenUpstreams[i] = root
	}
	return nil
}

// validateMavenUpstream refuses a repository root the route could not append
// a repository path to, naming key in the error. https only: unlike a distfile, nothing downstream of
// the transport checks a jar against a digest bodega holds.
func validateMavenUpstream(key, raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return fmt.Errorf("%s %q does not parse: %v", key, raw, err)
	case u.Scheme != "https":
		return fmt.Errorf("%s %q must be an https URL (default %s)", key, raw, DefaultMavenUpstream)
	case u.Host == "":
		return fmt.Errorf("%s %q names no host", key, raw)
	case u.User != nil:
		return fmt.Errorf("%s carries userinfo before the host — bodega reads no credential from this file and would copy it into logs and error messages. Remove everything between \"//\" and %q", key, u.Host)
	case u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%s %q carries a query or fragment — the repository path is appended to it, which would land after it", key, raw)
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

// gitRepoDepth is how many path segments a repository name under git
// namespace ns carries after the namespace: two (<owner>/<repo>) when the
// upstream URL stops at the host, one when the URL already names an owner or
// group. It is a minimum, not a count: a forge with nested groups puts a
// repository deeper, and the smart-HTTP gate matches it at whatever depth the
// clone path has. ok is false for a namespace git_upstreams does not name.
func (c *Config) gitRepoDepth(ns string) (depth int, ok bool) {
	up, ok := c.GitUpstreams[ns]
	if !ok {
		return 0, false
	}
	u, err := url.Parse(up.URL)
	if err != nil {
		return 2, true
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return 1, true
	}
	return 2, true
}

// ValidateGitEntryName refuses a git profile entry the gate could never
// match. The gate looks a clone up as <namespace>/<path after the namespace>,
// without the .git suffix, and then as the bare namespace; the legacy bundle
// route looks one up under its one-segment bundle name.
//
// Counting segments cannot answer this, because how deep a repository sits
// depends on the namespace's URL and on the forge's group nesting. A
// host-root namespace whose name is one segment short (github/louislam) is
// refused: without the forge's own depth it cannot be told from an owner,
// and an entry naming an owner admits nothing.
func (c *Config) ValidateGitEntryName(name string) error {
	segs := strings.Split(name, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("git entry %q has an empty, \".\" or \"..\" segment, which no clone path carries", name)
		}
	}
	if len(segs) == 1 {
		return nil
	}
	ns, repo := segs[0], segs[1:]
	depth, ok := c.gitRepoDepth(ns)
	if !ok {
		namespaces := make([]string, 0, len(c.GitUpstreams))
		for k := range c.GitUpstreams {
			namespaces = append(namespaces, k)
		}
		sort.Strings(namespaces)
		configured := "none; add one to git_upstreams in config.json"
		if len(namespaces) > 0 {
			configured = strings.Join(namespaces, ", ")
		}
		return fmt.Errorf("git entry %q names namespace %q, which git_upstreams does not configure, so no clone could ever match it.\n"+
			"  Configured namespaces: %s", name, ns, configured)
	}
	if strings.HasSuffix(repo[len(repo)-1], ".git") {
		return fmt.Errorf("git entry %q ends in .git, which the clone URL carries and the entry does not: write %s",
			name, strings.TrimSuffix(name, ".git"))
	}
	if len(repo) < depth {
		return fmt.Errorf("git entry %q is too short to name a repository under namespace %q.\n"+
			"  %q points at %s, so a repository is the namespace followed by at least %d path segment(s), e.g. %s",
			name, ns, ns, c.GitUpstreams[ns].URL, depth, gitEntryExample(ns, depth))
	}
	return nil
}

// gitEntryExample is one repository name of the minimum depth under ns.
func gitEntryExample(ns string, depth int) string {
	if depth == 1 {
		return ns + "/<repo>"
	}
	return ns + "/<owner>/<repo>"
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

	// Components are the components this archive publishes for the codename,
	// for the Components: line of the client stanza. Empty takes
	// aptsources.MirroredComponents.
	//
	// Configured rather than read, because reading it means fetching the
	// upstream Release at startup and parsing it, which is the pattern
	// internal/server/cargo.go already refuses for index.crates.io/config.json:
	// a server that will not start until an upstream answers has made every
	// client's availability depend on a host it only proxies. bodega parses no
	// index and forwards whatever path arrives, so any component named here
	// resolves whether or not bodega has ever heard of it.
	Components []string `json:"components,omitempty"`

	// SigningKeyURL is where the archive publishes the OpenPGP key that signs
	// its InRelease, e.g. "https://apt.grafana.com/gpg.key". Set for a vendor
	// archive whose key no stock client carries: a mirrored codename forwards
	// the upstream signature, and a host locked to bodega cannot fetch the key
	// from the vendor itself. GET /apt/keys/<codename>.asc serves it.
	SigningKeyURL string `json:"signing_key_url,omitempty"`

	// SigningKeyFingerprint is the primary key fingerprint the key at
	// SigningKeyURL must carry, 40 hex digits. It is the operator's decision to
	// trust the vendor, taken out of band: the URL alone is authenticated by
	// TLS and nothing else. Load normalizes it to uppercase with no spaces.
	SigningKeyFingerprint string `json:"signing_key_fingerprint,omitempty"`
}

// aptFingerprintPattern is a normalized OpenPGP v4 primary key fingerprint.
var aptFingerprintPattern = regexp.MustCompile(`^[0-9A-F]{40}$`)

// AptSigningKey is a mirrored codename's vendor key, as Load validated it.
type AptSigningKey struct {
	URL         string
	Fingerprint string
}

// AptSigningKeyFor returns the vendor key configured for a mirrored codename,
// and false when none is. Load guarantees every entry of one codename that
// names a key names the same fingerprint, so the first one found answers.
func (c *Config) AptSigningKeyFor(codename string) (AptSigningKey, bool) {
	for _, up := range c.AptUpstreams[codename] {
		if up.SigningKeyURL != "" {
			return AptSigningKey{URL: up.SigningKeyURL, Fingerprint: up.SigningKeyFingerprint}, true
		}
	}
	return AptSigningKey{}, false
}

// AptKeyedCodenames returns the mirrored codenames that carry a vendor key,
// sorted.
func (c *Config) AptKeyedCodenames() []string {
	var out []string
	for _, codename := range c.MirroredAptCodenames() {
		if _, ok := c.AptSigningKeyFor(codename); ok {
			out = append(out, codename)
		}
	}
	return out
}

// validateAptSigningKey refuses half a key pair, a key URL that is not https,
// and a fingerprint that is not 40 hex digits, and normalizes the fingerprint.
func validateAptSigningKey(codename string, i int, up *AptUpstream) error {
	if up.SigningKeyURL == "" && up.SigningKeyFingerprint == "" {
		return nil
	}
	if up.SigningKeyURL == "" || up.SigningKeyFingerprint == "" {
		return fmt.Errorf("apt_upstreams[%q][%d]: signing_key_url and signing_key_fingerprint go together — the URL says where the key is, the fingerprint says which key you trust. Set both, or neither", codename, i)
	}
	u, err := url.Parse(up.SigningKeyURL)
	switch {
	case err != nil:
		return fmt.Errorf("apt_upstreams[%q][%d]: signing_key_url %q does not parse: %v", codename, i, up.SigningKeyURL, err)
	case u.Scheme != "https":
		return fmt.Errorf("apt_upstreams[%q][%d]: signing_key_url %q must use the https scheme", codename, i, up.SigningKeyURL)
	case u.Host == "":
		return fmt.Errorf("apt_upstreams[%q][%d]: signing_key_url %q names no host", codename, i, up.SigningKeyURL)
	}
	fpr := strings.ToUpper(strings.ReplaceAll(up.SigningKeyFingerprint, " ", ""))
	if !aptFingerprintPattern.MatchString(fpr) {
		return fmt.Errorf("apt_upstreams[%q][%d]: signing_key_fingerprint %q is not an OpenPGP primary key fingerprint: want 40 hex digits (spaces allowed), as `gpg --show-keys --with-fingerprint <key>` prints it", codename, i, up.SigningKeyFingerprint)
	}
	up.SigningKeyFingerprint = fpr
	return nil
}

// aptComponentPattern is what a component name may look like: what apt puts in
// a path segment under dists/<codename>/, which covers "main", "non-free" and
// "non-free-firmware".
var aptComponentPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

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
			for j, comp := range up.Components {
				if !aptComponentPattern.MatchString(comp) {
					return fmt.Errorf("apt_upstreams[%q][%d].components[%d]: %q must match %s — it is a path segment apt requests under /apt/dists/%s/",
						codename, i, j, comp, aptComponentPattern, codename)
				}
			}
			list[i].URL = strings.TrimRight(up.URL, "/")
			if err := validateAptSigningKey(codename, i, &list[i]); err != nil {
				return err
			}
		}
		var fpr string
		for i, up := range list {
			switch {
			case up.SigningKeyFingerprint == "":
			case fpr == "":
				fpr = up.SigningKeyFingerprint
			case up.SigningKeyFingerprint != fpr:
				return fmt.Errorf("apt_upstreams[%q][%d]: signing_key_fingerprint %s differs from %s on an earlier entry: a codename is one InRelease and is signed by one key, so /apt/keys/%s.asc can serve only one",
					codename, i, up.SigningKeyFingerprint, fpr, codename)
			}
		}
	}
	return nil
}

// AptComponentsFor returns the components the client stanza for a mirrored
// codename should name: every component its upstreams declare, in config order,
// each once. Empty when the codename is not mirrored or names none, which
// renders aptsources.MirroredComponents.
//
// The union rather than one upstream's list: a real suite is split across
// archive, security and updates hosts, apt reads one Components: line for all of
// them, and a component any of them publishes is one apt may request.
func (c *Config) AptComponentsFor(codename string) []string {
	var out []string
	seen := map[string]bool{}
	for _, up := range c.AptUpstreams[codename] {
		for _, comp := range up.Components {
			if seen[comp] {
				continue
			}
			seen[comp] = true
			out = append(out, comp)
		}
	}
	return out
}

// MirrorsAptCodename reports whether a codename is served from upstream rather
// than generated. Load guarantees the two sets are disjoint, so a true answer
// here is also a guarantee that no generated suite answers for it.
func (c *Config) MirrorsAptCodename(codename string) bool {
	_, ok := c.AptUpstreams[codename]
	return ok
}

// ProfileAptCodename is the codename a profile's filtered apt index is served
// under: the mirrored codename it derives from, with the profile appended.
//
// Derived rather than stored so nothing has to keep two spellings in step. The
// base is in the name because a profile filters one upstream suite and the
// operator reading a sources line needs to see which; the profile is in it
// because two profiles over one base are the ordinary case.
func ProfileAptCodename(base, profile string) string {
	return base + "-" + profile
}

// ValidateProfileAptCodename reports whether a derived codename can be served
// beside what this config already answers for.
//
// Three ways it cannot. A name apt itself will not parse as a suite; a
// collision with a generated suite, whose Release this one would shadow in
// handleAptDists; and a collision with a mirrored codename, where a proxied
// dists/ tree wins the route and the filtered index is generated for nobody.
// Each is a profile rename or an apt_upstreams key rename, so the error names
// the pair that produced it.
func (c *Config) ValidateProfileAptCodename(codename, base, profile string) error {
	if !aptCodenamePattern.MatchString(codename) {
		return fmt.Errorf("profile %q over base %q derives the codename %q, which must match %s — rename the profile to a lowercase word",
			profile, base, codename, aptCodenamePattern)
	}
	if c.ServesAptSuite(codename) {
		return fmt.Errorf("profile %q over base %q derives the codename %q, which apt_suites already serves: one URL serves one Release, and the generated suite owns it",
			profile, base, codename)
	}
	if c.MirrorsAptCodename(codename) {
		return fmt.Errorf("profile %q over base %q derives the codename %q, which apt_upstreams already mirrors: the proxied dists/ tree wins the route and the filtered index would be generated for nobody",
			profile, base, codename)
	}
	return nil
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

// ResolveSpoolDir names the directory the proxy copies an upstream artifact
// through on its way to storage and the client: spool_dir, else
// <storage_path>/tmp. Deriving it from the config rather than reading $TMPDIR
// is what stops the artifact traffic landing on a filesystem nobody chose.
//
// It hangs off storage_path rather than build_root because the server unit
// docs/bodega.service ships runs ProtectSystem=strict with ReadWritePaths
// naming storage_path and log_dir alone. build_root defaults to /opt/bodega,
// which that unit makes read-only, so a build_root default meant serve refused
// to start on the deployment the unit describes. The spool also feeds
// storage_path on every miss, so sharing a filesystem with it turns the final
// move into a rename.
//
// DefaultStoragePath stands in when storage_path is unset, which is what an
// S3-only install leaves it as. DefaultManifestDir resolves the same way for
// the same reason: both land inside the unit's ReadWritePaths whether or not
// the operator wrote the key.
func (c *Config) ResolveSpoolDir() string {
	if c.SpoolDir != "" {
		return c.SpoolDir
	}
	return filepath.Join(firstNonEmpty(c.StoragePath, DefaultStoragePath), "tmp")
}

// UsesLocalManifests reports whether manifests are read and written straight
// from the filesystem rather than through the object store. Every caller that
// picks a manifest store must answer this the same way: when they disagree, a
// local install passes the mutation preflight and then fails asking for a
// bucket it never configured, or the TUI reloads from a leftover bucket the
// rest of the process stopped reading. --local-config forces it on whatever
// the configured backend is.
func (c *Config) UsesLocalManifests() bool {
	if c == nil {
		return true
	}
	return c.LocalConfig || c.StorageBackend == "" || c.StorageBackend == "local"
}

// ResolveOSVDBDir returns the directory the local OSV database lives in.
// Unset means {storage_path}/osv rather than "no database": the gate should
// find what `bodega policy osv sync` wrote without a second key being set.
func (c *Config) ResolveOSVDBDir() string {
	if c == nil {
		return ""
	}
	if c.OSVDBDir != "" {
		return c.OSVDBDir
	}
	return filepath.Join(firstNonEmpty(c.StoragePath, DefaultStoragePath), "osv")
}

// ResolveOSVDBMaxAge returns the staleness window for a synced ecosystem, or
// zero when the key is unset, which leaves the default with the gate that
// enforces it (policy.DefaultOSVMaxAge) rather than stating it in two places.
// Load has already refused an unparseable value, so a bad one here can only
// come from a Config built in code.
func (c *Config) ResolveOSVDBMaxAge() time.Duration {
	if c == nil || c.OSVDBMaxAge == "" {
		return 0
	}
	d, err := time.ParseDuration(c.OSVDBMaxAge)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// Values of revet_on_block.
const (
	RevetReport = "report"
	RevetHide   = "hide"
)

// DefaultRevetRate is revet_rate when unset, in versions per second.
const DefaultRevetRate = 1.0

// ResolveRevetInterval returns the scheduled re-vet interval, or zero when
// the schedule is off. Load has already refused an unparseable value.
func (c *Config) ResolveRevetInterval() time.Duration {
	if c == nil || c.RevetInterval == "" {
		return 0
	}
	d, err := time.ParseDuration(c.RevetInterval)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// ResolveRevetPause is the wait between two versions of a scheduled sweep,
// from revet_rate.
func (c *Config) ResolveRevetPause() time.Duration {
	rate := DefaultRevetRate
	if c != nil && c.RevetRate > 0 {
		rate = c.RevetRate
	}
	return time.Duration(float64(time.Second) / rate)
}

// ResolveRevetOnBlock returns revet_on_block, defaulting to report.
func (c *Config) ResolveRevetOnBlock() string {
	if c == nil || c.RevetOnBlock == "" {
		return RevetReport
	}
	return c.RevetOnBlock
}

// Defaults for the override keys.
const (
	DefaultOverrideMaxTTL = 30 * 24 * time.Hour
	DefaultOverrideQuorum = 2
)

// ResolveOverrideMaxTTL returns override_max_ttl, defaulting to 30 days. Load
// has already refused an unparseable value.
func (c *Config) ResolveOverrideMaxTTL() time.Duration {
	if c == nil || c.OverrideMaxTTL == "" {
		return DefaultOverrideMaxTTL
	}
	d, err := ParseTTL(c.OverrideMaxTTL)
	if err != nil {
		return DefaultOverrideMaxTTL
	}
	return d
}

// ResolveOverrideQuorum returns override_quorum, defaulting to 2.
func (c *Config) ResolveOverrideQuorum() int {
	if c == nil || c.OverrideQuorum == 0 {
		return DefaultOverrideQuorum
	}
	return c.OverrideQuorum
}

// ParseTTL reads a positive Go duration, or a whole number of days written
// <N>d, which is how an expiry is usually said and which time.ParseDuration
// does not accept.
func ParseTTL(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid duration %q (want e.g. \"7d\" or \"72h\")", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q (want e.g. \"7d\" or \"72h\")", s)
	}
	return d, nil
}

// spoolCeiling resolves one of the two spool byte ceilings against the file
// that was actually read. An absent key takes the built-in default; a key
// written as 0 is an operator turning the ceiling off, and json.Unmarshal
// cannot tell those two apart on an int64.
func spoolCeiling(snap *fileSnapshot, key string, have, def int64) (int64, error) {
	if have < 0 {
		return 0, fmt.Errorf("%s must not be negative (got %d); write 0 to remove the ceiling", key, have)
	}
	if have == 0 {
		if snap == nil {
			return def, nil
		}
		if _, present := snap.raw[key]; !present {
			return def, nil
		}
	}
	return have, nil
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
	cfg.ManifestDir = firstNonEmpty(manifestDir, os.Getenv(EnvManifestDir), cfg.ManifestDir, DefaultManifestDir(cfg.StoragePath))
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
	cfg.UpstreamConnectTimeout = firstNonEmpty(cfg.UpstreamConnectTimeout, DefaultUpstreamConnectTimeout)
	cfg.StaleGrace = firstNonEmpty(cfg.StaleGrace, DefaultStaleGrace)
	// The server parses both with no error path, so a typo here would become
	// a zero: no connect bound at all, or no grace.
	for _, d := range []struct{ key, val, example string }{
		{"upstream_connect_timeout", cfg.UpstreamConnectTimeout, DefaultUpstreamConnectTimeout},
		{"stale_grace", cfg.StaleGrace, DefaultStaleGrace},
	} {
		if v, err := time.ParseDuration(d.val); err != nil || v <= 0 {
			return nil, fmt.Errorf("invalid %s %q (want a positive Go duration, e.g. %q)", d.key, d.val, d.example)
		}
	}
	cfg.GomodUpstream = firstNonEmpty(cfg.GomodUpstream, "https://proxy.golang.org")
	cfg.GomodSumdbURL = strings.TrimRight(firstNonEmpty(cfg.GomodSumdbURL, "https://sum.golang.org"), "/")
	if err := validateSumdbURL(cfg.GomodSumdbURL); err != nil {
		return nil, err
	}
	cfg.NpmUpstream = firstNonEmpty(cfg.NpmUpstream, "https://registry.npmjs.org")
	cfg.PypiUpstream = firstNonEmpty(cfg.PypiUpstream, "https://pypi.org")
	cfg.CargoUpstream = firstNonEmpty(cfg.CargoUpstream, "https://index.crates.io")
	if err := resolveMavenUpstreams(cfg); err != nil {
		return nil, err
	}
	cfg.RubygemsUpstream = strings.TrimRight(firstNonEmpty(cfg.RubygemsUpstream, DefaultRubygemsUpstream), "/")
	if err := validateRootURL("rubygems_upstream", cfg.RubygemsUpstream, DefaultRubygemsUpstream); err != nil {
		return nil, err
	}
	cfg.ComposerUpstream = strings.TrimRight(firstNonEmpty(cfg.ComposerUpstream, DefaultComposerUpstream), "/")
	if err := validateRootURL("composer_upstream", cfg.ComposerUpstream, DefaultComposerUpstream); err != nil {
		return nil, err
	}
	// Absent takes the default; an empty list is the operator refusing every
	// dist host, which is a choice rather than an omission.
	if cfg.ComposerDistHosts == nil {
		cfg.ComposerDistHosts = append([]string(nil), DefaultComposerDistHosts...)
	}
	if err := validateHostList("composer_dist_hosts", cfg.ComposerDistHosts); err != nil {
		return nil, err
	}
	if err := resolveOCIUpstreams(cfg); err != nil {
		return nil, err
	}
	if err := resolveRpmUpstreams(cfg); err != nil {
		return nil, err
	}
	cfg.DistfilesUpstream = firstNonEmpty(cfg.DistfilesUpstream, DefaultDistfilesUpstream)

	// crates.io publishes the index and the tarballs on separate hosts, and
	// the index's own config.json is where the download root is named. Reading
	// it at startup would make `bodega serve` fail to bind because a registry
	// was unreachable, so the value is configuration and the default is what
	// that document says today. An operator mirroring the index is not thereby
	// mirroring the downloads, and needs to name both.
	cfg.CargoDLUpstream = firstNonEmpty(cfg.CargoDLUpstream, "https://static.crates.io/crates")

	// The fetch path refuses anything but https on every request, so a scheme
	// typo left to it is found by the first client rather than by serve.
	for _, u := range []struct{ key, val, def string }{
		{"gomod_upstream", cfg.GomodUpstream, "https://proxy.golang.org"},
		{"npm_upstream", cfg.NpmUpstream, "https://registry.npmjs.org"},
		{"pypi_upstream", cfg.PypiUpstream, "https://pypi.org"},
		{"cargo_upstream", cfg.CargoUpstream, "https://index.crates.io"},
		{"cargo_dl_upstream", cfg.CargoDLUpstream, "https://static.crates.io/crates"},
	} {
		if err := validateProxyUpstream(u.key, u.val, u.def); err != nil {
			return nil, err
		}
	}
	if err := validatePrivateUpstreamHosts(cfg.PrivateUpstreamHosts); err != nil {
		return nil, err
	}

	// Proxy spool ceilings.
	if cfg.SpoolMaxArtifactBytes, err = spoolCeiling(snap, "spool_max_artifact_bytes", cfg.SpoolMaxArtifactBytes, DefaultSpoolMaxArtifactBytes); err != nil {
		return nil, err
	}
	if cfg.SpoolMaxTotalBytes, err = spoolCeiling(snap, "spool_max_total_bytes", cfg.SpoolMaxTotalBytes, DefaultSpoolMaxTotalBytes); err != nil {
		return nil, err
	}
	if cfg.SpoolMaxTotalBytes > 0 && cfg.SpoolMaxArtifactBytes > cfg.SpoolMaxTotalBytes {
		return nil, fmt.Errorf("spool_max_artifact_bytes (%d) is above spool_max_total_bytes (%d): no artifact that large could ever be admitted, so every fetch over the budget would be refused for a reason naming the wrong key",
			cfg.SpoolMaxArtifactBytes, cfg.SpoolMaxTotalBytes)
	}

	// osv_db_max_age is read once per admission; a value time.ParseDuration
	// rejects would otherwise fall back to the default with nothing said, and
	// the operator would believe a tighter window was in force.
	if cfg.OSVDBMaxAge != "" {
		if d, err := time.ParseDuration(cfg.OSVDBMaxAge); err != nil || d <= 0 {
			return nil, fmt.Errorf("invalid osv_db_max_age %q (want a positive Go duration, e.g. \"168h\")", cfg.OSVDBMaxAge)
		}
	}

	// A typo in any of the three would otherwise read as "off", "the default
	// rate" or "report", and an operator who asked for hide would learn
	// otherwise from a version still being served.
	if cfg.RevetInterval != "" {
		if d, err := time.ParseDuration(cfg.RevetInterval); err != nil || d <= 0 {
			return nil, fmt.Errorf("invalid revet_interval %q (want a positive Go duration, e.g. \"24h\")", cfg.RevetInterval)
		}
	}
	if cfg.RevetRate < 0 {
		return nil, fmt.Errorf("invalid revet_rate %v (want versions per second above 0)", cfg.RevetRate)
	}
	switch cfg.RevetOnBlock {
	case "", RevetReport, RevetHide:
	default:
		return nil, fmt.Errorf("invalid revet_on_block %q (want %q or %q)", cfg.RevetOnBlock, RevetReport, RevetHide)
	}

	// A quorum of one is the single-operator override this setting exists
	// to replace, so it is refused rather than honored.
	if cfg.OverrideMaxTTL != "" {
		if _, err := ParseTTL(cfg.OverrideMaxTTL); err != nil {
			return nil, fmt.Errorf("override_max_ttl: %w", err)
		}
	}
	if cfg.OverrideQuorum != 0 && cfg.OverrideQuorum < 2 {
		return nil, fmt.Errorf("invalid override_quorum %d (want 2 or more: the requester plus at least one other identity)", cfg.OverrideQuorum)
	}

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
	// do not cover the Packages it is served next.
	if err := validateAptUpstreams(cfg.AptUpstreams); err != nil {
		return nil, err
	}
	for _, suite := range cfg.AptSuites {
		if cfg.MirrorsAptCodename(suite) {
			return nil, fmt.Errorf("apt codename %q is in both apt_suites and apt_upstreams: bodega generates and signs one, mirrors the other, and one URL can serve only one of them. "+
				"Drop it from apt_suites to mirror it, or from apt_upstreams to keep serving your own .debs under that name — a mirrored codename needs a name of its own", suite)
		}
	}

	if err := cfg.validateStorage(); err != nil {
		return nil, err
	}

	if err := validateUpstreams("git_upstreams", "/git/", cfg.GitUpstreams); err != nil {
		return nil, err
	}
	for ns, up := range cfg.GitUpstreams {
		if len(up.Revalidate) > 0 {
			return nil, fmt.Errorf("git_upstreams[%q]: revalidate applies to binary_upstreams only — a git namespace serves a fresh clone, never a path-cached object. Remove the key", ns)
		}
	}

	if err := validateUpstreams("binary_upstreams", "/binaries/", cfg.BinaryUpstreams); err != nil {
		return nil, err
	}

	if err := cfg.validateDistfiles(); err != nil {
		return nil, err
	}

	if len(cfg.InventorySources) > 0 {
		if ValidateInventorySources == nil {
			return nil, errors.New("inventory_sources is set, but this binary links no inventory source registry to check it against")
		}
		if err := ValidateInventorySources(cfg.InventorySources); err != nil {
			return nil, err
		}
	}

	if len(cfg.Integrations) > 0 {
		if ValidateIntegrations == nil {
			return nil, errors.New("integrations is set, but this binary links no integration registry to check it against")
		}
		if err := ValidateIntegrations(cfg.Integrations); err != nil {
			return nil, err
		}
	}

	if err := cfg.OsqueryScanDirs.validate(); err != nil {
		return nil, err
	}

	if err := cfg.validateOIDC(); err != nil {
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

// OsqueryDirs is one set of language-package trees.
type OsqueryDirs struct {
	Python []string `json:"python,omitempty"`
	NPM    []string `json:"npm,omitempty"`
}

// OsqueryScanDirs is osquery_scan_dirs: the trees for a host whose profile
// has no entry, and per-profile replacements. A profile's entry replaces the
// default rather than adding to it, so a profile can scan less than the rest
// of the fleet. Both default to nothing, which scans no language trees.
type OsqueryScanDirs struct {
	Default  OsqueryDirs            `json:"default,omitzero"`
	Profiles map[string]OsqueryDirs `json:"profiles,omitempty"`
}

// For returns the trees a host bound to profile scans; "" is a host with no
// profile.
func (o OsqueryScanDirs) For(profile string) OsqueryDirs {
	if d, ok := o.Profiles[profile]; ok && profile != "" {
		return d
	}
	return o.Default
}

// validate refuses a directory that is not absolute or that carries a quote
// or control character. Each one is written into an osquery SQL string
// literal, so a quote would end the literal and a relative path would scan
// wherever osqueryd happens to run.
func (o OsqueryScanDirs) validate() error {
	check := func(where string, d OsqueryDirs) error {
		for kind, dirs := range map[string][]string{"python": d.Python, "npm": d.NPM} {
			for _, dir := range dirs {
				if !strings.HasPrefix(dir, "/") {
					return fmt.Errorf("osquery_scan_dirs.%s.%s: %q is not an absolute path", where, kind, dir)
				}
				if strings.ContainsAny(dir, "'\"\\") || strings.ContainsFunc(dir, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
					return fmt.Errorf("osquery_scan_dirs.%s.%s: %q holds a quote, backslash or control character, which an osquery query cannot carry safely", where, kind, dir)
				}
			}
		}
		return nil
	}
	if err := check("default", o.Default); err != nil {
		return err
	}
	for name, d := range o.Profiles {
		if name == "" {
			return errors.New("osquery_scan_dirs.profiles: a profile name is empty; the default entry is where a host with no profile is configured")
		}
		if err := check("profiles."+name, d); err != nil {
			return err
		}
	}
	return nil
}

// InventorySource is one inventory_sources entry as the file carries it.
// internal/inventory owns what the keys mean.
type InventorySource map[string]any

// ValidateInventorySources checks inventory_sources during Load, and refuses
// the load on an unknown type, an unknown key or a value the type rejects.
// internal/inventory sets it: the registry of source types lives there, and
// that package already imports this one.
var ValidateInventorySources func(map[string]InventorySource) error

// Integration is one integrations entry as the file carries it.
type Integration map[string]any

// ValidateIntegrations checks integrations during Load. internal/integration
// sets it, for the reason ValidateInventorySources is set from outside.
var ValidateIntegrations func(map[string]Integration) error

// FileKey returns one top-level key of the config file in force as the file
// writes it. ok is false when the file or the key is absent.
func FileKey(key string) (json.RawMessage, bool, error) {
	data, err := os.ReadFile(ConfigPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, parseConfigError(ConfigPath(), err)
	}
	v, ok := raw[key]
	return v, ok, nil
}

// SetFileKey writes one top-level key of the config file in force and
// returns the path written. Every other key is re-emitted from the file's own
// bytes in the file's own order, so a command that owns one key cannot
// rewrite a setting it does not own. A nil value removes the key.
//
// It deliberately does not go through Load and Save. Save writes whatever
// differs from what Load resolved, so a flag or environment variable in force
// for the editing command could reach the file beside the key it meant to
// change.
func SetFileKey(key string, value any) (string, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		data = defaultConfigContent()
	case err != nil:
		return "", fmt.Errorf("read config %s: %w", path, err)
	}
	var check map[string]json.RawMessage
	if err := json.Unmarshal(data, &check); err != nil {
		return "", parseConfigError(path, err)
	}
	snap := newFileSnapshot(data)
	if snap.raw == nil {
		snap.raw = map[string]json.RawMessage{}
	}
	order := snap.order
	if value == nil {
		delete(snap.raw, key)
	} else {
		v, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("marshal config key %q: %w", key, err)
		}
		indented, err := indentValue(v)
		if err != nil {
			return "", fmt.Errorf("marshal config key %q: %w", key, err)
		}
		if _, ok := snap.raw[key]; !ok {
			order = append(order, key)
		}
		snap.raw[key] = indented
	}
	out, err := encodeOrdered(snap.raw, order, snap.spaced)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create config dir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return "", fmt.Errorf("write config %s: %w", path, err)
	}
	return path, nil
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
		delete(c.snapshot.cleared, k)
	}
}

// Clear marks config keys for removal, so the next Save deletes them from the
// file whatever the file and the Config say.
//
// A reset needs this and pinning cannot express it. Assigning a field its
// built-in default produces a diff of zero against a baseline that already
// resolved to that default, so `bodega --region us-west-2 shell` leaves an
// older region on disk; pinning the key instead writes the default in as a
// setting, which is the destructive save marshalForFile exists to prevent. An
// absent key already means "use the built-in default" everywhere else and
// survives a later change to what that default is.
//
// The struct tags cannot carry this either. Deleting on absence from the
// marshalled keys works only under omitempty, and omitempty on an int or a
// bool cannot tell a cleared key from an operator's deliberate 0 or false.
//
// One write: a successful Save discards the set, so a later save of a key the
// operator has since retyped writes it rather than dropping it again. Pin and
// Clear are contradictory instructions on one key, so the later call wins.
func (c *Config) Clear(keys ...string) {
	if c.snapshot == nil {
		return
	}
	if c.snapshot.cleared == nil {
		c.snapshot.cleared = make(map[string]bool, len(keys))
	}
	for _, k := range keys {
		c.snapshot.cleared[k] = true
		delete(c.snapshot.pinned, k)
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
		if err := validatePrefix(name, spec.Prefix); err != nil {
			return err
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

	for group, name := range c.StorageByGroup {
		switch {
		case group == "":
			return fmt.Errorf("invalid storage_by_group key: empty group name")
		case name == "":
			return fmt.Errorf("storage_by_group[%q]: empty backend name", group)
		case name == DefaultStorageName:
			continue
		}
		if _, ok := c.StorageBackends[name]; !ok {
			return fmt.Errorf("storage_by_group[%q] names undefined storage backend %q (defined: %s)", group, name, c.definedStorageNames())
		}
	}
	return nil
}

// validatePrefix refuses a storage prefix that names one location in more than
// one way, or that names a location outside the backend.
//
// Refused rather than normalized, and the two are separate decisions.
//
// Normalizing would be silent, and silence is wrong per driver: the local
// backend resolves "cold//x/k" through filepath.Join and stores it at
// "cold/x/k", but s3 stores the key it is handed, so "cold//x/k" and
// "cold/x/k" are two distinct objects in one bucket. Rewriting the prefix
// under an operator would move every object on one driver and orphan every
// object on the other. Refusing makes the operator write the spelling they
// meant, and it is what lets prefixed.Label() clean the prefix without
// claiming an s3 identity the bucket does not have.
//
// A traversal segment is a different question and gets its own refusal. The
// two spellings above are one directory under two names; "../x" is a prefix
// that leaves storage_path entirely. Every key through such a backend already
// fails storage.ValidateKey, so the backend is unusable rather than dangerous
// — but it fails at the first upload rather than at startup, which is the
// wrong end of the day to find out.
//
// A leading and a trailing "/" stay legal: withPrefix strips them, so they are
// spellings of the same prefix rather than of a different one.
func validatePrefix(name, prefix string) error {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(prefix, "/"), "/")
	if trimmed == "" {
		return nil
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return fmt.Errorf("storage_backends[%q]: prefix %q leaves the backend root; write it relative to the backend, with no %q segment", name, prefix, "..")
		}
	}
	cleaned := path.Clean("/" + trimmed)
	if cleaned == "/"+trimmed {
		return nil
	}
	want := strings.TrimPrefix(cleaned, "/")
	if want == "" {
		return fmt.Errorf("storage_backends[%q]: prefix %q names no location; remove it", name, prefix)
	}
	return fmt.Errorf("storage_backends[%q]: prefix %q is not canonical; write it as %q. Two spellings of one prefix are two backend identities, and 'bodega pkg move' between them deletes the only copy", name, prefix, want)
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
	data, changed, written, order, err := c.marshalForFile()
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
	if c.snapshot != nil {
		c.snapshot.cleared = nil
		// The snapshot becomes what is now on disk, so the next save answers
		// "what did this write change" rather than "what differs from the file
		// at startup". Without it every save after the first re-reports the
		// same keys, and the "nothing to save" line is unreachable for the rest
		// of the session once any key has moved.
		//
		// resolved stays where it is: it records what flags and environment
		// resolved to at startup, which a save does not change. pinned is
		// dropped because this write consumed those pins — a key Pin marked is
		// written whether or not it differs, and marking it again for the next
		// save would re-report it forever.
		if written != nil {
			c.snapshot.raw = written
			c.snapshot.order = order
		}
		c.snapshot.pinned = nil
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
func (c *Config) marshalForFile() ([]byte, []string, map[string]json.RawMessage, []string, error) {
	if c.snapshot == nil {
		data, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("marshal config: %w", err)
		}
		return append(data, '\n'), nil, nil, nil, nil
	}

	current, err := marshalKeys(c)
	if err != nil {
		return nil, nil, nil, nil, err
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
			return nil, nil, nil, nil, fmt.Errorf("marshal config key %q: %w", k, err)
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
	// Clear says so outright, for the keys omitempty cannot speak for.
	for k := range c.snapshot.cleared {
		delete(out, k)
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
			return nil, nil, nil, nil, fmt.Errorf("marshal config key %q: %w", replacement, err)
		}
		out[replacement] = indented
		order = append(order, replacement)
	}

	data, err := encodeOrdered(out, order, c.snapshot.spaced)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return data, changedKeys(c.snapshot.raw, out), out, order, nil
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
  "apt_root": "",
  "git_root": "",
  "pypi_root": "",
  "binary_root": "",

  "_comment_tls": "TLS: set both tls_cert and tls_key to serve HTTPS. Setting one without the other is an error. bodega has no ACME client; get certificates from certbot or terminate TLS at a proxy in front.",
  "tls_cert": "",
  "tls_key": "",

  "_comment_allow_plaintext": "allow_plaintext: authorize an unencrypted listener. With no cert pair bodega refuses to start unless this is true — set it for local use, or on a loopback listener behind a proxy that terminates TLS. --allow-plaintext=false overrides it back off.",
  "allow_plaintext": false,

  "_comment_listen": "listen_addr: address bodega serve binds; --addr and $BODEGA_LISTEN_ADDR override it",
  "listen_addr": ":8080",

  "_comment_proxy": "Proxy/cache: when enabled, the server fetches from upstream on cache miss",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "upstream_connect_timeout": "5s",
  "stale_grace": "3s",
  "gomod_upstream": "https://proxy.golang.org",
  "gomod_sumdb_url": "https://sum.golang.org",
  "npm_upstream": "https://registry.npmjs.org",
  "pypi_upstream": "https://pypi.org",

  "_comment_spool": "spool_dir: where a proxied upstream artifact is copied on its way to storage and the client. Empty means {storage_path}/tmp. bodega serve refuses to start if it cannot create the directory or write in it. spool_max_artifact_bytes caps one artifact; a declared Content-Length over it is refused before a byte moves, and an undeclared body is refused as it crosses. spool_max_total_bytes is the budget shared by every fetch in flight, and a request over it gets 503 with Retry-After rather than a queue. Write 0 in either to remove that ceiling.",
  "spool_dir": "",
  "spool_max_artifact_bytes": 8589934592,
  "spool_max_total_bytes": 34359738368,

  "_comment_cargo_upstream": "cargo_upstream is the sparse index; cargo_dl_upstream is the separate host the crate tarballs come from. crates.io names the second in its own config.json — bodega does not fetch that at startup, so an instance mirroring the index must name both keys.",
  "cargo_upstream": "https://index.crates.io",
  "cargo_dl_upstream": "https://static.crates.io/crates",
  "maven_upstreams": ["https://repo.maven.apache.org/maven2", "https://plugins.gradle.org/m2"],
  "rubygems_upstream": "https://rubygems.org",

  "_comment_composer": "composer_upstream is Packagist's metadata root, served under /composer/. Packagist serves metadata only, and each version's archive is fetched from the dist URL that metadata names, so composer_dist_hosts lists the hosts such a URL may name; a dist on any other host is refused with 403. A GitHub zipball is fetched from codeload.github.com, where the API redirects it. An empty list refuses every archive.",
  "composer_upstream": "https://repo.packagist.org",
  "composer_dist_hosts": ["api.github.com", "codeload.github.com", "gitlab.com", "bitbucket.org"],

  "_comment_oci": "oci_upstreams maps each registry a container client may name under /v2/ to the URL bodega pulls it from; a registry outside the map answers 404. A request names its registry with containerd's ?ns= parameter or as the first path segment (podman's mirror location), and anything else is Docker Hub. A URL may carry a credential as https://<user>:<token>@host, which bodega presents to the registry's token service as Basic auth and never to the registry itself. oci_token_hosts lists the hosts a registry's Bearer realm may name besides the registry's own; a realm anywhere else is refused with 502.",
  "oci_upstreams": {"docker.io": "https://registry-1.docker.io", "ghcr.io": "https://ghcr.io", "quay.io": "https://quay.io"},
  "oci_token_hosts": ["auth.docker.io", "ghcr.io", "quay.io"],

  "_comment_rpm": "rpm_upstreams maps a repository name you choose to the base URL of a dnf repository, served under /rpm/<name>/<releasever>/<basearch>/. The URL may carry $releasever and $basearch, which bodega fills from the request path; no other dnf variable is substituted. Empty serves no repository, and a name outside the map answers 404. bodega signs every repomd.xml it serves with the apt signing key (/rpm/bodega.gpg) and passes packages through byte for byte, so their vendor signatures still verify. e.g. {\"rocky-baseos\": \"https://dl.rockylinux.org/pub/rocky/$releasever/BaseOS/$basearch/os/\", \"epel\": \"https://dl.fedoraproject.org/pub/epel/$releasever/Everything/$basearch/\"}",
  "rpm_upstreams": {},

  "_comment_private_upstream_hosts": "private_upstream_hosts: hostnames or IP literals (no scheme, port or path) the upstream guard lets resolve to a private address (RFC 1918, fc00::/7), for fronting an internal registry such as Artifactory, Nexus or Verdaccio, e.g. [\"registry.corp.example\"]. Listing a host trusts it as a public upstream is trusted: any client that can reach bodega can make it fetch any path under that ecosystem's route from the host. Loopback, link-local (including 169.254.169.254) and unspecified addresses stay refused for every host, listed or not, and each redirect hop is judged again, so a listed host cannot hand the fetch to an unlisted one. Names, not CIDRs: a range would trust whatever a public upstream's DNS points into it.",
  "private_upstream_hosts": [],

  "_comment_git_upstreams": "git_upstreams: maps a namespace under /git/ onto an upstream forge, e.g. {\"internal\": {\"url\": \"https://git.corp.example/\", \"mode\": \"open\"}}. The key is a URL segment and a directory name: letters, digits, _ and -, starting with a letter, and folded to lower case before the reserved-name check so \"Repos\" is refused with \"repos\". The url must be https, end in \"/\", and carry no userinfo, no query, no fragment and no uncleaned path. A key may share a name with an uploaded git package: /git/{name}/{file} serves the bundle and /git/{ns}/{org}/{repo}.git/... resolves the upstream.",
  "_comment_git_upstreams_mode": "mode is \"catalog\" (default when absent or empty) or \"open\". catalog resolves only paths an existing manifest entry names; anything else 404s and is recorded as no_manifest for 'bodega discover promote'. open composes the upstream URL for any path under the namespace and fetches it, so on a public forge any client that can reach bodega can make bodega fetch arbitrary upstream repositories. Pick open for a forge whose publishing is already controlled.",
  "_comment_git_upstreams_auth": "Only public, unauthenticated upstreams are supported. No credential is read from this file or the environment, so a private forge answers bodega as an anonymous client and the request surfaces as a 404. A url carrying userinfo is refused at load rather than quietly used: it would land in discovery rows, logs and error messages.",
  "git_upstreams": {},

  "_comment_binary_upstreams": "binary_upstreams: maps a namespace under /binaries/ onto an upstream download host, e.g. {\"example-vendor\": {\"url\": \"https://downloads.example.com/\", \"mode\": \"open\"}}. Same key, url and mode rules as git_upstreams, enforced by the same validator. Binaries come from many vendors at once, which is why this is a map rather than one flat key.",
  "_comment_binary_upstreams_paths": "While this is empty, /binaries/{path...} serves from storage exactly as it always has. Once any entry exists, a request whose first segment names no key here 404s and is recorded as no_namespace instead of falling through to a storage read — including a path that used to resolve. Name a namespace for every tree you still serve locally, or leave the block empty.",
  "_comment_binary_upstreams_auth": "Only public, unauthenticated upstreams are supported. A namespace pointing at a private release endpoint fails as a 404 with no credential prompt, which looks identical to a typo in the path — check the upstream by hand before hunting the path.",
  "binary_upstreams": {},

  "_comment_osv": "osv_db_dir: where 'bodega policy osv sync' writes the OSV database, one archive per ecosystem. Empty means {storage_path}/osv. Admission matches against this directory and reaches no network. On an air-gapped host, sync where the network is, copy the directory over, and point this key at the copy. osv_api_fallback: authorize a live api.osv.dev query when the local copy cannot answer. Off by default — on a restricted network every version would otherwise stall for the client timeout against a host that never answers. osv_db_max_age: how old a synced ecosystem may be before a clean answer warns instead of passing; a Go duration, default 168h.",
  "osv_db_dir": "",
  "osv_api_fallback": false,
  "osv_db_max_age": "168h",

  "_comment_discover": "Discover mode: \"\" off, \"observe\" record every upstream request bodega could not answer from its own manifests. It changes no decision: the allow-list, catalog mode, version constraints and the ACLs enforce the same either way. See bodega discover --help.",
  "discover_mode": "",

  "gomod_root": "",
  "helm_root": "",
  "npm_root": "",
  "cargo_root": "",
  "rubygems_root": "",
  "composer_root": "",
  "oci_root": "",
  "rpm_root": "",

  "_comment_apt": "apt_codename: default suite for apt entries that name none. apt_suites: every suite served under /apt/dists/; apt_codename is always included.",
  "apt_codename": "noble",
  "apt_suites": ["noble"],

  "_comment_apt_upstreams": "apt_upstreams: codenames mirrored from an upstream archive instead of generated, e.g. {\"noble\": [{\"url\": \"https://archive.ubuntu.com/ubuntu\"}, {\"url\": \"https://security.ubuntu.com/ubuntu\"}]}. bodega proxies the upstream dists/ tree unchanged, signature included, so clients verify against the distro keyring they already have and need no [trusted=yes]. Empty means every codename is generated, which is what every install without this key does.",
  "_comment_apt_upstreams_disjoint": "A codename may not appear in both apt_suites and apt_upstreams — bodega signs one and forwards the other's signature, and a shared name would serve an index whose digests do not cover the packages beside it. A mirrored codename needs a name of its own.",
  "_comment_apt_upstreams_pool": "/apt/pool/ carries no codename, so a .deb is resolved by probing every configured archive in sorted order and remembering which one answered. There is no per-package allow-list for apt: constrain it with 'bodega policy add apt <host>'.",
  "apt_upstreams": {},

  "_comment_apt_signing": "apt_signing_name / apt_signing_email: the UID stamped on a key made by 'bodega apt key generate'. They name the key, nothing more — the server loads whatever key it finds and never generates one.",
  "apt_signing_name": "",
  "apt_signing_email": "",

  "_comment_policy": "Policy lives in the audit database, not in this file, so it changes on a running server. A fresh install is seeded with a minimum publish age of 7d on npm and pypi at action warn: a version published less than a week ago is admitted and flagged rather than refused. That cooldown is the control that catches a compromised release inside the window upstream withdraws it in. Checksum pinning cannot: it guarantees today's bytes match the first fetch, including a first fetch that was already malicious. Read it with 'bodega policy age list', harden it with 'bodega policy age set npm 7d block', drop it with 'bodega policy age remove npm'. A removal is final: bodega records that this install has decided the age gate, so no upgrade re-seeds it. An install upgraded from a release before this default gains nothing and keeps enforcing what it already enforced; 'bodega doctor' reports one that enforces nothing.",

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

// ResolveAttestationPlatformID returns the ingestionPlatform.id this instance
// signs under: attestation_platform_id, then the public URL, then
// "bodega://<hostname>". The last is a placeholder a verifier can still tell
// apart per host, for an install that has neither key set; a statement
// naming no platform at all would say nothing about where it was admitted.
func (c *Config) ResolveAttestationPlatformID() string {
	if id := firstNonEmpty(c.AttestationPlatformID, c.ResolvePublicURL("")); id != "" {
		return id
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	return "bodega://" + host
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

// DefaultManifestDir returns the built-in manifest directory, always absolute.
// It is what Load resolves when no config, environment variable or flag names
// one, so a caller clearing manifest_dir can keep the running process pointed
// at the directory the next Load will choose.
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
func DefaultManifestDir(storagePath string) string {
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
