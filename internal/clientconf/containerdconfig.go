package clientconf

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	toml "github.com/ravinald/bodega/internal/clientconf/internal/gotoml224"
)

// containerdServerConfig is Config in cmd/containerd/server/config/config.go
// at containerd v2.2.0, with the structs it holds: every field with its TOML
// tag and Go type. Fields doctor never reads are here because containerd
// refuses to start over a wrong type in any of them, and then nothing reads
// the registry configuration config_path names.
//
// Plugins stays untyped, as it is there: each plugin decodes its own table
// when it starts, after the file has loaded.
type containerdServerConfig struct {
	Version          int                                  `toml:"version"`
	Root             string                               `toml:"root"`
	State            string                               `toml:"state"`
	TempDir          string                               `toml:"temp"`
	GRPC             containerdGRPCConfig                 `toml:"grpc"`
	TTRPC            containerdTTRPCConfig                `toml:"ttrpc"`
	Debug            containerdDebug                      `toml:"debug"`
	Metrics          containerdMetricsConfig              `toml:"metrics"`
	DisabledPlugins  []string                             `toml:"disabled_plugins"`
	RequiredPlugins  []string                             `toml:"required_plugins"`
	Plugins          map[string]any                       `toml:"plugins"`
	OOMScore         int                                  `toml:"oom_score"`
	Cgroup           containerdCgroupConfig               `toml:"cgroup"`
	ProxyPlugins     map[string]containerdProxyPlugin     `toml:"proxy_plugins"`
	Timeouts         map[string]string                    `toml:"timeouts"`
	Imports          []string                             `toml:"imports"`
	StreamProcessors map[string]containerdStreamProcessor `toml:"stream_processors"`
}

type containerdStreamProcessor struct {
	Accepts []string `toml:"accepts"`
	Returns string   `toml:"returns"`
	Path    string   `toml:"path"`
	Args    []string `toml:"args"`
	Env     []string `toml:"env"`
}

type containerdGRPCConfig struct {
	Address        string `toml:"address"`
	TCPAddress     string `toml:"tcp_address"`
	TCPTLSCA       string `toml:"tcp_tls_ca"`
	TCPTLSCert     string `toml:"tcp_tls_cert"`
	TCPTLSKey      string `toml:"tcp_tls_key"`
	UID            int    `toml:"uid"`
	GID            int    `toml:"gid"`
	MaxRecvMsgSize int    `toml:"max_recv_message_size"`
	MaxSendMsgSize int    `toml:"max_send_message_size"`
	TCPTLSCName    string `toml:"tcp_tls_common_name"`
}

type containerdTTRPCConfig struct {
	Address string `toml:"address"`
	UID     int    `toml:"uid"`
	GID     int    `toml:"gid"`
}

type containerdDebug struct {
	Address string `toml:"address"`
	UID     int    `toml:"uid"`
	GID     int    `toml:"gid"`
	Level   string `toml:"level"`
	Format  string `toml:"format"`
}

type containerdMetricsConfig struct {
	Address       string `toml:"address"`
	GRPCHistogram bool   `toml:"grpc_histogram"`
}

type containerdCgroupConfig struct {
	Path string `toml:"path"`
}

type containerdProxyPlugin struct {
	Type         string            `toml:"type"`
	Address      string            `toml:"address"`
	Platform     string            `toml:"platform"`
	Exports      map[string]string `toml:"exports"`
	Capabilities []string          `toml:"capabilities"`
}

// decodeContainerdConfig is loadConfigFile there: go-toml v2.2.4 fills the
// struct, and a key the struct does not know is a warning in containerd's log
// rather than an error, so it is none here. The error carries the row and
// column containerd prints.
func decodeContainerdConfig(data []byte) (*containerdServerConfig, error) {
	cfg := new(containerdServerConfig)
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, tomlPlaced(err)
	}
	return cfg, nil
}

// tomlPlaced adds the row and column of a go-toml decode error, as
// containerd's loadConfigFile does.
func tomlPlaced(err error) error {
	var derr *toml.DecodeError
	if errors.As(err, &derr) {
		row, column := derr.Position()
		return fmt.Errorf("failed to unmarshal TOML at row %d column %d: %w", row, column, err)
	}
	return fmt.Errorf("failed to unmarshal TOML: %w", err)
}

// containerdDefaultServerConfig is what the containerd v2.2.0 command starts
// from before it loads any file: platformAgnosticDefaultConfig
// (cmd/containerd/command/config.go, lines 128-143), which is what
// `containerd config default` prints of these keys on Linux. Timeouts holds
// what the plugins of the Linux release register with the timeout package,
// which a [timeouts] entry replaces by key and that command prints too.
func containerdDefaultServerConfig() *containerdServerConfig {
	const keys = "--decryption-keys-path"
	decoder := func(accepts, returns string) containerdStreamProcessor {
		return containerdStreamProcessor{
			Accepts: []string{accepts}, Returns: returns, Path: "ctd-decoder",
			Args: []string{keys, "/etc/containerd/ocicrypt/keys"},
			Env:  []string{"OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf"},
		}
	}
	const tar = "application/vnd.oci.image.layer.v1.tar"
	return &containerdServerConfig{
		Version: 3,
		Root:    "/var/lib/containerd",
		State:   "/run/containerd",
		GRPC:    containerdGRPCConfig{Address: "/run/containerd/containerd.sock", MaxRecvMsgSize: 16 << 20, MaxSendMsgSize: 16 << 20},
		Imports: []string{"/etc/containerd/conf.d/*.toml"},
		StreamProcessors: map[string]containerdStreamProcessor{
			"io.containerd.ocicrypt.decoder.v1.tar":      decoder(tar+"+encrypted", tar),
			"io.containerd.ocicrypt.decoder.v1.tar.gzip": decoder(tar+"+gzip+encrypted", tar+"+gzip"),
		},
		ProxyPlugins: map[string]containerdProxyPlugin{},
		Timeouts: map[string]string{
			"io.containerd.timeout.bolt.open":         "0s",
			"io.containerd.timeout.cri.defercleanup":  "1m0s",
			"io.containerd.timeout.metrics.shimstats": "2s",
			"io.containerd.timeout.shim.cleanup":      "5s",
			"io.containerd.timeout.shim.load":         "5s",
			"io.containerd.timeout.shim.shutdown":     "3s",
			"io.containerd.timeout.task.state":        "2s",
		},
	}
}

// containerdMerge is mergeConfig (cmd/containerd/server/config/config.go,
// lines 417-449) for the keys of the daemon itself: a value a file sets
// replaces the one before it unless it is the zero value, and an entry of
// stream_processors, proxy_plugins or timeouts replaces the entry of that
// name whole. The command merges every file this way, the main one included,
// over its defaults, so a key set to "" or 0 is a key left out.
//
// The lists and the plugin tables are not merged here: ResolveContainerdConfig
// adds up disabled_plugins, required_plugins and imports, and each plugin
// table is decoded over the one before it.
func containerdMerge(to, from reflect.Value) {
	for i := range to.NumField() {
		t, f := to.Field(i), from.Field(i)
		switch f.Kind() {
		case reflect.Struct:
			containerdMerge(t, f)
		case reflect.Map:
			if f.Type().Elem().Kind() == reflect.Interface {
				continue
			}
			for _, key := range f.MapKeys() {
				t.SetMapIndex(key, f.MapIndex(key))
			}
		case reflect.Slice:
		default:
			if !f.IsZero() {
				t.Set(f)
			}
		}
	}
}

// validatePluginURIs is the plugin half of ValidateVersion: a file past
// format version 1 names each plugin by its full URI. A version 1 name is
// migrated to one before this runs there, so only a file declaring version 2
// or later is held to it.
func (c *containerdServerConfig) validatePluginURIs() error {
	for _, p := range c.DisabledPlugins {
		if !strings.ContainsAny(p, ".") {
			return fmt.Errorf("invalid disabled plugin URI %q expect io.containerd.x.vx", p)
		}
	}
	for _, p := range c.RequiredPlugins {
		if !strings.ContainsAny(p, ".") {
			return fmt.Errorf("invalid required plugin URI %q expect io.containerd.x.vx", p)
		}
	}
	return nil
}

// containerdImageConfig is ImageConfig in internal/cri/config/config.go at
// containerd v2.2.0, with the structs it holds: the table the CRI image
// plugin decodes for itself once config.toml has loaded.
type containerdImageConfig struct {
	Snapshotter                string            `toml:"snapshotter"`
	DisableSnapshotAnnotations bool              `toml:"disable_snapshot_annotations"`
	DiscardUnpackedLayers      bool              `toml:"discard_unpacked_layers"`
	PinnedImages               map[string]string `toml:"pinned_images"`
	RuntimePlatforms           map[string]struct {
		Platform    string `toml:"platform"`
		Snapshotter string `toml:"snapshotter"`
	} `toml:"runtime_platforms"`
	Registry                   containerdImageRegistry   `toml:"registry"`
	ImageDecryption            containerdImageDecryption `toml:"image_decryption"`
	MaxConcurrentDownloads     int                       `toml:"max_concurrent_downloads"`
	ConcurrentLayerFetchBuffer int                       `toml:"concurrent_layer_fetch_buffer"`
	ImagePullProgressTimeout   string                    `toml:"image_pull_progress_timeout"`
	ImagePullWithSyncFs        bool                      `toml:"image_pull_with_sync_fs"`
	StatsCollectPeriod         int                       `toml:"stats_collect_period"`
	UseLocalImagePull          bool                      `toml:"use_local_image_pull"`
}

type containerdImageRegistry struct {
	ConfigPath string `toml:"config_path"`
	Mirrors    map[string]struct {
		Endpoints []string `toml:"endpoint"`
	} `toml:"mirrors"`
	Configs map[string]struct {
		Auth *containerdAuthConfig `toml:"auth"`
	} `toml:"configs"`
	Auths   map[string]containerdAuthConfig `toml:"auths"`
	Headers map[string][]string             `toml:"headers"`
}

type containerdImageDecryption struct {
	KeyModel string `toml:"key_model"`
}

type containerdAuthConfig struct {
	Username      string `toml:"username"`
	Password      string `toml:"password"`
	Auth          string `toml:"auth"`
	IdentityToken string `toml:"identitytoken"`
}

// validate is the part of ValidateImageConfig that can fail. mirrors beside
// config_path, which it also refuses, is reported apart, as
// ContainerdRegistry.Legacy.
func (c *containerdImageConfig) validate() error {
	for endpoint := range c.Registry.Auths {
		if _, err := url.Parse(endpoint); err != nil {
			return fmt.Errorf("failed to parse registry url %q from `registry.auths`: %w", endpoint, err)
		}
	}
	if c.ImagePullProgressTimeout != "" {
		if _, err := time.ParseDuration(c.ImagePullProgressTimeout); err != nil {
			return fmt.Errorf("invalid image pull progress timeout: %w", err)
		}
	}
	return nil
}

// containerdRuntimeConfig is RuntimeConfig in the same file, with the structs
// it holds: the table the CRI runtime plugin decodes. The CRI service needs
// that plugin and the image plugin both (initCRIService in
// plugins/cri/cri.go), so a runtime table that does not decode leaves
// containerd serving no CRI pull, whatever the registry table says.
type containerdRuntimeConfig struct {
	Containerd struct {
		DefaultRuntimeName            string                       `toml:"default_runtime_name"`
		Runtimes                      map[string]containerdRuntime `toml:"runtimes"`
		IgnoreBlockIONotEnabledErrors bool                         `toml:"ignore_blockio_not_enabled_errors"`
		IgnoreRdtNotEnabledErrors     bool                         `toml:"ignore_rdt_not_enabled_errors"`
	} `toml:"containerd"`
	Cni struct {
		BinDir        string   `toml:"bin_dir"`
		BinDirs       []string `toml:"bin_dirs"`
		ConfDir       string   `toml:"conf_dir"`
		MaxConfNum    int      `toml:"max_conf_num"`
		SetupSerially bool     `toml:"setup_serially"`
		ConfTemplate  string   `toml:"conf_template"`
		IPPreference  string   `toml:"ip_pref"`
		UseLoopback   bool     `toml:"use_internal_loopback"`
	} `toml:"cni"`
	EnableSelinux                      bool     `toml:"enable_selinux"`
	SelinuxCategoryRange               int      `toml:"selinux_category_range"`
	MaxContainerLogLineSize            int      `toml:"max_container_log_line_size"`
	DisableApparmor                    bool     `toml:"disable_apparmor"`
	RestrictOOMScoreAdj                bool     `toml:"restrict_oom_score_adj"`
	DisableProcMount                   bool     `toml:"disable_proc_mount"`
	UnsetSeccompProfile                string   `toml:"unset_seccomp_profile"`
	TolerateMissingHugetlbController   bool     `toml:"tolerate_missing_hugetlb_controller"`
	DisableHugetlbController           bool     `toml:"disable_hugetlb_controller"`
	DeviceOwnershipFromSecurityContext bool     `toml:"device_ownership_from_security_context"`
	IgnoreImageDefinedVolumes          bool     `toml:"ignore_image_defined_volumes"`
	NetNSMountsUnderStateDir           bool     `toml:"netns_mounts_under_state_dir"`
	EnableUnprivilegedPorts            bool     `toml:"enable_unprivileged_ports"`
	EnableUnprivilegedICMP             bool     `toml:"enable_unprivileged_icmp"`
	EnableCDI                          bool     `toml:"enable_cdi"`
	CDISpecDirs                        []string `toml:"cdi_spec_dirs"`
	DrainExecSyncIOTimeout             string   `toml:"drain_exec_sync_io_timeout"`
	IgnoreDeprecationWarnings          []string `toml:"ignore_deprecation_warnings"`
}

type containerdRuntime struct {
	Type                                          string         `toml:"runtime_type"`
	Path                                          string         `toml:"runtime_path"`
	PodAnnotations                                []string       `toml:"pod_annotations"`
	ContainerAnnotations                          []string       `toml:"container_annotations"`
	Options                                       map[string]any `toml:"options"`
	PrivilegedWithoutHostDevices                  bool           `toml:"privileged_without_host_devices"`
	PrivilegedWithoutHostDevicesAllDevicesAllowed bool           `toml:"privileged_without_host_devices_all_devices_allowed"`
	CgroupWritable                                bool           `toml:"cgroup_writable"`
	BaseRuntimeSpec                               string         `toml:"base_runtime_spec"`
	NetworkPluginConfDir                          string         `toml:"cni_conf_dir"`
	NetworkPluginMaxConfNum                       int            `toml:"cni_max_conf_num"`
	Snapshotter                                   string         `toml:"snapshotter"`
	Sandboxer                                     string         `toml:"sandboxer"`
	IOType                                        string         `toml:"io_type"`
}

// validate is ValidateRuntimeConfig, less what only the host can answer. Two
// settings containerd checks against the host are refused as not interpreted:
// cgroup_writable, which it accepts only under cgroup v2, and
// base_runtime_spec, a file initCRIRuntime loads and stops on. The kernel
// version behind enable_unprivileged_ports is not checked: it is on by
// default and 4.11 is older than any kernel containerd 2.x is packaged for.
//
// It reads the table every loaded file added up to: default_runtime_name and
// the runtime it names can sit in different files.
func (c *containerdRuntimeConfig) validate() error {
	name := c.Containerd.DefaultRuntimeName
	if name == "" {
		return errors.New("`default_runtime_name` is empty")
	}
	if _, ok := c.Containerd.Runtimes[name]; !ok {
		return fmt.Errorf("no corresponding runtime configured in `containerd.runtimes` for `containerd` `default_runtime_name = \"%s\"", name)
	}
	names := make([]string, 0, len(c.Containerd.Runtimes))
	for name := range c.Containerd.Runtimes {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		r := c.Containerd.Runtimes[name]
		switch {
		case r.CgroupWritable:
			return fmt.Errorf("runtime %s sets cgroup_writable, which containerd accepts only on a host under cgroup v2 and doctor does not interpret", name)
		case !r.PrivilegedWithoutHostDevices && r.PrivilegedWithoutHostDevicesAllDevicesAllowed:
			return errors.New("`privileged_without_host_devices_all_devices_allowed` requires `privileged_without_host_devices` to be enabled")
		case r.IOType != "" && r.IOType != "streaming" && r.IOType != "fifo":
			return errors.New("`io_type` can only be `streaming` or `named_pipe`")
		case r.BaseRuntimeSpec != "":
			return fmt.Errorf("runtime %s sets base_runtime_spec, a file containerd loads as the plugin starts and doctor does not interpret", name)
		}
	}
	if c.DrainExecSyncIOTimeout != "" {
		if _, err := time.ParseDuration(c.DrainExecSyncIOTimeout); err != nil {
			return fmt.Errorf("invalid `drain_exec_sync_io_timeout`: %w", err)
		}
	}
	return nil
}

// containerdCRIServerConfig is ServerConfig in the same file: the table the
// CRI plugin itself decodes, which is the stream server's.
type containerdCRIServerConfig struct {
	DisableTCPService   bool   `toml:"disable_tcp_service"`
	StreamServerAddress string `toml:"stream_server_address"`
	StreamServerPort    string `toml:"stream_server_port"`
	StreamIdleTimeout   string `toml:"stream_idle_timeout"`
	EnableTLSStreaming  bool   `toml:"enable_tls_streaming"`
	X509KeyPair         struct {
		TLSCertFile string `toml:"tls_cert_file"`
		TLSKeyFile  string `toml:"tls_key_file"`
	} `toml:"x509_key_pair_streaming"`
}

// validate is ValidateServerConfig and the configuration half of
// StreamingConfig (internal/cri/config/streaming.go), which initCRIService
// runs before it serves anything: the idle timeout, and which of
// tls_cert_file and tls_key_file may be set. A pair named whole is one
// containerd loads from disk, which doctor does not.
func (c *containerdCRIServerConfig) validate() error {
	if c.StreamIdleTimeout != "" {
		if _, err := time.ParseDuration(c.StreamIdleTimeout); err != nil {
			return fmt.Errorf("invalid stream idle timeout: %w", err)
		}
	}
	cert, key := c.X509KeyPair.TLSCertFile != "", c.X509KeyPair.TLSKeyFile != ""
	switch {
	case c.EnableTLSStreaming && cert && key:
		return errors.New("x509_key_pair_streaming names a certificate and key containerd loads as the CRI plugin starts, which doctor does not interpret")
	case c.EnableTLSStreaming && cert:
		return errors.New("invalid stream server configuration: must set X509KeyPairStreaming.TLSKeyFile")
	case c.EnableTLSStreaming && key:
		return errors.New("invalid stream server configuration: must set X509KeyPairStreaming.TLSCertFile")
	case !c.EnableTLSStreaming && cert:
		return errors.New("invalid stream server configuration: X509KeyPairStreaming.TLSCertFile is set but EnableTLSStreaming is not set")
	case !c.EnableTLSStreaming && key:
		return errors.New("invalid stream server configuration: X509KeyPairStreaming.TLSKeyFile is set but EnableTLSStreaming is not set")
	}
	return nil
}

// containerdLegacyCRI holds the keys of a version 1 or 2 CRI table that
// containerd v2.2.0 moves under another name or asserts a type on while it
// migrates the table to version 3, each with the type the migration or its
// destination needs: sandbox_image becomes a pinned image, the three
// snapshot keys of [containerd] and the six top-level image keys go to the
// image plugin (configMigration in plugins/cri/images/plugin.go, lines
// 166-264), sandbox_mode becomes a runtime's sandboxer and cni.bin_dir its
// bin_dirs (plugins/cri/runtime/plugin.go, lines 197-306). The migrations
// assert containerd, runtimes and each runtime to be tables and bin_dir a
// string, and panic on anything else.
type containerdLegacyCRI struct {
	SandboxImage             string                    `toml:"sandbox_image"`
	Registry                 containerdImageRegistry   `toml:"registry"`
	ImageDecryption          containerdImageDecryption `toml:"image_decryption"`
	MaxConcurrentDownloads   int                       `toml:"max_concurrent_downloads"`
	ImagePullProgressTimeout string                    `toml:"image_pull_progress_timeout"`
	ImagePullWithSyncFs      bool                      `toml:"image_pull_with_sync_fs"`
	StatsCollectPeriod       int                       `toml:"stats_collect_period"`
	Containerd               struct {
		// Snapshotter is a pointer because the migration moves the key when
		// the table holds it, "" included.
		Snapshotter                *string `toml:"snapshotter"`
		DisableSnapshotAnnotations *bool   `toml:"disable_snapshot_annotations"`
		DiscardUnpackedLayers      *bool   `toml:"discard_unpacked_layers"`
		Runtimes                   map[string]struct {
			SandboxMode string `toml:"sandbox_mode"`
		} `toml:"runtimes"`
	} `toml:"containerd"`
	Cni struct {
		// BinDir is a pointer for the same reason: the migration turns the
		// key into bin_dirs when the table holds it.
		BinDir *string `toml:"bin_dir"`
	} `toml:"cni"`
}

// The plugin ids config.toml names the CRI's tables by. A version 3 file
// holds one table per plugin; versions 1 and 2 hold one table for all three,
// under the id the CRI plugin keeps.
const (
	containerdCRIPlugin     = "io.containerd.grpc.v1.cri"
	containerdImagesPlugin  = "io.containerd.cri.v1.images"
	containerdRuntimePlugin = "io.containerd.cri.v1.runtime"
)

// decodeContainerdPlugin decodes the table config.toml holds for the plugin
// id into the struct into points at, over what that struct already holds, as
// Config.Decode does (cmd/containerd/server/config/config.go, lines 257-286):
// a key the struct does not know is a warning there and nothing here, and a
// value of the wrong type is the error. The table is decoded where it stands
// in the file, by the same go-toml v2.2.4, in place of containerd's marshal
// and decode of the generic table.
func decodeContainerdPlugin(data []byte, id string, into any) error {
	target := reflect.ValueOf(into).Elem()
	plugins := reflect.StructOf([]reflect.StructField{{Name: "Table", Type: target.Type(), Tag: reflect.StructTag("toml:" + strconv.Quote(id))}})
	doc := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "Plugins", Type: plugins, Tag: `toml:"plugins"`}}))
	doc.Elem().Field(0).Field(0).Set(target)
	if err := toml.Unmarshal(data, doc.Interface()); err != nil {
		return tomlPlaced(err)
	}
	target.Set(doc.Elem().Field(0).Field(0))
	return nil
}

// containerdCRI is the configuration containerd v2.2.0's three CRI plugins
// start on: images, which reads the registry configuration, runtime, and the
// CRI plugin that needs both. containerd logs a plugin's failure and goes on
// without it, so no hosts.toml under config_path is read.
//
// It is filled one file at a time, main file first and then each import in
// the order containerd loads them, because containerd validates what the
// files add up to and not each file: mergeConfig
// (cmd/containerd/server/config/config.go, lines 429-449) merges an import's
// plugin tables into the main file's key by key, the import's value winning,
// and each plugin decodes and validates its table after that. Decoding every
// file over the same structs gives the same result for every key they hold.
//
// A version 3 file names each plugin's table. An older one is migrated first:
// version 1 names the CRI table "cri", which v1Migrate renames, and the
// plugins' own migrations then move its keys into the three tables. Those
// keys are decoded where the file has them, with the types their destinations
// have. legacy is the name the file's version gives the table.
type containerdCRI struct {
	version int
	legacy  string
	moved   containerdLegacyCRI
	images  containerdImageConfig
	runtime containerdRuntimeConfig
	server  containerdCRIServerConfig
	// start is the rest of what containerd reads before it serves anything.
	start containerdStart
}

func newContainerdCRI(version int, legacy string) *containerdCRI {
	c := &containerdCRI{version: version, legacy: legacy}
	c.images, c.runtime, c.server = containerdCRIDefaults()
	c.start = containerdStart{top: containerdDefaultServerConfig(), tables: map[string]error{}, values: map[string]any{}}
	// A version 1 or 2 table holds these two under their version 3 names, and
	// the image plugin's migration moves them only when the table has them.
	c.moved.MaxConcurrentDownloads, c.moved.StatsCollectPeriod = c.images.MaxConcurrentDownloads, c.images.StatsCollectPeriod
	return c
}

// containerdCRIDefaults is what the three CRI plugins register as Config on
// Linux at containerd v2.2.0, for every key unmodeled compares:
// DefaultImageConfig and DefaultRuntimeConfig
// (internal/cri/config/config_unix.go) and DefaultServerConfig
// (internal/cri/config/config.go, lines 779-791). A key containerdModeled
// names is left at its zero value where no reader here needs the default.
func containerdCRIDefaults() (images containerdImageConfig, runtime containerdRuntimeConfig, server containerdCRIServerConfig) {
	images.Snapshotter = containerdDefaultSnapshotter
	images.DisableSnapshotAnnotations = true
	images.MaxConcurrentDownloads = 3
	images.StatsCollectPeriod = 10

	runtime.Containerd.DefaultRuntimeName = "runc"
	runtime.Containerd.Runtimes = map[string]containerdRuntime{"runc": {Type: "io.containerd.runc.v2"}}
	runtime.Cni.BinDirs = []string{"/opt/cni/bin"}
	runtime.Cni.ConfDir = "/etc/cni/net.d"
	runtime.Cni.MaxConfNum = 1
	runtime.CDISpecDirs = []string{"/etc/cdi", "/var/run/cdi"}

	server.DisableTCPService = true
	server.StreamServerAddress = "127.0.0.1"
	server.StreamServerPort = "0"
	server.StreamIdleTimeout = "4h0m0s"
	return images, runtime, server
}

const containerdDefaultSnapshotter = "overlayfs"

func containerdPluginFailed(plugin string, err error) error {
	return fmt.Errorf("the CRI %s, without which containerd serves no CRI pull, does not start on its table: %w", plugin, err)
}

// load decodes the CRI tables of one config.toml over what earlier files
// left. The error is a value of the wrong type, which no later file repairs.
func (c *containerdCRI) load(data []byte) error {
	imagesTable, runtimeTable, serverTable := containerdImagesPlugin, containerdRuntimePlugin, containerdCRIPlugin
	if c.version < 3 {
		imagesTable, runtimeTable, serverTable = "", c.legacy, c.legacy
		if err := decodeContainerdPlugin(data, c.legacy, &c.moved); err != nil {
			return fmt.Errorf("containerd's CRI plugins do not start on what it migrates its version %d CRI table into: %w", c.version, err)
		}
	}
	if imagesTable != "" {
		if err := decodeContainerdPlugin(data, imagesTable, &c.images); err != nil {
			return containerdPluginFailed("image plugin", err)
		}
	}
	if err := decodeContainerdPlugin(data, runtimeTable, &c.runtime); err != nil {
		return containerdPluginFailed("runtime plugin", err)
	}
	if err := decodeContainerdPlugin(data, serverTable, &c.server); err != nil {
		return containerdPluginFailed("plugin", err)
	}
	return c.start.load(data, c.version)
}

// pluginState is containerdPluginState for the composed disabled_plugins and
// required_plugins, and after it what containerdStart refuses: New's own
// checks run on every plugin, not only those disabled_plugins names.
func (c *containerdCRI) pluginState(disabled, required []string) (criDisabled bool, invalid string) {
	criDisabled, invalid = containerdPluginState(disabled, required)
	if invalid == "" {
		invalid = c.start.invalid(disabled, required)
	}
	if invalid == "" && !slices.Contains(disabled, containerdImagesPlugin) {
		if err := c.imagesInit(disabled); err != nil {
			invalid = containerdStartFailure("the CRI image plugin", err)
		}
	}
	if invalid == "" {
		invalid = c.unmodeled(disabled, criDisabled)
	}
	return criDisabled, invalid
}

// containerdModeled is the one list of keys in a composed containerd
// configuration whose every value the port follows from the command's start
// to the point containerd serves its first CRI request, by table: "" is the
// daemon's own keys, with a section's keys under its name, and every other
// name is a plugin's URI. A "*" stands for any name of a table.
//
// Every key the composed configuration holds that is not here is followed at
// one value only, the one containerd v2.2.0 starts with when no file sets it,
// and unmodeled refuses any other. That covers the keys startup acts on with
// this host's state or with code nothing here ports: the listeners the
// command opens (cmd/containerd/command/main.go, lines 245-284), the
// directories, OOM score and cgroup it sets up, the stream server's listener,
// the CNI and CDI directories, a snapshotter's root.
//
// A key is here on one of four grounds, each read from containerd v2.2.0:
//
//   - the port composes or validates it as containerd does: version,
//     imports and the two plugin lists, which ResolveContainerdConfig and
//     containerdPluginState follow; debug.level and debug.format, which
//     command refuses as applyFlags does; a proxy plugin's type, which
//     invalid refuses as LoadPlugins panics on it, and its address, which
//     getClient hands to a client that dials nothing until a request; the
//     keys the validators and initError methods above read;
//   - startup reads it and no value fails: initPlatform
//     (internal/cri/server/service_linux.go) warns on the selinux and oom
//     keys, skips CDI when enable_cdi is off, and introspectRuntimeHandler
//     (internal/cri/server/service.go) logs and drops any error a runtime's
//     type, path or options produce;
//   - nothing reads it before a request arrives: its only readers are the
//     sandbox, container, exec, status and pull handlers;
//   - its plugin is one nothing the CRI service starts through requires, and
//     no value of it stops containerd: the opt plugin's InitFn
//     (plugins/services/opt/service.go, lines 42-61) returns every failure
//     as an error, which New logs and passes over for a plugin
//     required_plugins does not name (cmd/containerd/server/server.go, lines
//     320-336), and the restart monitor sleeps for whatever interval it is
//     given (plugins/restart/monitor.go, lines 90-100). invalid refuses
//     either plugin under required_plugins.
//
// "plugins" is the table of tables, each walked under its own name.
var containerdModeled = map[string][]string{
	"": {
		"version", "imports", "disabled_plugins", "required_plugins", "plugins",
		"debug.level", "debug.format",
		"proxy_plugins.*.type", "proxy_plugins.*.address",
	},
	containerdCRIPlugin: {"disable_tcp_service", "stream_idle_timeout"},
	containerdImagesPlugin: {
		"snapshotter", "registry", "runtime_platforms", "pinned_images", "image_decryption",
		"image_pull_progress_timeout", "concurrent_layer_fetch_buffer",
	},
	containerdRuntimePlugin: {
		"containerd.default_runtime_name", "containerd.ignore_blockio_not_enabled_errors", "containerd.ignore_rdt_not_enabled_errors",
		"containerd.runtimes.*.runtime_type", "containerd.runtimes.*.runtime_path",
		"containerd.runtimes.*.pod_annotations", "containerd.runtimes.*.container_annotations",
		"containerd.runtimes.*.options", "containerd.runtimes.*.sandboxer", "containerd.runtimes.*.io_type",
		"containerd.runtimes.*.privileged_without_host_devices",
		"containerd.runtimes.*.privileged_without_host_devices_all_devices_allowed",
		"cni.setup_serially", "cni.conf_template", "cni.ip_pref",
		"enable_selinux", "selinux_category_range", "max_container_log_line_size", "disable_apparmor",
		"restrict_oom_score_adj", "disable_proc_mount", "unset_seccomp_profile",
		"tolerate_missing_hugetlb_controller", "disable_hugetlb_controller",
		"device_ownership_from_security_context", "ignore_image_defined_volumes", "netns_mounts_under_state_dir",
		"enable_unprivileged_ports", "enable_unprivileged_icmp", "enable_cdi",
		"drain_exec_sync_io_timeout", "ignore_deprecation_warnings",
	},
	"io.containerd.internal.v1.opt":              {"path"},
	"io.containerd.metadata.v1.bolt":             {"content_sharing_policy"},
	"io.containerd.monitor.container.v1.restart": {"interval"},
	"io.containerd.runtime.v2.task":              {"platforms"},
	"io.containerd.service.v1.diff-service":      {"default"},
	"io.containerd.transfer.v1.local":            {"unpack_config"},
}

// containerdFollowedKey reports whether followed names the key at path.
func containerdFollowedKey(path, followed []string) bool {
	return slices.ContainsFunc(followed, func(pattern string) bool {
		names := strings.Split(pattern, ".")
		if len(names) != len(path) {
			return false
		}
		for i, name := range names {
			if name != "*" && name != path[i] {
				return false
			}
		}
		return true
	})
}

// containerdFollowsUnder reports whether followed names a key below path.
func containerdFollowsUnder(path, followed []string) bool {
	return slices.ContainsFunc(followed, func(pattern string) bool {
		names := strings.Split(pattern, ".")
		return len(names) > len(path) && containerdFollowedKey(path, []string{strings.Join(names[:len(path)], ".")})
	})
}

// containerdOffDefault is the path of the first key under got that followed
// does not name and that holds something other than want holds, or nil. A
// table of named entries is compared entry by entry. An entry want lacks is
// off by being there, unless followed names keys of such an entry: then it is
// compared against the empty one a file starts it from.
func containerdOffDefault(got, want reflect.Value, path, followed []string) []string {
	if containerdFollowedKey(path, followed) {
		return nil
	}
	under := func(name string) []string { return append(slices.Clone(path), name) }
	switch {
	case got.Kind() == reflect.Struct:
		for i := range got.NumField() {
			if off := containerdOffDefault(got.Field(i), want.Field(i), under(got.Type().Field(i).Tag.Get("toml")), followed); off != nil {
				return off
			}
		}
		return nil
	case got.Kind() == reflect.Map && got.Type().Elem().Kind() != reflect.Interface:
		names := map[string]bool{}
		for _, key := range got.MapKeys() {
			names[key.String()] = true
		}
		for _, key := range want.MapKeys() {
			names[key.String()] = true
		}
		for _, name := range slices.Sorted(maps.Keys(names)) {
			key := reflect.ValueOf(name)
			entry, registered := got.MapIndex(key), want.MapIndex(key)
			if !entry.IsValid() {
				return under(name)
			}
			if !registered.IsValid() {
				if !containerdFollowsUnder(under(name), followed) {
					return under(name)
				}
				registered = reflect.Zero(got.Type().Elem())
			}
			if off := containerdOffDefault(entry, registered, under(name), followed); off != nil {
				return off
			}
		}
		return nil
	case got.Kind() == reflect.Map:
		if !reflect.DeepEqual(got.Interface(), want.Interface()) {
			return path
		}
		return nil
	}
	if !containerdSameValue(got, want) {
		return path
	}
	return nil
}

// containerdTable is one table of the composed configuration: what the
// loaded files add up to in it, and what containerd v2.2.0 starts with when
// no file names it. name is its key in containerdModeled.
type containerdTable struct {
	name      string
	got, want any
}

// document is every table of the composed configuration containerd acts on
// before it serves a CRI pull, read once every file has loaded and a version
// 1 or 2 CRI table has been migrated: the daemon's own keys, the three CRI
// plugins' tables, and the table of every registered plugin a file holds one
// for.
//
// A disabled plugin decodes no table, one its own table makes containerd
// skip reads nothing past the key that skips it, and a table under a name no
// plugin registers is decoded by nothing. The CRI plugins' tables are read by
// nothing either once disabled_plugins takes the CRI service out.
func (c *containerdCRI) document(disabled []string, criDisabled bool) []containerdTable {
	// New turns each timeout into a duration before anything reads it, so two
	// spellings of one duration are one value. invalid has refused any that
	// does not parse.
	canonical := func(timeouts map[string]string) map[string]string {
		out := make(map[string]string, len(timeouts))
		for key, value := range timeouts {
			if d, err := time.ParseDuration(value); err == nil {
				value = d.String()
			}
			out[key] = value
		}
		return out
	}
	top, wantTop := *c.start.top, containerdDefaultServerConfig()
	top.Timeouts, wantTop.Timeouts = canonical(top.Timeouts), canonical(wantTop.Timeouts)
	tables := []containerdTable{{"", &top, wantTop}}
	if !criDisabled {
		runtime := c.runtime
		if dir := c.moved.Cni.BinDir; c.version < 3 && dir != nil {
			// migrateConfig in plugins/cri/runtime/plugin.go, lines 248-262:
			// bin_dir becomes bin_dirs and is not carried over under its own name.
			runtime.Cni.BinDir, runtime.Cni.BinDirs = "", []string{*dir}
		}
		images, server := c.imagesConfig(), c.server
		wantImages, wantRuntime, wantServer := containerdCRIDefaults()
		tables = append(tables,
			containerdTable{containerdCRIPlugin, &server, &wantServer},
			containerdTable{containerdRuntimePlugin, &runtime, &wantRuntime},
			containerdTable{containerdImagesPlugin, &images, &wantImages})
	}
	for _, uri := range slices.Sorted(maps.Keys(c.start.values)) {
		if skipped, _ := c.start.skip(uri); skipped != "" || slices.Contains(disabled, uri) {
			continue
		}
		tables = append(tables, containerdTable{uri, c.start.values[uri], containerdPlugins[uri]()})
	}
	return tables
}

// unmodeled is the first key of the composed configuration that holds a
// value the port does not follow, as the reason doctor cannot say containerd
// serves a CRI pull; "" when every key of every table in document holds what
// containerd v2.2.0 starts with or is one containerdModeled names. It is the
// bound on what every check here certifies: they follow named keys, and this
// one walk refuses the rest instead of passing them, the daemon's own keys
// and each plugin's alike.
func (c *containerdCRI) unmodeled(disabled []string, criDisabled bool) string {
	for _, table := range c.document(disabled, criDisabled) {
		off := containerdOffDefault(reflect.ValueOf(table.got).Elem(), reflect.ValueOf(table.want).Elem(), nil, containerdModeled[table.name])
		if off == nil {
			continue
		}
		where, key := fmt.Sprintf("[plugins.%q]", table.name), strings.Join(off, ".")
		switch cri := table.name == containerdCRIPlugin || table.name == containerdRuntimePlugin || table.name == containerdImagesPlugin; {
		case table.name == "" && len(off) > 1:
			where, key = "["+off[0]+"]", strings.Join(off[1:], ".")
		case table.name == "":
			where = "config.toml"
		case cri && c.version < 3:
			// The file holds one table for all three plugins, under its own
			// names for some of these keys.
			where = fmt.Sprintf("[plugins.%q], in the table containerd migrates to %s,", c.legacy, table.name)
		}
		return fmt.Sprintf("%s sets %s to a value other than the one containerd v2.2.0 starts with by default: containerd acts on that key before it serves, with this host's state and code doctor does not follow, so whether it serves a CRI pull on that value is unknown", where, key)
	}
	return ""
}

// imagesConfig is the table the image plugin decodes once every file has
// loaded: its own in a version 3 file, and what its migration builds in an
// older one.
func (c *containerdCRI) imagesConfig() containerdImageConfig {
	if c.version >= 3 {
		return c.images
	}
	// The image plugin's migration takes six keys by name and leaves the
	// rest of the table to the runtime plugin. It moves [containerd]'s
	// snapshotter only past a return it takes when that table holds no
	// runtimes (migrateConfig in plugins/cri/images/plugin.go, lines 225-262).
	m := c.moved
	images, _, _ := containerdCRIDefaults()
	images.Registry, images.ImageDecryption = m.Registry, m.ImageDecryption
	images.MaxConcurrentDownloads, images.StatsCollectPeriod = m.MaxConcurrentDownloads, m.StatsCollectPeriod
	images.ImagePullProgressTimeout, images.ImagePullWithSyncFs = m.ImagePullProgressTimeout, m.ImagePullWithSyncFs
	if m.Containerd.Runtimes == nil {
		return images
	}
	if m.Containerd.Snapshotter != nil {
		images.Snapshotter = *m.Containerd.Snapshotter
	}
	if m.Containerd.DisableSnapshotAnnotations != nil {
		images.DisableSnapshotAnnotations = *m.Containerd.DisableSnapshotAnnotations
	}
	if m.Containerd.DiscardUnpackedLayers != nil {
		images.DiscardUnpackedLayers = *m.Containerd.DiscardUnpackedLayers
	}
	return images
}

// imagesInit is what the image plugin's InitFn refuses in its table past
// ValidateImageConfig (plugins/cri/images/plugin.go, lines 106-143): a
// snapshotter that is not among those the metadata plugin collected, and a
// runtime platform that does not parse. initCRIService stops without the
// image plugin, so no hosts.toml is read.
func (c *containerdCRI) imagesInit(disabled []string) error {
	images := c.imagesConfig()
	if err := c.start.named("io.containerd.snapshotter.v1", images.Snapshotter, disabled); err != nil {
		return fmt.Errorf("failed to find snapshotter %q: %w", images.Snapshotter, err)
	}
	for _, name := range slices.Sorted(maps.Keys(images.RuntimePlatforms)) {
		if p := images.RuntimePlatforms[name].Platform; p != "" {
			if err := containerdPlatformError(p); err != nil {
				return fmt.Errorf("unable to parse platform %q: %w", p, err)
			}
		}
	}
	return nil
}

// validate is what the three plugins refuse in the tables every loaded file
// added up to: ValidateImageConfig, ValidateRuntimeConfig and
// ValidateServerConfig. It runs once, after the last file.
func (c *containerdCRI) validate() error {
	images := c.imagesConfig()
	if err := images.validate(); err != nil {
		return containerdPluginFailed("image plugin", fmt.Errorf("invalid cri image config: %w", err))
	}
	if err := c.runtime.validate(); err != nil {
		return containerdPluginFailed("runtime plugin", fmt.Errorf("invalid plugin config: %w", err))
	}
	if err := c.server.validate(); err != nil {
		return containerdPluginFailed("plugin", err)
	}
	return nil
}

// containerdV1Plugins is corePlugins in v1MigratePluginName
// (cmd/containerd/server/config/config.go, lines 148-187): the short names a
// version 1 file gives plugins, and the URIs containerd 2.x reads them as.
var containerdV1Plugins = map[string]string{
	"cri":       "io.containerd.grpc.v1.cri",
	"cgroups":   "io.containerd.monitor.v1.cgroups",
	"linux":     "io.containerd.runtime.v1.linux",
	"scheduler": "io.containerd.gc.v1.scheduler",
	"bolt":      "io.containerd.metadata.v1.bolt",
	"task":      "io.containerd.runtime.v2.task",
	"opt":       "io.containerd.internal.v1.opt",
	"restart":   "io.containerd.internal.v1.restart",
	"tracing":   "io.containerd.internal.v1.tracing",
	"otlp":      "io.containerd.tracing.processor.v1.otlp",
	"aufs":      "io.containerd.snapshotter.v1.aufs",
	"btrfs":     "io.containerd.snapshotter.v1.btrfs",
	"devmapper": "io.containerd.snapshotter.v1.devmapper",
	"native":    "io.containerd.snapshotter.v1.native",
	"overlayfs": "io.containerd.snapshotter.v1.overlayfs",
	"zfs":       "io.containerd.snapshotter.v1.zfs",
}

// containerdV1PluginName is v1MigratePluginName: the URI of a plugin a
// version 1 file names without one.
func containerdV1PluginName(name string) string {
	if strings.Contains(name, ".") {
		return name
	}
	if full, ok := containerdV1Plugins[name]; ok {
		return full
	}
	switch {
	case strings.HasSuffix(name, "-service"):
		return "io.containerd.service.v1." + name
	case name == "windows" || name == "windows-lcow":
		return "io.containerd.snapshotter.v1." + name
	}
	return "io.containerd.grpc.v1." + name
}

// containerdOutsideCRI are the plugin types no plugin the CRI service starts
// through requires, at containerd v2.2.0: following Requires from the CRI
// plugin's registration (plugins/cri/cri.go, lines 46-60) through the image
// and runtime plugins, the transfer, metadata, snapshot and service plugins
// and the task service (plugins/services/tasks/local.go, lines 67-72)
// reaches none of them. A disabled plugin of one of these types leaves the
// CRI service as it was. The CRI plugin is itself a gRPC plugin and is told
// apart by its URI.
var containerdOutsideCRI = []string{
	"io.containerd.grpc.v1.",
	"io.containerd.ttrpc.v1.",
	"io.containerd.http.v1.",
	"io.containerd.internal.v1.",
	"io.containerd.streaming.v1.",
	"io.containerd.runtime.v1.",
	"io.containerd.monitor.container.v1.",
	"io.containerd.tracing.processor.v1.",
}

// containerdPluginState reads disabled_plugins and required_plugins, as every
// loaded file adds them up and by URI, for what they do to the CRI service.
//
// criDisabled is a disabled plugin that reads the registry configuration:
// the CRI plugin, or its image plugin. invalid is why containerd does not
// start, the CRI plugin does not, or doctor cannot say it does: the runtime
// plugin, which initCRIService fetches before it serves anything and stops
// without (plugins/cri/cri.go, lines 71-75); a plugin both required and
// disabled, on which New exits with "required plugin not included"
// (cmd/containerd/server/server.go, lines 260-356); or a disabled plugin of a
// type the CRI service's requirements reach, where whether the service
// starts without it depends on which plugin of that type each requirement
// takes, which doctor does not follow.
func containerdPluginState(disabled, required []string) (criDisabled bool, invalid string) {
	for _, p := range disabled {
		switch {
		// "cri" is the CRI plugin as a version 1 file names it. A later
		// format refuses the bare name, and the plugin is what its author
		// meant to disable.
		case p == "cri" || p == containerdCRIPlugin || p == containerdImagesPlugin:
			criDisabled = true
		case p == containerdRuntimePlugin:
			if invalid == "" {
				invalid = fmt.Sprintf("disabled_plugins names %s, and the CRI plugin, which reads the registry configuration, does not start without it: unable to load CRI runtime service plugin dependency", p)
			}
		case slices.Contains(required, p):
			if invalid == "" {
				invalid = fmt.Sprintf("required plugin %s not included: disabled_plugins names it too", p)
			}
		case !slices.ContainsFunc(containerdOutsideCRI, func(prefix string) bool { return strings.HasPrefix(p, prefix) }):
			if invalid == "" {
				invalid = fmt.Sprintf("disabled_plugins names %s, a plugin of a type containerd's CRI service requires, and doctor does not follow whether the service starts without it", p)
			}
		}
	}
	return criDisabled, invalid
}
