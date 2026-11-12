package clientconf

import (
	"fmt"
	"maps"
	"slices"
	"time"
)

// containerdDuration is Duration in internal/tomlext at containerd v2.2.0: a
// duration written as a string, which time.ParseDuration reads. An integer
// is handed to the same parser and fails on its missing unit.
type containerdDuration time.Duration

func (d *containerdDuration) UnmarshalText(b []byte) error {
	x, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = containerdDuration(x)
	return nil
}

// The tables of the plugins below are the Config each registers at
// containerd v2.2.0, every field with its TOML tag and Go type. New
// (cmd/containerd/server/server.go, lines 307-312) decodes each one before
// the plugin starts and exits on a value of the wrong type, whichever plugin
// it belongs to.
type (
	// config in plugins/gc/scheduler.go.
	containerdGCConfig struct {
		PauseThreshold    float64            `toml:"pause_threshold"`
		DeletionThreshold int                `toml:"deletion_threshold"`
		MutationThreshold int                `toml:"mutation_threshold"`
		ScheduleDelay     containerdDuration `toml:"schedule_delay"`
		StartupDelay      containerdDuration `toml:"startup_delay"`
	}
	// Config in pkg/imageverifier/bindir/bindir.go.
	containerdVerifierConfig struct {
		BinDir             string             `toml:"bin_dir"`
		MaxVerifiers       int                `toml:"max_verifiers"`
		PerVerifierTimeout containerdDuration `toml:"per_verifier_timeout"`
	}
	// BoltConfig in plugins/metadata/plugin.go.
	containerdBoltConfig struct {
		ContentSharingPolicy string `toml:"content_sharing_policy"`
		NoSync               bool   `toml:"no_sync"`
	}
	// Config in internal/nri/config.go, with DefaultValidatorConfig of
	// github.com/containerd/nri v0.10.0, the version containerd v2.2.0 pins.
	containerdNRIConfig struct {
		Disable                   bool               `toml:"disable"`
		SocketPath                string             `toml:"socket_path"`
		PluginPath                string             `toml:"plugin_path"`
		PluginConfigPath          string             `toml:"plugin_config_path"`
		PluginRegistrationTimeout containerdDuration `toml:"plugin_registration_timeout"`
		PluginRequestTimeout      containerdDuration `toml:"plugin_request_timeout"`
		DisableConnections        bool               `toml:"disable_connections"`
		DefaultValidator          *struct {
			Enable                                bool     `toml:"enable"`
			RejectOCIHookAdjustment               bool     `toml:"reject_oci_hook_adjustment"`
			RejectRuntimeDefaultSeccompAdjustment bool     `toml:"reject_runtime_default_seccomp_adjustment"`
			RejectUnconfinedSeccompAdjustment     bool     `toml:"reject_unconfined_seccomp_adjustment"`
			RejectCustomSeccompAdjustment         bool     `toml:"reject_custom_seccomp_adjustment"`
			RejectNamespaceAdjustment             bool     `toml:"reject_namespace_adjustment"`
			RequiredPlugins                       []string `toml:"required_plugins"`
			TolerateMissingAnnotation             string   `toml:"tolerate_missing_plugins_annotation"`
		} `toml:"default_validator"`
	}
	// Config in plugins/restart/monitor.go.
	containerdRestartConfig struct {
		Interval containerdDuration `toml:"interval"`
	}
	// Config in core/metrics/cgroups/cgroups.go.
	containerdCgroupsConfig struct {
		NoPrometheus bool `toml:"no_prometheus"`
	}
	// TaskConfig in core/runtime/v2/task_manager.go.
	containerdTaskConfig struct {
		Platforms []string `toml:"platforms"`
	}
	// ShimConfig in core/runtime/v2/shim_manager.go.
	containerdShimConfig struct {
		Env []string `toml:"env"`
	}
	// config in plugins/services/diff/local.go.
	containerdDiffServiceConfig struct {
		Order  []string `toml:"default"`
		SyncFs bool     `toml:"sync_fs"`
	}
	// Config in plugins/services/tasks/local.go.
	containerdTasksServiceConfig struct {
		BlockIOConfigFile string `toml:"blockio_config_file"`
		RdtConfigFile     string `toml:"rdt_config_file"`
	}
	// Config in plugins/services/opt/service.go.
	containerdOptConfig struct {
		Path string `toml:"path"`
	}
	// TraceConfig and OTLPConfig in pkg/tracing/plugin/otlp.go.
	containerdTraceConfig struct {
		ServiceName        string  `toml:"service_name"`
		TraceSamplingRatio float64 `toml:"sampling_ratio"`
	}
	containerdOTLPConfig struct {
		Endpoint string `toml:"endpoint"`
		Protocol string `toml:"protocol"`
		Insecure bool   `toml:"insecure"`
	}
	// transferConfig in plugins/transfer/plugin.go.
	containerdTransferConfig struct {
		MaxConcurrentDownloads      int  `toml:"max_concurrent_downloads"`
		ConcurrentLayerFetchBuffer  int  `toml:"concurrent_layer_fetch_buffer"`
		MaxConcurrentUploadedLayers int  `toml:"max_concurrent_uploaded_layers"`
		CheckPlatformSupported      bool `toml:"check_platform_supported"`
		UnpackConfiguration         []struct {
			Platform    string   `toml:"platform"`
			Snapshotter string   `toml:"snapshotter"`
			Differ      string   `toml:"differ"`
			ConfigType  string   `toml:"config_type"`
			LayerTypes  []string `toml:"layer_types"`
		} `toml:"unpack_config"`
		RegistryConfigPath   string `toml:"config_path"`
		MaxConcurrentUnpacks int    `toml:"max_concurrent_unpacks"`
	}
	// Config in plugins/diff/erofs/plugin/plugin.go.
	containerdErofsDiffConfig struct {
		MkfsOptions    []string `toml:"mkfs_options"`
		EnableTarIndex bool     `toml:"enable_tar_index"`
	}
	// Config in plugins/mount/erofs/plugin_linux.go holds no field.
	containerdErofsMountConfig struct{}
	// Config of the btrfs and native snapshotters, and of
	// github.com/containerd/zfs/v2 v2.0.0-rc.0.
	containerdRootPathConfig struct {
		RootPath string `toml:"root_path"`
	}
	// Config in plugins/snapshots/blockfile/plugin/plugin.go.
	containerdBlockfileConfig struct {
		RootPath        string   `toml:"root_path"`
		ScratchFile     string   `toml:"scratch_file"`
		FSType          string   `toml:"fs_type"`
		MountOptions    []string `toml:"mount_options"`
		RecreateScratch bool     `toml:"recreate_scratch"`
	}
	// Config in plugins/snapshots/devmapper/config.go.
	containerdDevmapperConfig struct {
		RootPath       string `toml:"root_path"`
		PoolName       string `toml:"pool_name"`
		BaseImageSize  string `toml:"base_image_size"`
		AsyncRemove    bool   `toml:"async_remove"`
		DiscardBlocks  bool   `toml:"discard_blocks"`
		FileSystemType string `toml:"fs_type"`
		FsOptions      string `toml:"fs_options"`
	}
	// Config in plugins/snapshots/erofs/plugin/plugin.go.
	containerdErofsConfig struct {
		RootPath       string   `toml:"root_path"`
		OvlOptions     []string `toml:"ovl_mount_options"`
		EnableFsverity bool     `toml:"enable_fsverity"`
		SetImmutable   bool     `toml:"set_immutable"`
		DefaultSize    string   `toml:"default_size"`
	}
	// Config in plugins/snapshots/overlay/plugin/plugin.go.
	containerdOverlayConfig struct {
		RootPath      string   `toml:"root_path"`
		UpperdirLabel bool     `toml:"upperdir_label"`
		SyncRemove    bool     `toml:"sync_remove"`
		SlowChown     bool     `toml:"slow_chown"`
		MountOptions  []string `toml:"mount_options"`
	}
)

func containerdTable[T any]() any { return new(T) }

// containerdPlugins is every plugin the containerd v2.2.0 Linux release
// registers, by URI: the builtins of cmd/containerd/builtins with no build
// tag set to leave one out, which is the list `ctr plugins ls` prints against
// that release. The value makes the Config the plugin registers, nil for a
// plugin that registers none and so decodes no table. The three CRI plugins
// are nil too: containerdCRI decodes and validates theirs.
//
// A table under any other name is one no plugin decodes, and containerd
// starts whatever it holds.
var containerdPlugins = map[string]func() any{
	"io.containerd.content.v1.content":                  nil,
	"io.containerd.cri.v1.images":                       nil,
	"io.containerd.cri.v1.runtime":                      nil,
	"io.containerd.differ.v1.erofs":                     containerdTable[containerdErofsDiffConfig],
	"io.containerd.differ.v1.walking":                   nil,
	"io.containerd.event.v1.exchange":                   nil,
	"io.containerd.gc.v1.scheduler":                     containerdTable[containerdGCConfig],
	"io.containerd.grpc.v1.containers":                  nil,
	"io.containerd.grpc.v1.content":                     nil,
	"io.containerd.grpc.v1.cri":                         nil,
	"io.containerd.grpc.v1.diff":                        nil,
	"io.containerd.grpc.v1.events":                      nil,
	"io.containerd.grpc.v1.healthcheck":                 nil,
	"io.containerd.grpc.v1.images":                      nil,
	"io.containerd.grpc.v1.introspection":               nil,
	"io.containerd.grpc.v1.leases":                      nil,
	"io.containerd.grpc.v1.mounts":                      nil,
	"io.containerd.grpc.v1.namespaces":                  nil,
	"io.containerd.grpc.v1.sandbox-controllers":         nil,
	"io.containerd.grpc.v1.sandboxes":                   nil,
	"io.containerd.grpc.v1.snapshots":                   nil,
	"io.containerd.grpc.v1.streaming":                   nil,
	"io.containerd.grpc.v1.tasks":                       nil,
	"io.containerd.grpc.v1.transfer":                    nil,
	"io.containerd.grpc.v1.version":                     nil,
	"io.containerd.image-verifier.v1.bindir":            containerdTable[containerdVerifierConfig],
	"io.containerd.internal.v1.opt":                     containerdTable[containerdOptConfig],
	"io.containerd.internal.v1.tracing":                 containerdTable[containerdTraceConfig],
	"io.containerd.lease.v1.manager":                    nil,
	"io.containerd.metadata.v1.bolt":                    containerdTable[containerdBoltConfig],
	"io.containerd.monitor.container.v1.restart":        containerdTable[containerdRestartConfig],
	"io.containerd.monitor.task.v1.cgroups":             containerdTable[containerdCgroupsConfig],
	"io.containerd.mount-handler.v1.erofs":              containerdTable[containerdErofsMountConfig],
	"io.containerd.mount-manager.v1.bolt":               nil,
	"io.containerd.nri.v1.nri":                          containerdTable[containerdNRIConfig],
	"io.containerd.podsandbox.controller.v1.podsandbox": nil,
	"io.containerd.runtime.v2.task":                     containerdTable[containerdTaskConfig],
	"io.containerd.sandbox.controller.v1.shim":          nil,
	"io.containerd.sandbox.store.v1.local":              nil,
	"io.containerd.service.v1.containers-service":       nil,
	"io.containerd.service.v1.content-service":          nil,
	"io.containerd.service.v1.diff-service":             containerdTable[containerdDiffServiceConfig],
	"io.containerd.service.v1.images-service":           nil,
	"io.containerd.service.v1.introspection-service":    nil,
	"io.containerd.service.v1.namespaces-service":       nil,
	"io.containerd.service.v1.snapshots-service":        nil,
	"io.containerd.service.v1.tasks-service":            containerdTable[containerdTasksServiceConfig],
	"io.containerd.shim.v1.manager":                     containerdTable[containerdShimConfig],
	"io.containerd.snapshotter.v1.blockfile":            containerdTable[containerdBlockfileConfig],
	"io.containerd.snapshotter.v1.btrfs":                containerdTable[containerdRootPathConfig],
	"io.containerd.snapshotter.v1.devmapper":            containerdTable[containerdDevmapperConfig],
	"io.containerd.snapshotter.v1.erofs":                containerdTable[containerdErofsConfig],
	"io.containerd.snapshotter.v1.native":               containerdTable[containerdRootPathConfig],
	"io.containerd.snapshotter.v1.overlayfs":            containerdTable[containerdOverlayConfig],
	"io.containerd.snapshotter.v1.zfs":                  containerdTable[containerdRootPathConfig],
	"io.containerd.streaming.v1.manager":                nil,
	"io.containerd.tracing.processor.v1.otlp":           containerdTable[containerdOTLPConfig],
	"io.containerd.transfer.v1.local":                   containerdTable[containerdTransferConfig],
	"io.containerd.ttrpc.v1.otelttrpc":                  nil,
	"io.containerd.warning.v1.deprecations":             nil,
}

// containerdProxyTypes is the switch in LoadPlugins
// (cmd/containerd/server/server.go, lines 507-530): the type a proxy_plugins
// entry may name, by URI or short name, and the plugin type it registers as.
var containerdProxyTypes = map[string]string{
	"io.containerd.snapshotter.v1": "io.containerd.snapshotter.v1", "snapshot": "io.containerd.snapshotter.v1",
	"io.containerd.content.v1": "io.containerd.content.v1", "content": "io.containerd.content.v1",
	"io.containerd.sandbox.controller.v1": "io.containerd.sandbox.controller.v1", "sandbox": "io.containerd.sandbox.controller.v1",
	"io.containerd.differ.v1": "io.containerd.differ.v1", "diff": "io.containerd.differ.v1",
}

// containerdStart is what New in cmd/containerd/server/server.go at
// containerd v2.2.0 reads of config.toml before it serves anything, outside
// the CRI plugins' own tables: the timeouts it parses, the TLS pair of the
// TCP listener, the proxy plugins it registers, the table every registered
// plugin decodes, and required_plugins. New returns an error or panics on
// each, and containerd exits; no hosts.toml is read then, whatever the CRI
// tables say.
//
// Like containerdCRI it is filled one file at a time, since New runs on what
// config.toml and its imports add up to: mergeConfig lets an import's
// timeouts and proxy_plugins replace the main file's by key.
type containerdStart struct {
	timeouts map[string]string
	proxies  map[string]containerdProxyPlugin
	tlsCert  string
	tlsCName string
	// tables is the first decode error of each registered plugin's table, by
	// plugin URI. It is judged once the files are all loaded, because New
	// decodes no table of a plugin disabled_plugins names.
	tables map[string]error
}

// containerdPluginURI is the plugin a table named name in a config.toml of
// format version belongs to once containerd v2.2.0 has migrated the file:
// v1Migrate gives a version 1 short name its URI, and the cgroups and restart
// plugins take the table their earlier names held (core/metrics/cgroups/
// cgroups.go, lines 51-64; plugins/restart/monitor.go, lines 66-78).
func containerdPluginURI(name string, version int) string {
	if version == 1 {
		name = containerdV1PluginName(name)
	}
	if version < 3 {
		switch name {
		case "io.containerd.monitor.v1.cgroups":
			return "io.containerd.monitor.task.v1.cgroups"
		case "io.containerd.internal.v1.restart":
			return "io.containerd.monitor.container.v1.restart"
		}
	}
	return name
}

// load adds one config.toml of format version to what earlier files left.
// Every table a registered plugin could be handed is decoded for its types,
// under each name the migrations read it from: where two names in a file of
// an earlier format reach one plugin, containerd keeps one of them, and both
// are held to the plugin's types here rather than guessing which.
func (s *containerdStart) load(data []byte, version int) error {
	cfg, err := decodeContainerdConfig(data)
	if err != nil {
		return err
	}
	if s.timeouts == nil {
		s.timeouts, s.proxies, s.tables = map[string]string{}, map[string]containerdProxyPlugin{}, map[string]error{}
	}
	maps.Copy(s.timeouts, cfg.Timeouts)
	maps.Copy(s.proxies, cfg.ProxyPlugins)
	if cfg.GRPC.TCPTLSCert != "" {
		s.tlsCert = cfg.GRPC.TCPTLSCert
	}
	if cfg.GRPC.TCPTLSCName != "" {
		s.tlsCName = cfg.GRPC.TCPTLSCName
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Plugins)) {
		uri := containerdPluginURI(name, version)
		table := containerdPlugins[uri]
		if table == nil || s.tables[uri] != nil {
			continue
		}
		if err := decodeContainerdPlugin(data, name, table()); err != nil {
			s.tables[uri] = err
		}
	}
	return nil
}

// invalid is why containerd does not start on what the loaded files add up
// to, or why doctor cannot say it does; "" for neither. disabled and required
// are the composed disabled_plugins and required_plugins, by URI.
func (s *containerdStart) invalid(disabled, required []string) string {
	for _, key := range slices.Sorted(maps.Keys(s.timeouts)) {
		if _, err := time.ParseDuration(s.timeouts[key]); err != nil {
			return fmt.Sprintf("timeouts sets %s = %q, and containerd does not start: unable to parse %s into a time duration", key, s.timeouts[key], s.timeouts[key])
		}
	}
	switch {
	case s.tlsCert != "":
		return fmt.Sprintf("[grpc] sets tcp_tls_cert = %q, a certificate and key containerd loads before it starts and exits without, which doctor does not interpret", s.tlsCert)
	case s.tlsCName != "":
		return fmt.Sprintf("[grpc] sets tcp_tls_common_name = %q, which containerd reads a Windows certificate store for before it starts, and doctor does not interpret", s.tlsCName)
	}
	proxies := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(s.proxies)) {
		typ, ok := containerdProxyTypes[s.proxies[name].Type]
		switch {
		case !ok:
			return fmt.Sprintf("proxy_plugins.%s has type %q, which containerd has no proxy for, and it panics registering the plugin: no type for plugin", name, s.proxies[name].Type)
		case name == "":
			return "proxy_plugins holds an entry with an empty name, and containerd panics registering it: no plugin id"
		}
		uri := typ + "." + name
		if _, builtin := containerdPlugins[uri]; builtin {
			return fmt.Sprintf("proxy_plugins.%s takes the name of a plugin containerd already holds, and it panics registering the plugin: %s: plugin id already registered", name, uri)
		}
		proxies[uri] = true
	}
	for _, uri := range slices.Sorted(maps.Keys(s.tables)) {
		if !slices.Contains(disabled, uri) {
			return fmt.Sprintf("plugin %s does not decode its table, and containerd does not start: %v", uri, s.tables[uri])
		}
	}
	for _, uri := range required {
		_, builtin := containerdPlugins[uri]
		switch {
		case !builtin && !proxies[uri]:
			return fmt.Sprintf("required plugin [%s] not included: containerd v2.2.0 registers no plugin of that name, and does not start", uri)
		case uri == containerdCRIPlugin || uri == containerdImagesPlugin || uri == containerdRuntimePlugin || slices.Contains(disabled, uri):
			// The CRI plugins start on the tables containerdCRI validates, and
			// a plugin both required and disabled is containerdPluginState's.
		default:
			return fmt.Sprintf("required_plugins names %s, and containerd exits unless that plugin initializes, which depends on this host and doctor does not follow", uri)
		}
	}
	return ""
}
