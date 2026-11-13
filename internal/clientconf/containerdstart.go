package clientconf

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
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

// containerdInit is the part of a plugin's InitFn at containerd v2.2.0 that
// its decoded table decides alone, whatever the host: an enumeration, a
// platform or size it parses, a plugin it looks up by a configured name. The
// rest of each InitFn (a directory, a mount, a socket) is the host's.
//
// Only plugins the CRI service starts through carry one. GetSingle and
// GetByType (github.com/containerd/plugin v1.0.0, context.go) hand a
// dependent the error of any plugin of the type it asks for, so one failing
// snapshotter fails the metadata plugin, and with it the image plugin.
//
// An error that is a containerdHostError says the host decides, and anything
// else that containerd fails on the configuration alone.
type containerdInit interface {
	initError(s *containerdStart, disabled []string) error
}

// The metadata plugin's InitFn (plugins/metadata/plugin.go, lines 112-146):
// the one content store, the snapshotters that loaded, and then
// BoltConfig.Validate (lines 84-91), which it skips for "".
func (c *containerdBoltConfig) initError(s *containerdStart, disabled []string) error {
	if err := s.single("io.containerd.content.v1", disabled); err != nil {
		return err
	}
	if err := s.collect("io.containerd.snapshotter.v1", disabled); err != nil {
		return err
	}
	switch c.ContentSharingPolicy {
	case "", "shared", "isolated":
		return nil
	}
	return fmt.Errorf("unknown policy: %s: invalid argument", c.ContentSharingPolicy)
}

// platforms.ParseAll in the task manager's InitFn (core/runtime/v2/
// task_manager.go, lines 73-77).
func (c *containerdTaskConfig) initError(*containerdStart, []string) error {
	for _, p := range c.Platforms {
		if err := containerdPlatformError(p); err != nil {
			return fmt.Errorf("invalid platform %s: %w", p, err)
		}
	}
	return nil
}

// The diff service's InitFn (plugins/services/diff/local.go, lines 66-86)
// takes each differ `default` names from those that loaded.
func (c *containerdDiffServiceConfig) initError(s *containerdStart, disabled []string) error {
	if err := s.collect("io.containerd.differ.v1", disabled); err != nil {
		return err
	}
	for _, name := range c.Order {
		if err := s.named("io.containerd.differ.v1", name, disabled); err != nil {
			return fmt.Errorf("needed differ not loaded: %s: %w", name, err)
		}
	}
	return nil
}

// The transfer plugin's InitFn (plugins/transfer/plugin.go, lines 94-170)
// for each unpack_config entry: the platform it parses, the snapshotter it
// takes from those the metadata plugin collected, and the differ it looks up
// by name, where GetByID hands it a skipped differ's error. Whether a differ
// matches the platform when none is named is the host's.
func (c *containerdTransferConfig) initError(s *containerdStart, disabled []string) error {
	for _, uc := range c.UnpackConfiguration {
		if containerdPlatformError(uc.Platform) != nil {
			return fmt.Errorf("io.containerd.transfer.v1: platform configuration %v invalid", uc.Platform)
		}
		if err := s.named("io.containerd.snapshotter.v1", uc.Snapshotter, disabled); err != nil {
			return fmt.Errorf("snapshotter %q not found: %w", uc.Snapshotter, err)
		}
		if uc.Differ == "" {
			continue
		}
		if err := s.named("io.containerd.differ.v1", uc.Differ, disabled); err != nil {
			return fmt.Errorf("failed to get instance for diff plugin %q: %w", uc.Differ, err)
		}
	}
	return nil
}

// Config.parse and Config.Validate (plugins/snapshots/devmapper/config.go),
// which NewSnapshotter runs first. With no pool_name the plugin is skipped
// and reads nothing, which skip reports and is no failure of its own;
// root_path is filled before either runs.
func (c *containerdDevmapperConfig) initError(*containerdStart, []string) error {
	if c.PoolName == "" {
		return nil
	}
	if err := containerdRAMSizeError(c.BaseImageSize); err != nil {
		return fmt.Errorf("failed to parse base image size: '%s': %w", c.BaseImageSize, err)
	}
	switch c.FileSystemType {
	case "", "ext4", "xfs", "ext2":
		return nil
	}
	return fmt.Errorf("unsupported Filesystem Type: %q", c.FileSystemType)
}

// The erofs snapshotter's InitFn (plugins/snapshots/erofs/plugin/plugin.go)
// parses default_size when it is set.
func (c *containerdErofsConfig) initError(*containerdStart, []string) error {
	if c.DefaultSize == "" {
		return nil
	}
	if err := containerdRAMSizeError(c.DefaultSize); err != nil {
		return fmt.Errorf("failed to parse default_size '%v': %w", c.DefaultSize, err)
	}
	return nil
}

var (
	containerdPlatformPart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	containerdPlatformOS   = regexp.MustCompile(`^([A-Za-z0-9_-]+)(?:\(([A-Za-z0-9_.-]*)\))?$`)
	containerdKnownOS      = strings.Fields("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris windows zos")
	containerdKnownArch    = strings.Fields("386 amd64 amd64p32 arm armbe arm64 arm64be ppc64 ppc64le loong64 mips mipsle mips64 mips64le mips64p32 mips64p32le ppc riscv riscv64 s390 s390x sparc sparc64 wasm")
	containerdArchAliases  = map[string]string{"i386": "386", "x86_64": "amd64", "x86-64": "amd64", "aarch64": "arm64", "armhf": "arm", "armel": "arm"}
)

// containerdPlatformError is why Parse in github.com/containerd/platforms
// v1.0.0-rc.2 (platforms.go), the version containerd v2.2.0 pins, refuses a
// platform specifier; nil when it parses. Only the refusals are ported: what
// a specifier parses into depends on the host, whether it parses does not.
func containerdPlatformError(specifier string) error {
	if strings.Contains(specifier, "*") {
		return fmt.Errorf("%q: wildcards not yet supported: invalid argument", specifier)
	}
	parts := strings.SplitN(specifier, "/", 4)
	for i, part := range parts {
		switch {
		case i == 0 && !containerdPlatformOS.MatchString(part):
			return fmt.Errorf("%q is an invalid OS component of %q: OSAndVersion specifier component must match %q: invalid argument", part, specifier, containerdPlatformOS.String())
		case i > 0 && !containerdPlatformPart.MatchString(part):
			return fmt.Errorf("%q is an invalid component of %q: platform specifier component must match %q: invalid argument", part, specifier, containerdPlatformPart.String())
		}
	}
	switch len(parts) {
	case 1:
		// A lone component is an operating system Parse knows, "macos" among
		// them, or an architecture it knows under any of its aliases.
		os := strings.ToLower(containerdPlatformOS.FindStringSubmatch(parts[0])[1])
		arch := strings.ToLower(parts[0])
		if alias, ok := containerdArchAliases[arch]; ok {
			arch = alias
		}
		if os == "macos" || slices.Contains(containerdKnownOS, os) || slices.Contains(containerdKnownArch, arch) {
			return nil
		}
		return fmt.Errorf("%q: unknown operating system or architecture: invalid argument", specifier)
	case 2, 3:
		return nil
	}
	return fmt.Errorf("%q: cannot parse platform specifier: invalid argument", specifier)
}

// containerdRAMSizeError is why RAMInBytes in github.com/docker/go-units
// v0.5.0 (size.go, parseSize with the binary units), the version containerd
// v2.2.0 pins, refuses a size; nil when it parses.
func containerdRAMSizeError(size string) error {
	sep := strings.LastIndexAny(size, "01234567890. ")
	if sep == -1 {
		return fmt.Errorf("invalid size: '%s'", size)
	}
	num, sfx := size[:sep+1], size[sep+1:]
	if size[sep] == ' ' {
		num = size[:sep]
	}
	n, err := strconv.ParseFloat(num, 64)
	switch {
	case err != nil:
		return err
	case n < 0:
		return fmt.Errorf("invalid size: '%s'", size)
	case sfx == "":
		return nil
	}
	sfx = strings.ToLower(sfx)
	bad := fmt.Errorf("invalid suffix: '%s'", sfx)
	switch {
	case len(sfx) > 3:
		return fmt.Errorf("invalid suffix: '%s'", size[sep+1:])
	case sfx[0] == 'b':
		if len(sfx) > 1 {
			return bad
		}
	case !strings.ContainsRune("kmgtp", rune(sfx[0])),
		len(sfx) == 2 && sfx[1] != 'b',
		len(sfx) == 3 && sfx[1:] != "ib":
		return bad
	}
	return nil
}

// containerdLogLevels is what ParseLevel in github.com/sirupsen/logrus v1.9.3
// reads, in lower case.
var containerdLogLevels = strings.Fields("panic fatal error warn warning info debug trace")

// containerdPlugins is every plugin the containerd v2.2.0 Linux release
// registers, by URI: the builtins of cmd/containerd/builtins with no build
// tag set to leave one out, which is the list `ctr plugins ls` prints against
// that release. The value makes the Config the plugin registers, nil for a
// plugin that registers none and so decodes no table. Config.Decode fills that
// struct, so a key the file leaves out keeps the registered value and one it
// sets to "" does not; the two an InitFn below reads are made with theirs, new
// on each call because a decode writes into the slice it finds. The three CRI plugins
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
	"io.containerd.metadata.v1.bolt":                    func() any { return &containerdBoltConfig{ContentSharingPolicy: "shared"} },
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
	"io.containerd.service.v1.diff-service":             func() any { return &containerdDiffServiceConfig{Order: []string{"walking"}} },
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
	// values is the Config of each registered plugin a loaded file holds a
	// table for, by plugin URI: what the plugin registers, with every file's
	// table decoded over it. It is kept past the decode because a plugin's
	// InitFn refuses values of the right type too.
	values map[string]any
	// What the containerd command reads before it calls New
	// (cmd/containerd/command/main.go, lines 143-160): the log level and
	// format, and the two directories. An import's value replaces the main
	// file's unless it is empty.
	logLevel, logFormat string
	root, state         string
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
		s.timeouts, s.proxies, s.tables, s.values = map[string]string{}, map[string]containerdProxyPlugin{}, map[string]error{}, map[string]any{}
		// defaultConfig in cmd/containerd/command/config.go.
		s.root, s.state = "/var/lib/containerd", "/run/containerd"
	}
	for _, field := range []struct{ to, from *string }{
		{&s.logLevel, &cfg.Debug.Level}, {&s.logFormat, &cfg.Debug.Format}, {&s.root, &cfg.Root}, {&s.state, &cfg.State},
	} {
		if *field.from != "" {
			*field.to = *field.from
		}
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
		value := s.values[uri]
		if value == nil {
			value = table()
			s.values[uri] = value
		}
		// A later file's unpack_config replaces an earlier one's, where
		// decoding over the same slice would add to it.
		restore := func() {}
		if transfer, ok := value.(*containerdTransferConfig); ok {
			earlier := transfer.UnpackConfiguration
			transfer.UnpackConfiguration = nil
			restore = func() {
				if transfer.UnpackConfiguration == nil {
					transfer.UnpackConfiguration = earlier
				}
			}
		}
		if err := decodeContainerdPlugin(data, name, value); err != nil {
			s.tables[uri] = err
		}
		restore()
	}
	return nil
}

// containerdHostError is a dependency lookup whose answer the host decides:
// what has to hold for the plugins it asks for to load.
type containerdHostError struct{ needs string }

func (e *containerdHostError) Error() string { return e.needs }

// containerdStartFailure says why a plugin the CRI service starts through
// does not initialize, or that the host decides whether it does.
func containerdStartFailure(plugin string, err error) string {
	var host *containerdHostError
	if errors.As(err, &host) {
		return fmt.Sprintf("%s, without which containerd serves no CRI pull, initializes only when %s, which depends on this host and doctor does not follow", plugin, host.needs)
	}
	return fmt.Sprintf("%s, without which containerd serves no CRI pull, does not initialize on its configuration: %v", plugin, err)
}

// config is the Config a registered plugin's InitFn is handed: what it
// registers, with every loaded file's table decoded over it. nil for a
// plugin that registers none.
func (s *containerdStart) config(uri string) any {
	if value := s.values[uri]; value != nil {
		return value
	}
	if table := containerdPlugins[uri]; table != nil {
		return table()
	}
	return nil
}

// skip is why a registered plugin's InitFn returns ErrSkipPlugin at
// containerd v2.2.0, for every plugin of the Linux release that can: skipped
// when its Config alone decides so, host when something doctor does not read
// does. Both are "" for a plugin that never skips. A skipped plugin is
// registered and loads no instance, so a dependent that asks for it finds
// none.
func (s *containerdStart) skip(uri string) (skipped, host string) {
	switch uri {
	case "io.containerd.snapshotter.v1.devmapper":
		// plugins/snapshots/devmapper/plugin/plugin.go, lines 45-47.
		if s.config(uri).(*containerdDevmapperConfig).PoolName == "" {
			return "its table sets no pool_name", ""
		}
	case "io.containerd.snapshotter.v1.blockfile":
		// NewSnapshotter in plugins/snapshots/blockfile/blockfile.go, lines
		// 138-153: with no scratch_file there is nothing to make the scratch
		// file from, so the plugin loads only on one already under its root.
		switch c := s.config(uri).(*containerdBlockfileConfig); {
		case c.ScratchFile != "":
		case c.RecreateScratch:
			return "its table sets recreate_scratch and no scratch_file", ""
		default:
			return "", "a scratch file exists under the blockfile snapshotter's root"
		}
	case "io.containerd.snapshotter.v1.btrfs":
		// plugins/snapshots/btrfs/btrfs.go, lines 60-69.
		return "", "the btrfs snapshotter's root is on a btrfs filesystem"
	case "io.containerd.snapshotter.v1.erofs":
		// plugins/snapshots/erofs/erofs_linux.go, lines 50-56.
		return "", "the kernel has EROFS loaded"
	case "io.containerd.snapshotter.v1.zfs":
		// github.com/containerd/zfs/v2 v2.0.0-rc.0, plugin/plugin.go, lines 52-60.
		return "", "the zfs snapshotter's root is on a ZFS dataset"
	case "io.containerd.differ.v1.erofs":
		// plugins/diff/erofs/plugin/plugin.go, lines 50-57.
		return "", "mkfs.erofs is installed and has a tar mode"
	case "io.containerd.tracing.processor.v1.otlp":
		// checkDisabled in pkg/tracing/plugin/otlp.go, lines 131-146.
		return "", "containerd's environment names an OTLP endpoint"
	}
	return "", ""
}

// containerdProvider is one plugin of a type containerd holds once it has
// loaded them, with why it is skipped; the fields are skip's.
type containerdProvider struct{ skipped, host string }

// providers is every plugin of type typ in the set an InitFn looks through,
// by id: those the release builds in and those proxy_plugins declares, less
// what disabled_plugins names. A proxy's InitFn dials nothing and loads
// whatever its socket holds (LoadPlugins and getClient in
// cmd/containerd/server/server.go, lines 548-609).
func (s *containerdStart) providers(typ string, disabled []string) map[string]containerdProvider {
	found := map[string]containerdProvider{}
	for uri := range containerdPlugins {
		if id, ok := strings.CutPrefix(uri, typ+"."); ok && !slices.Contains(disabled, uri) {
			skipped, host := s.skip(uri)
			found[id] = containerdProvider{skipped, host}
		}
	}
	for name, proxy := range s.proxies {
		if containerdProxyTypes[proxy.Type] == typ && !slices.Contains(disabled, typ+"."+name) {
			found[name] = containerdProvider{}
		}
	}
	return found
}

// loaded sorts the plugins of type typ into those that load on the
// configuration and those the host decides; one the configuration skips is
// in neither.
func (s *containerdStart) loaded(typ string, disabled []string) (usable, host []string) {
	found := s.providers(typ, disabled)
	for _, id := range slices.Sorted(maps.Keys(found)) {
		switch p := found[id]; {
		case p.skipped != "":
		case p.host != "":
			host = append(host, fmt.Sprintf("%s.%s (when %s)", typ, id, p.host))
		default:
			usable = append(usable, id)
		}
	}
	return usable, host
}

// named is a lookup of one plugin by id among those that loaded: GetByID,
// and a map a GetByType filled. It needs that plugin, not skipped.
func (s *containerdStart) named(typ, name string, disabled []string) error {
	p, ok := s.providers(typ, disabled)[name]
	switch {
	case name == "" || !ok:
		return fmt.Errorf("containerd holds no plugin %s.%s", typ, name)
	case p.skipped != "":
		return fmt.Errorf("containerd skips plugin %s.%s while %s", typ, name, p.skipped)
	case p.host != "":
		return &containerdHostError{fmt.Sprintf("plugin %s.%s loads, which it does only when %s", typ, name, p.host)}
	}
	return nil
}

// single is GetSingle (github.com/containerd/plugin v1.0.0, context.go,
// lines 131-158): exactly one plugin of the type loaded. A skipped one does
// not count, and a second one that loads fails the lookup.
func (s *containerdStart) single(typ string, disabled []string) error {
	usable, host := s.loaded(typ, disabled)
	switch {
	case len(usable) > 1:
		return fmt.Errorf("multiple plugins registered for %s (%s): plugin: multiple instances", typ, strings.Join(usable, ", "))
	case len(host) > 0:
		return &containerdHostError{fmt.Sprintf("exactly one plugin of type %s loads, and whether these do is the host's: %s", typ, strings.Join(host, ", "))}
	case len(usable) == 0:
		return fmt.Errorf("no plugins registered for %s: plugin: not found", typ)
	}
	return nil
}

// collect is GetByType (context.go, lines 182-199): every plugin of the type
// that loaded, and at least one.
func (s *containerdStart) collect(typ string, disabled []string) error {
	usable, host := s.loaded(typ, disabled)
	switch {
	case len(usable) > 0:
		return nil
	case len(host) > 0:
		return &containerdHostError{fmt.Sprintf("a plugin of type %s loads, and whether these do is the host's: %s", typ, strings.Join(host, ", "))}
	}
	return fmt.Errorf("no plugins registered for %s: plugin: not found", typ)
}

// command is what the containerd command refuses in the loaded configuration
// before it calls New: applyFlags sets the log level and format
// (cmd/containerd/command/main.go, lines 320-378), and
// CreateTopLevelDirectories compares the two directories
// (cmd/containerd/server/server.go, lines 73-81). containerd exits on each.
func (s *containerdStart) command() error {
	switch {
	case s.logLevel != "" && !slices.Contains(containerdLogLevels, strings.ToLower(s.logLevel)):
		return fmt.Errorf("[debug] sets level = %q: not a valid logrus Level: %q", s.logLevel, s.logLevel)
	case s.logFormat != "" && s.logFormat != "text" && s.logFormat != "json":
		return fmt.Errorf("[debug] sets format = %q: unknown log format: %s", s.logFormat, s.logFormat)
	case s.root == s.state:
		return errors.New("root and state must be different paths")
	}
	return nil
}

// invalid is why containerd does not start on what the loaded files add up
// to, or why doctor cannot say it does; "" for neither. disabled and required
// are the composed disabled_plugins and required_plugins, by URI.
func (s *containerdStart) invalid(disabled, required []string) string {
	if err := s.command(); err != nil {
		return fmt.Sprintf("containerd does not start: %v", err)
	}
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
	// A plugin no file holds a table for starts on the Config it registers,
	// and looks its dependencies up all the same.
	for _, uri := range slices.Sorted(maps.Keys(containerdPlugins)) {
		check, ok := s.config(uri).(containerdInit)
		if !ok || slices.Contains(disabled, uri) {
			continue
		}
		if err := check.initError(s, disabled); err != nil {
			return containerdStartFailure("plugin "+uri, err)
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
