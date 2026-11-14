package clientconf

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ravinald/bodega/internal/plannedfs"
)

// dockerDaemonConfig is Config in daemon/config/config_linux.go at moby
// v28.5.2, with CommonConfig and everything it embeds from
// daemon/config/config.go: every field with its JSON tag, Go type and
// embedding depth, which is what decides the key encoding/json reads it from.
// Fields doctor never edits are here because dockerd refuses to start over a
// wrong type in any of them, and then no registry-mirrors entry or certs.d
// directory is one a pull uses.
type dockerDaemonConfig struct {
	dockerCommonConfig

	Runtimes             map[string]dockerRuntime `json:"runtimes,omitempty"`
	DefaultInitBinary    string                   `json:"default-init,omitempty"`
	CgroupParent         string                   `json:"cgroup-parent,omitempty"`
	EnableSelinuxSupport bool                     `json:"selinux-enabled,omitempty"`
	RemappedRoot         string                   `json:"userns-remap,omitempty"`
	Ulimits              map[string]*dockerUlimit `json:"default-ulimits,omitempty"`
	CPURealtimePeriod    int64                    `json:"cpu-rt-period,omitempty"`
	CPURealtimeRuntime   int64                    `json:"cpu-rt-runtime,omitempty"`
	Init                 bool                     `json:"init,omitempty"`
	InitPath             string                   `json:"init-path,omitempty"`
	SeccompProfile       string                   `json:"seccomp-profile,omitempty"`
	ShmSize              dockerMemBytes           `json:"default-shm-size,omitempty"`
	NoNewPrivileges      bool                     `json:"no-new-privileges,omitempty"`
	IpcMode              string                   `json:"default-ipc-mode,omitempty"`
	CgroupNamespaceMode  string                   `json:"default-cgroupns-mode,omitempty"`
	ResolvConf           string                   `json:"resolv-conf,omitempty"`
	Rootless             bool                     `json:"rootless,omitempty"`
}

type dockerCommonConfig struct {
	AuthorizationPlugins  []string `json:"authorization-plugins,omitempty"`
	AutoRestart           bool     `json:"-"`
	DisableBridge         bool     `json:"-"`
	ExecOptions           []string `json:"exec-opts,omitempty"`
	GraphDriver           string   `json:"storage-driver,omitempty"`
	GraphOptions          []string `json:"storage-opts,omitempty"`
	Labels                []string `json:"labels,omitempty"`
	NetworkDiagnosticPort int      `json:"network-diagnostic-port,omitempty"`
	Pidfile               string   `json:"pidfile,omitempty"`
	RawLogs               bool     `json:"raw-logs,omitempty"`
	Root                  string   `json:"data-root,omitempty"`
	ExecRoot              string   `json:"exec-root,omitempty"`
	SocketGroup           string   `json:"group,omitempty"`
	CorsHeaders           string   `json:"api-cors-header,omitempty"`

	DockerProxies `json:"proxies"`

	LiveRestoreEnabled     bool `json:"live-restore,omitempty"`
	MaxConcurrentDownloads int  `json:"max-concurrent-downloads,omitempty"`
	MaxConcurrentUploads   int  `json:"max-concurrent-uploads,omitempty"`
	MaxDownloadAttempts    int  `json:"max-download-attempts,omitempty"`
	ShutdownTimeout        int  `json:"shutdown-timeout,omitempty"`

	Debug     bool     `json:"debug,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	LogLevel  string   `json:"log-level,omitempty"`
	LogFormat string   `json:"log-format,omitempty"`
	TLS       *bool    `json:"tls,omitempty"`
	TLSVerify *bool    `json:"tlsverify,omitempty"`

	dockerTLSOptions

	SwarmDefaultAdvertiseAddr string `json:"swarm-default-advertise-addr"`
	SwarmRaftHeartbeatTick    uint32 `json:"swarm-raft-heartbeat-tick"`
	SwarmRaftElectionTick     uint32 `json:"swarm-raft-election-tick"`

	MetricsAddress string `json:"metrics-addr"`

	dockerDNSConfig
	dockerLogConfig
	dockerBridgeConfig
	dockerNetworkConfig
	dockerServiceOptions

	ValuesSet map[string]any `json:"-"`

	Experimental bool `json:"experimental"`

	NodeGenericResources []string `json:"node-generic-resources,omitempty"`

	ContainerdAddr string `json:"containerd,omitempty"`
	CriContainerd  bool   `json:"cri-containerd,omitempty"`

	Features map[string]bool `json:"features,omitempty"`

	Builder dockerBuilderConfig `json:"builder,omitempty"`

	ContainerdNamespace       string `json:"containerd-namespace,omitempty"`
	ContainerdPluginNamespace string `json:"containerd-plugin-namespace,omitempty"`

	DefaultRuntime string `json:"default-runtime,omitempty"`

	CDISpecDirs []string `json:"cdi-spec-dirs,omitempty"`

	MinAPIVersion string `json:"-"`
}

type DockerProxies struct {
	HTTPProxy  string `json:"http-proxy,omitempty"`
	HTTPSProxy string `json:"https-proxy,omitempty"`
	NoProxy    string `json:"no-proxy,omitempty"`
}

type dockerTLSOptions struct {
	CAFile   string `json:"tlscacert,omitempty"`
	CertFile string `json:"tlscert,omitempty"`
	KeyFile  string `json:"tlskey,omitempty"`
}

type dockerDNSConfig struct {
	DNS            []net.IP     `json:"dns,omitempty"`
	DNSOptions     []string     `json:"dns-opts,omitempty"`
	DNSSearch      []string     `json:"dns-search,omitempty"`
	HostGatewayIP  net.IP       `json:"host-gateway-ip,omitempty"`
	HostGatewayIPs []netip.Addr `json:"host-gateway-ips,omitempty"`
}

type dockerLogConfig struct {
	Type   string            `json:"log-driver,omitempty"`
	Config map[string]string `json:"log-opts,omitempty"`
}

type dockerBridgeCommon struct {
	Iface     string `json:"bridge,omitempty"`
	FixedCIDR string `json:"fixed-cidr,omitempty"`
}

type dockerDefaultBridgeConfig struct {
	dockerBridgeCommon

	EnableIPv6                  bool   `json:"ipv6,omitempty"`
	FixedCIDRv6                 string `json:"fixed-cidr-v6,omitempty"`
	MTU                         int    `json:"mtu,omitempty"`
	DefaultIP                   net.IP `json:"ip,omitempty"`
	IP                          string `json:"bip,omitempty"`
	IP6                         string `json:"bip6,omitempty"`
	DefaultGatewayIPv4          net.IP `json:"default-gateway,omitempty"`
	DefaultGatewayIPv6          net.IP `json:"default-gateway-v6,omitempty"`
	InterContainerCommunication bool   `json:"icc,omitempty"`
}

type dockerBridgeConfig struct {
	dockerDefaultBridgeConfig

	EnableIPTables           bool   `json:"iptables,omitempty"`
	EnableIP6Tables          bool   `json:"ip6tables,omitempty"`
	EnableIPForward          bool   `json:"ip-forward,omitempty"`
	DisableFilterForwardDrop bool   `json:"ip-forward-no-drop,omitempty"`
	EnableIPMasq             bool   `json:"ip-masq,omitempty"`
	EnableUserlandProxy      bool   `json:"userland-proxy,omitempty"`
	UserlandProxyPath        string `json:"userland-proxy-path,omitempty"`
	AllowDirectRouting       bool   `json:"allow-direct-routing,omitempty"`
}

type dockerNetworkConfig struct {
	DefaultAddressPools    dockerPoolsOpt               `json:"default-address-pools,omitempty"`
	NetworkControlPlaneMTU int                          `json:"network-control-plane-mtu,omitempty"`
	DefaultNetworkOpts     map[string]map[string]string `json:"default-network-opts,omitempty"`
}

// dockerServiceOptions is registry.ServiceOptions.
type dockerServiceOptions struct {
	Mirrors            []string `json:"registry-mirrors,omitempty"`
	InsecureRegistries []string `json:"insecure-registries,omitempty"`
}

// dockerRuntime is system.Runtime in api/types/system.
type dockerRuntime struct {
	Path    string         `json:"path,omitempty"`
	Args    []string       `json:"runtimeArgs,omitempty"`
	Type    string         `json:"runtimeType,omitempty"`
	Options map[string]any `json:"options,omitempty"`
}

// dockerUlimit is units.Ulimit in docker/go-units v0.5.0.
type dockerUlimit struct {
	Name string
	Hard int64
	Soft int64
}

// dockerPoolsOpt is opts.PoolsOpt, whose values are ipamutils.NetworkToSplit.
type dockerPoolsOpt struct {
	Values []*struct {
		Base netip.Prefix `json:"base"`
		Size int          `json:"size"`
	}
}

func (p *dockerPoolsOpt) UnmarshalJSON(raw []byte) error {
	return json.Unmarshal(raw, &p.Values)
}

// dockerMemBytes is opts.MemBytes: a quoted size, never a bare number.
type dockerMemBytes int64

func (m *dockerMemBytes) UnmarshalJSON(s []byte) error {
	if len(s) <= 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Errorf("invalid size: %q", s)
	}
	val, err := dockerRAMInBytes(string(s[1 : len(s)-1]))
	*m = dockerMemBytes(val)
	return err
}

// dockerRAMInBytes is units.RAMInBytes in docker/go-units v0.5.0.
func dockerRAMInBytes(sizeStr string) (int64, error) {
	binary := map[byte]int64{'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30, 't': 1 << 40, 'p': 1 << 50}
	sep := strings.LastIndexAny(sizeStr, "01234567890. ")
	if sep == -1 {
		return -1, fmt.Errorf("invalid size: '%s'", sizeStr)
	}
	num, sfx := sizeStr[:sep+1], sizeStr[sep+1:]
	if sizeStr[sep] == ' ' {
		num = sizeStr[:sep]
	}
	size, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return -1, err
	}
	if size < 0 {
		return -1, fmt.Errorf("invalid size: '%s'", sizeStr)
	}
	if len(sfx) == 0 {
		return int64(size), nil
	}
	bad := fmt.Errorf("invalid suffix: '%s'", strings.ToLower(sfx))
	if len(sfx) > 3 {
		return -1, bad
	}
	sfx = strings.ToLower(sfx)
	if sfx[0] == 'b' {
		if len(sfx) > 1 {
			return -1, bad
		}
		return int64(size), nil
	}
	mul, ok := binary[sfx[0]]
	if !ok || (len(sfx) == 2 && sfx[1] != 'b') || (len(sfx) == 3 && sfx[1:] != "ib") {
		return -1, bad
	}
	return int64(size * float64(mul)), nil
}

// The builder types are daemon/config/builder.go. Their keys are the Go
// field names, and two of them decode through a second struct that also
// takes the key the field replaced.

type dockerBuilderConfig struct {
	GC           dockerBuilderGC           `json:",omitempty"`
	Entitlements dockerBuilderEntitlements `json:",omitempty"`
	History      *dockerBuilderHistory     `json:",omitempty"`
}

type dockerBuilderEntitlements struct {
	NetworkHost      *bool `json:"network-host,omitempty"`
	SecurityInsecure *bool `json:"security-insecure,omitempty"`
}

type dockerBuilderHistory struct {
	MaxAge     dockerBuildkitDuration `json:",omitempty"`
	MaxEntries int64                  `json:",omitempty"`
}

// dockerBuildkitDuration is Duration in buildkit v0.25.2's
// cmd/buildkitd/config, the version moby v28.5.2 vendors: a duration string,
// or a string of whole seconds.
type dockerBuildkitDuration struct{ time.Duration }

func (d *dockerBuildkitDuration) UnmarshalText(textb []byte) error {
	text := string(textb)
	if len(text) > 0 && text[0] == '"' && text[len(text)-1] == '"' {
		text = text[1 : len(text)-1]
	}
	if len(text) == 0 {
		return nil
	}
	if duration, err := time.ParseDuration(text); err == nil {
		d.Duration = duration
		return nil
	}
	if i, err := strconv.ParseInt(text, 10, 64); err == nil {
		d.Duration = time.Duration(i) * time.Second
		return nil
	}
	return fmt.Errorf("invalid duration %s", text)
}

type dockerBuilderGC struct {
	Enabled              *bool
	Policy               []dockerBuilderGCRule
	DefaultReservedSpace string
	DefaultMaxUsedSpace  string
	DefaultMinFreeSpace  string
}

func (x *dockerBuilderGC) UnmarshalJSON(data []byte) error {
	var xx struct {
		Enabled              bool                  `json:",omitempty"`
		Policy               []dockerBuilderGCRule `json:",omitempty"`
		DefaultReservedSpace string                `json:",omitempty"`
		DefaultMaxUsedSpace  string                `json:",omitempty"`
		DefaultMinFreeSpace  string                `json:",omitempty"`
		DefaultKeepStorage   string                `json:",omitempty"`
	}
	xx.Enabled = true
	if err := json.Unmarshal(data, &xx); err != nil {
		return err
	}
	x.Enabled, x.Policy = &xx.Enabled, xx.Policy
	return nil
}

type dockerBuilderGCRule struct {
	All    bool
	Filter dockerBuilderGCFilter
}

func (x *dockerBuilderGCRule) UnmarshalJSON(data []byte) error {
	var xx struct {
		All           bool                  `json:",omitempty"`
		Filter        dockerBuilderGCFilter `json:",omitempty"`
		ReservedSpace string                `json:",omitempty"`
		MaxUsedSpace  string                `json:",omitempty"`
		MinFreeSpace  string                `json:",omitempty"`
		KeepStorage   string                `json:",omitempty"`
	}
	if err := json.Unmarshal(data, &xx); err != nil {
		return err
	}
	x.All, x.Filter = xx.All, xx.Filter
	return nil
}

// dockerBuilderGCFilter takes a list of key=value strings, or the older object
// form filters.Args decodes.
type dockerBuilderGCFilter map[string]map[string]bool

func (x *dockerBuilderGCFilter) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		f := map[string]map[string]bool{}
		err := json.Unmarshal(data, &f)
		*x = f
		return err
	}
	return nil
}

// dockerdFlags is every name dockerd v28.5.2 accepts as a daemon.json key:
// its long flags (cmd/dockerd/docker.go, options.go, config.go and
// config_unix.go, with cobra's help), and the name each list, map or pool
// flag gives its option, which is the key the file spells it by. dockerd
// refuses a file holding any other key, and this list is not the set of JSON
// tags above: swarm-raft-heartbeat-tick has a tag and no flag, so dockerd
// refuses it.
var dockerdFlags = func() map[string]bool {
	out := map[string]bool{}
	for _, name := range strings.Fields(`
		help version config-file debug validate log-level log-format tls tlsverify tlscacert tlscert tlskey host
		add-runtime group storage-driver selinux-enabled default-ulimit iptables ip6tables ip-forward
		ip-forward-no-drop ip-masq ipv6 bip bip6 bridge fixed-cidr fixed-cidr-v6 default-gateway
		default-gateway-v6 icc ip userland-proxy userland-proxy-path allow-direct-routing cgroup-parent
		userns-remap live-restore init init-path cpu-rt-period cpu-rt-runtime seccomp-profile default-shm-size
		no-new-privileges default-ipc-mode default-address-pool rootless default-cgroupns-mode
		registry-mirror insecure-registry storage-opt authorization-plugin exec-opt pidfile data-root exec-root
		containerd cri-containerd feature default-network-opt mtu network-control-plane-mtu
		network-diagnostic-port raw-logs dns dns-opt dns-search host-gateway-ip label log-driver log-opt
		max-concurrent-downloads max-concurrent-uploads max-download-attempts shutdown-timeout
		swarm-default-advertise-addr experimental metrics-addr node-generic-resource containerd-namespace
		containerd-plugins-namespace default-runtime http-proxy https-proxy no-proxy cdi-spec-dir
		allow-nondistributable-artifacts api-cors-header restart

		hosts runtimes default-ulimits default-address-pools registry-mirrors insecure-registries storage-opts
		authorization-plugins exec-opts features default-network-opts dns-opts host-gateway-ips labels log-opts
		node-generic-resources cdi-spec-dirs

		builder deprecated-key-path`) {
		out[name] = true
	}
	return out
}()

// dockerFlatOptions is flatOptions: the keys whose object value is the
// option itself. Any other object is a group, and its members are options.
var dockerFlatOptions = map[string]bool{
	"cluster-store-opts": true, "default-network-opts": true, "log-opts": true, "runtimes": true,
	"default-ulimits": true, "features": true, "builder": true,
}

// DockerDaemonFile is what a daemon.json dockerd loads says about registries.
type DockerDaemonFile struct {
	// Mirrors is registry-mirrors and InsecureRegistries insecure-registries,
	// each as written.
	Mirrors            []string
	InsecureRegistries []string
	// TLSUnmodeled names the first key that has dockerd load TLS files for
	// its own API listeners (tls, tlsverify, tlscacert, tlscert, tlskey), ""
	// for none. dockerd builds that TLS configuration as it starts and exits
	// when the files do not load, which nothing here reads, so a CA is not
	// certified for a dockerd holding one. It is no load error: a configure
	// that installs no CA edits such a file as it stands.
	TLSUnmodeled string
	// StartError is the error dockerd exits on after it has loaded the file,
	// "" for none: the checks NewDaemon runs on the configuration alone
	// before it serves (dockerStartError). dockerd --validate does not run
	// them, so it is no load error and a configure that installs no CA edits
	// the file as it stands, but no mirror or certs.d directory is one a
	// pull uses.
	StartError string
	// StartUnmodeled names the first key dockerd acts on between loading
	// the file and serving in a way the host decides (its storage, network,
	// cgroups, plugins, listeners), set to other than dockerd's default, ""
	// for none. Nothing here reads that host state, so a CA is not certified
	// for a dockerd holding one.
	StartUnmodeled string
}

// ParseDockerDaemonFile loads a daemon.json as dockerd v28.5.2 does with no flag
// on its command line beyond --config-file: MergeDaemonConfigurations in
// daemon/config/config.go, then the checks loadDaemonCliConfig runs on the
// result. That is the byte order mark, the keys dockerd knows, the typed
// decode, Validate and the label conflict check. Any error is one dockerd
// exits on, so nothing in a file that fails here is a setting it runs with.
//
// Left out of the error, because the file alone does not decide them: a key
// that repeats a flag set on dockerd's command line and the userland-proxy
// binary dockerd looks up on the host. What dockerd does with a loaded file
// as it starts is StartError and StartUnmodeled on the result.
func ParseDockerDaemonFile(data []byte) (*DockerDaemonFile, error) {
	b, err := dockerDecodeBOM(data)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return &DockerDaemonFile{}, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	set := map[string]any{}
	for k, v := range raw {
		if m, ok := v.(map[string]any); ok && !dockerFlatOptions[k] {
			for km, vm := range m {
				set[km] = vm
			}
			continue
		}
		set[k] = v
	}
	var unknown []string
	for key := range set {
		if !dockerdFlags[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("the following directives don't match any configuration option: %s", strings.Join(unknown, ", "))
	}
	if _, old := set["host-gateway-ip"]; old {
		if _, both := set["host-gateway-ips"]; both {
			return nil, errors.New("host-gateway-ip and host-gateway-ips must not both be specified in the config file")
		}
	}
	var conf dockerDaemonConfig
	if err := json.Unmarshal(b, &conf); err != nil {
		return nil, err
	}
	if err := conf.validate(); err != nil {
		return nil, err
	}
	d := &DockerDaemonFile{Mirrors: conf.Mirrors, InsecureRegistries: conf.InsecureRegistries}
	if err := conf.startError(set); err != nil {
		d.StartError = err.Error()
	}
	d.StartUnmodeled = conf.startUnmodeled(set)
	for _, k := range []struct {
		key string
		set bool
	}{
		{"tls", conf.TLS != nil && *conf.TLS}, {"tlsverify", conf.TLSVerify != nil && *conf.TLSVerify},
		{"tlscacert", conf.CAFile != ""}, {"tlscert", conf.CertFile != ""}, {"tlskey", conf.KeyFile != ""},
	} {
		if k.set {
			d.TLSUnmodeled = k.key
			break
		}
	}
	return d, nil
}

// LoadDockerDaemonFile reads the daemon.json at path. A missing file is a dockerd
// running on its defaults: nil and no error. Any other failure names the file.
func LoadDockerDaemonFile(path string) (*DockerDaemonFile, error) {
	data, err := plannedfs.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	d, err := ParseDockerDaemonFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// dockerDecodeBOM is the transform getConflictFreeConfiguration applies:
// a UTF-8 or UTF-16 byte order mark selects the encoding, none means UTF-8,
// and the result must be valid UTF-8.
func dockerDecodeBOM(b []byte) ([]byte, error) {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		b = b[3:]
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		order = binary.LittleEndian
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		order = binary.BigEndian
	}
	if order != nil {
		b = b[2:]
		units := make([]uint16, len(b)/2)
		for i := range units {
			units[i] = order.Uint16(b[2*i:])
		}
		// A trailing odd byte or an unpaired surrogate decodes to U+FFFD under
		// x/text too, which is valid UTF-8 and then fails as JSON.
		out := string(utf16.Decode(units))
		if len(b)%2 == 1 {
			out += string(utf8.RuneError)
		}
		return []byte(out), nil
	}
	if !utf8.Valid(b) {
		return nil, errors.New("failed to decode configuration JSON: encoding: invalid UTF-8")
	}
	return b, nil
}

var (
	dockerAlphaRe  = regexp.MustCompile(`[a-zA-Z]`)
	dockerDomainRe = regexp.MustCompile(`^(:?(:?[a-zA-Z0-9]|(:?[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))(:?\.(:?[a-zA-Z0-9]|(:?[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])))*)\.?\s*$`)
)

// validate is Validate in daemon/config/config.go with validatePlatformConfig
// from config_linux.go, then GetConflictFreeLabels, less the userland-proxy
// binary lookup. Each check reads only what the file set: dockerd runs them
// on the file merged over its flag defaults, and every default passes.
func (conf *dockerDaemonConfig) validate() error {
	if conf.LogLevel != "" {
		switch strings.ToLower(conf.LogLevel) {
		case "panic", "fatal", "error", "warn", "info", "debug", "trace":
		default:
			return fmt.Errorf("invalid logging level: %s", conf.LogLevel)
		}
	}
	switch conf.LogFormat {
	case "", "text", "json":
	default:
		return fmt.Errorf("invalid log format: %s", conf.LogFormat)
	}
	for _, val := range conf.DNSSearch {
		if val = strings.Trim(val, " "); val == "." {
			continue
		}
		ns := dockerDomainRe.FindStringSubmatch(val)
		if dockerAlphaRe.FindString(val) == "" || len(ns) == 0 || len(ns[1]) >= 255 {
			return fmt.Errorf("%s is not a valid domain", val)
		}
	}
	var have4, have6 bool
	for _, ip := range conf.HostGatewayIPs {
		switch {
		case ip.Is4() && have4:
			return errors.New("only one IPv4 host gateway IP address can be specified")
		case ip.Is4():
			have4 = true
		case have6:
			return errors.New("only one IPv6 host gateway IP address can be specified")
		default:
			have6 = true
		}
	}
	for _, label := range conf.Labels {
		if !strings.Contains(label, "=") {
			return fmt.Errorf("bad attribute format: %s", label)
		}
		lowered := strings.ToLower(label)
		for _, reserved := range []string{"com.docker.", "io.docker.", "org.dockerproject."} {
			if strings.HasPrefix(lowered, reserved) {
				return fmt.Errorf("label %s is not allowed: the namespaces com.docker.*, io.docker.*, and org.dockerproject.* are reserved for internal use", label)
			}
		}
	}
	switch {
	case conf.MTU < 0:
		return fmt.Errorf("invalid default MTU: %d", conf.MTU)
	case conf.MaxConcurrentDownloads < 0:
		return fmt.Errorf("invalid max concurrent downloads: %d", conf.MaxConcurrentDownloads)
	case conf.MaxConcurrentUploads < 0:
		return fmt.Errorf("invalid max concurrent uploads: %d", conf.MaxConcurrentUploads)
	case conf.MaxDownloadAttempts < 0:
		return fmt.Errorf("invalid max download attempts: %d", conf.MaxDownloadAttempts)
	case conf.NetworkDiagnosticPort < 0 || conf.NetworkDiagnosticPort > 65535:
		return fmt.Errorf("invalid network-diagnostic-port (%d): value must be between 0 and 65535", conf.NetworkDiagnosticPort)
	}
	if err := dockerGenericResources(conf.NodeGenericResources); err != nil {
		return err
	}
	for _, h := range conf.Hosts {
		if err := dockerValidateHost(h); err != nil {
			return err
		}
	}
	for _, mirror := range conf.Mirrors {
		if err := dockerValidateMirror(mirror); err != nil {
			return err
		}
	}
	if conf.CorsHeaders != "" {
		return errors.New(`DEPRECATED: The "api-cors-header" config parameter and the dockerd "--api-cors-header" option have been removed; use a reverse proxy if you need CORS headers`)
	}
	for _, keyValue := range conf.ExecOptions {
		k, v, ok := strings.Cut(keyValue, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch {
		case !ok || k == "" || v == "":
			return fmt.Errorf("invalid exec-opt (%s): must be formatted 'opt=value'", keyValue)
		case k == "isolation":
			return fmt.Errorf("invalid exec-opt (%s): option '%s' is only supported on windows", keyValue, k)
		case k != "native.cgroupdriver":
			return fmt.Errorf("invalid exec-opt (%s): unknown option: '%s'", keyValue, k)
		}
	}
	switch mode := conf.IpcMode; {
	case mode == "", mode == "private", mode == "shareable":
	case mode == "none", mode == "host", strings.HasPrefix(mode, "container:"):
		return fmt.Errorf(`IPC mode "%v" is not supported as default value; use "shareable" or "private"`, mode)
	default:
		return fmt.Errorf(`default IPC mode setting (%v) is invalid; use "shareable" or "private"`, mode)
	}
	if conf.FixedCIDRv6 != "" {
		prefix, err := netip.ParsePrefix(conf.FixedCIDRv6)
		linkLocal := netip.MustParsePrefix("fe80::/64")
		switch {
		case err != nil:
		case !prefix.Addr().Is6() || prefix.Addr().Is4In6():
			err = fmt.Errorf("'%s' is not a valid IPv6 subnet", prefix)
		case prefix.Addr().IsMulticast():
			err = fmt.Errorf("multicast subnet '%s' is not allowed", prefix)
		case prefix.Masked() != linkLocal && linkLocal.Overlaps(prefix):
			err = fmt.Errorf("'%s' clashes with the Link-Local prefix 'fe80::/64'", prefix)
		}
		if err != nil {
			return fmt.Errorf("invalid fixed-cidr-v6: %w", err)
		}
	}
	switch conf.CgroupNamespaceMode {
	case "", "private", "host":
	default:
		return fmt.Errorf(`invalid default cgroup namespace (%v): use "host" or "private"`, conf.CgroupNamespaceMode)
	}
	labels := map[string]string{}
	for _, label := range conf.Labels {
		key, val, _ := strings.Cut(label, "=")
		if v, ok := labels[key]; ok && v != val {
			return fmt.Errorf("conflict labels for %s=%s and %s=%s", key, val, key, v)
		}
		labels[key] = val
	}
	return nil
}

// dockerHostPortRe is validHostPortRegex in registry/config.go: DomainRegexp
// of distribution/reference v0.6.0, the version moby v28.5.2 vendors,
// anchored.
var dockerHostPortRe = regexp.MustCompile(`^(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*|\[(?:[a-fA-F0-9:]+)\])(?::[0-9]+)?$`)

// dockerInsecureRegistry is the check loadInsecureRegistries in
// registry/config.go runs on one insecure-registries entry, kept to its
// errors: registry.NewService is the first thing NewDaemon builds.
func dockerInsecureRegistry(r string) error {
	if strings.HasPrefix(r, "-") || strings.HasSuffix(r, "-") {
		return fmt.Errorf("invalid index name (%s). Cannot begin or end with a hyphen", r)
	}
	switch lower := strings.ToLower(r); {
	case strings.HasPrefix(lower, "http://"):
		r = r[7:]
	case strings.HasPrefix(lower, "https://"):
		r = r[8:]
	case strings.Contains(r, "://"):
		return fmt.Errorf("insecure registry %s should not contain '://'", r)
	}
	if _, _, err := net.ParseCIDR(r); err == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(r)
	if err != nil {
		host, port = r, ""
	}
	if !dockerHostPortRe.MatchString(r) && net.ParseIP(host) == nil {
		return fmt.Errorf("insecure registry %s is not valid: invalid host %q", r, host)
	}
	if port != "" {
		v, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("insecure registry %s is not valid: %w", r, err)
		}
		if v < 0 || v > 65535 {
			return fmt.Errorf("insecure registry %s is not valid: invalid port %q", r, port)
		}
	}
	return nil
}

// cgroupDriver is the native.cgroupdriver exec-opts names, "" for none:
// GetExecOpt over parseExecOptions, where the last entry wins.
func (conf *dockerDaemonConfig) cgroupDriver() string {
	cd := ""
	for _, keyValue := range conf.ExecOptions {
		k, v, _ := strings.Cut(keyValue, "=")
		if strings.ToLower(strings.TrimSpace(k)) == "native.cgroupdriver" {
			cd = strings.TrimSpace(v)
		}
	}
	return cd
}

// dockerSlice is the name verifyDaemonSettings takes for cgroup-parent under
// systemd's cgroup driver.
func dockerSlice(parent string) bool {
	return len(parent) > 6 && strings.HasSuffix(parent, ".slice")
}

// startError is what NewDaemon in daemon/daemon.go at moby v28.5.2 checks on
// the configuration alone before it serves, in its order: registry.NewService
// over the insecure registries (the mirrors are validated on load), then
// every check of verifyDaemonSettings in daemon/daemon_unix.go that reads no
// host state. set is the file's keys, groups flattened, which is what tells
// a key the file leaves at dockerd's default from one it turns off.
//
// The one check of verifyDaemonSettings left out reads the host's cgroup
// version, for rootless under systemd's driver; startUnmodeled names rootless.
func (conf *dockerDaemonConfig) startError(set map[string]any) error {
	for _, r := range conf.InsecureRegistries {
		if err := dockerInsecureRegistry(r); err != nil {
			return err
		}
	}
	on := func(key string, def bool) bool {
		if v, ok := set[key].(bool); ok {
			return v
		}
		return def
	}
	// The file spells the plugins namespace by its flag, which has no field
	// tag to decode into; where it is set, startUnmodeled names it.
	containers := conf.ContainerdNamespace
	if containers == "" {
		containers = dockerStartDefaults["containerd-namespace"].(string)
	}
	if _, named := set["containerd-plugins-namespace"]; !named && containers == dockerStartDefaults["containerd-plugins-namespace"] {
		return errors.New("containers namespace and plugins namespace cannot be the same")
	}
	// dockerd's own sentences, as it prints them.
	exclusive := ""
	switch {
	case conf.Iface != "" && conf.IP != "":
		exclusive = "You specified -b & --bip, mutually exclusive options. Please specify only one"
	case conf.Iface != "" && conf.IP6 != "":
		exclusive = "You specified -b & --bip6, mutually exclusive options. Please specify only one"
	case !on("icc", true) && !on("iptables", true):
		exclusive = "You specified --iptables=false with --icc=false. ICC=false uses iptables to function. Please set --icc or --iptables to true"
	case !on("icc", true) && on("ipv6", false) && !on("ip6tables", true):
		exclusive = "You specified --ip6tables=false with --icc=false. ICC=false uses ip6tables to function. Please set --icc or --ip6tables to true"
	}
	if exclusive != "" {
		return errors.New(exclusive)
	}
	switch cd := conf.cgroupDriver(); cd {
	case "", "cgroupfs":
	case "systemd":
		if conf.CgroupParent != "" && !dockerSlice(conf.CgroupParent) {
			return errors.New(`cgroup-parent for systemd cgroup should be a valid slice named as "xxx.slice"`)
		}
	case "none":
		return fmt.Errorf("native.cgroupdriver option %s is internally used and cannot be specified manually", cd)
	default:
		return fmt.Errorf("native.cgroupdriver option %s not supported", cd)
	}
	return nil
}

// dockerStartModeled is every daemon.json key whose value cannot stop
// dockerd v28.5.2 between loading the file and serving, past what validate
// and startError check: the registry lists, logging of the daemon itself,
// labels, the transfer limits, and the defaults a container is created with.
// log-driver is one of those: defaultLogConfig in daemon/logs.go looks the
// driver up only to validate log-opts, which is not here.
// The TLS keys are TLSUnmodeled's. Any other key is acted on as dockerd starts
// (cmd/dockerd/daemon.go start, then NewDaemon) against the host: a
// directory, a listener, a storage or log driver, a network, a plugin, a
// runtime binary, containerd, swarm state.
var dockerStartModeled = map[string]bool{
	"registry-mirrors": true, "insecure-registries": true,
	"debug": true, "log-level": true, "log-format": true, "raw-logs": true, "labels": true, "log-driver": true,
	"max-concurrent-downloads": true, "max-concurrent-uploads": true, "max-download-attempts": true,
	"shutdown-timeout": true, "experimental": true,
	"exec-opts": true, "cgroup-parent": true,
	"default-ipc-mode": true, "default-cgroupns-mode": true, "no-new-privileges": true,
	"tls": true, "tlsverify": true, "tlscacert": true, "tlscert": true, "tlskey": true,
}

// dockerStartDefaults is dockerd's default for each key outside
// dockerStartModeled whose default is not its type's zero value: config.New
// with setPlatformDefaults in daemon/config, and the flag defaults in
// cmd/dockerd/config.go and config_unix.go, for a dockerd not under
// RootlessKit.
var dockerStartDefaults = map[string]any{
	"iptables": true, "ip6tables": true, "ip-forward": true, "ip-masq": true, "icc": true,
	"userland-proxy": true, "restart": true,
	"data-root": "/var/lib/docker", "exec-root": "/var/run/docker", "pidfile": "/var/run/docker.pid",
	"group": "docker", "default-runtime": "runc", "seccomp-profile": "builtin",
	"containerd-namespace": "moby", "containerd-plugins-namespace": "plugins.moby",
	"mtu": float64(1500), "network-control-plane-mtu": float64(1500), "ip": "0.0.0.0",
}

// startUnmodeled names the first key, in name order, that the file sets to
// other than dockerd's default and dockerStartModeled does not hold, "" for
// none. cgroup-parent is named where the file leaves the cgroup driver to
// the host: dockerd picks systemd's on a cgroup v2 host running systemd
// (UsingSystemd), and refuses a parent that is no slice only there.
func (conf *dockerDaemonConfig) startUnmodeled(set map[string]any) string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if dockerStartModeled[key] {
			continue
		}
		switch v := set[key].(type) {
		case nil:
			continue
		case []any:
			if len(v) == 0 {
				continue
			}
		case map[string]any:
			if len(v) == 0 {
				continue
			}
		default:
			if def, ok := dockerStartDefaults[key]; ok && v == def {
				continue
			}
			if _, ok := dockerStartDefaults[key]; !ok && (v == false || v == "" || v == float64(0)) {
				continue
			}
		}
		return key
	}
	if conf.CgroupParent != "" && conf.cgroupDriver() == "" && !dockerSlice(conf.CgroupParent) {
		return "cgroup-parent"
	}
	return ""
}

// dockerGenericResources is genericresource.Parse in swarmkit v2.0.0, kept
// to its errors.
func dockerGenericResources(terms []string) error {
	tokens := map[string][]string{}
	for _, term := range terms {
		kva := strings.Split(term, "=")
		if len(kva) != 2 {
			return fmt.Errorf("could not parse GenericResource: incorrect term %s, missing '=' or malformed expression", term)
		}
		key := strings.TrimSpace(kva[0])
		tokens[key] = append(tokens[key], strings.TrimSpace(kva[1]))
	}
	for k, v := range tokens {
		discrete := 0
		for _, val := range v {
			if _, err := strconv.ParseInt(val, 10, 64); err == nil {
				discrete++
			}
		}
		if len(v) == 1 && discrete == 1 {
			if u, _ := strconv.ParseInt(v[0], 10, 64); u < 0 {
				return fmt.Errorf("could not parse GenericResource: cannot ask for negative resource %s", k)
			}
			continue
		}
		if discrete > 0 {
			return fmt.Errorf("could not parse GenericResource: mixed discrete and named resources in expression '%s=%s'", k, v)
		}
	}
	return nil
}

// dockerValidateHost is opts.ValidateHost: parseDaemonHost over a trimmed,
// non-empty value.
func dockerValidateHost(val string) error {
	address := strings.TrimSpace(val)
	if address == "" {
		return nil
	}
	proto, addr, ok := strings.Cut(address, "://")
	if !ok && proto != "" {
		addr, proto = proto, "tcp"
	}
	switch proto {
	case "tcp":
		try := address
		if !strings.Contains(try, "://") {
			try = "tcp://" + try
		}
		u, err := url.Parse(try)
		switch {
		case err != nil:
		case u.Scheme != "tcp":
			err = fmt.Errorf("unsupported proto '%s'", u.Scheme)
		case u.Path != "":
			err = errors.New("should not contain a path element")
		case u.Port() != "":
			if p, convErr := strconv.Atoi(u.Port()); convErr != nil || p == 0 {
				err = fmt.Errorf("invalid port: %s", u.Port())
			}
		}
		if err != nil {
			return fmt.Errorf("invalid bind address (%s): %w", address, err)
		}
	case "unix", "npipe":
		if strings.Contains(addr, "://") {
			return fmt.Errorf("invalid bind address (%s): invalid %s address: %s", address, proto, addr)
		}
	case "fd":
	default:
		return fmt.Errorf("invalid bind address (%s): unsupported proto '%s'", address, proto)
	}
	return nil
}

// dockerValidateMirror is registry.ValidateMirror.
func dockerValidateMirror(mirrorURL string) error {
	if scheme, _, ok := strings.Cut(mirrorURL, "://"); !ok || scheme == "" {
		return fmt.Errorf("invalid mirror: no scheme specified for %q: must use either 'https://' or 'http://'", mirrorURL)
	}
	uri, err := url.Parse(mirrorURL)
	switch {
	case err != nil:
		return fmt.Errorf("invalid mirror: %q is not a valid URI: %w", mirrorURL, err)
	case uri.Scheme != "http" && uri.Scheme != "https":
		return fmt.Errorf("invalid mirror: unsupported scheme %q in %q: must use either 'https://' or 'http://'", uri.Scheme, uri)
	case uri.RawQuery != "" || uri.Fragment != "":
		return fmt.Errorf("invalid mirror: query or fragment at end of the URI %q", uri)
	case uri.User != nil:
		uri.User = url.UserPassword(uri.User.Username(), "xxxxx")
		return fmt.Errorf("invalid mirror: username/password not allowed in URI %q", uri)
	}
	return nil
}

// DockerCertsDirError is the check dockerd v28.5.2 runs on the certs.d
// directory of a registry or mirror host before it sends that host a
// request: loadTLSConfig in registry/registry.go, lines 66-118. Every .crt
// must read, every .cert needs the .key beside it and must load with it as a
// key pair, and every .key needs its .cert. dockerd builds no TLS
// configuration for the host on any of those errors, so it sends the host
// nothing, whatever a ca.crt in the same directory holds. A directory that
// does not exist is a host with no certificates of its own: no error.
//
// planned names a .crt a plan is about to write there, which is not read
// since the plan replaces it. "" reads every one.
func DockerCertsDirError(dir, planned string) error {
	entries, err := plannedfs.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	has := func(name string) bool {
		for _, e := range entries {
			if e.Name() == name {
				return true
			}
		}
		return false
	}
	for _, e := range entries {
		name := e.Name()
		switch filepath.Ext(name) {
		case ".crt":
			if name == planned {
				continue
			}
			if _, err := plannedfs.ReadFile(filepath.Join(dir, name)); err != nil {
				return err
			}
		case ".cert":
			key := name[:len(name)-len(".cert")] + ".key"
			if !has(key) {
				return fmt.Errorf("missing key %s for client certificate %s in %s. CA certificates must use the extension .crt", key, name, dir)
			}
			if _, err := tls.LoadX509KeyPair(filepath.Join(dir, name), filepath.Join(dir, key)); err != nil {
				return fmt.Errorf("client certificate %s in %s: %w", name, dir, err)
			}
		case ".key":
			cert := name[:len(name)-len(".key")] + ".cert"
			if !has(cert) {
				return fmt.Errorf("missing client certificate %s for key %s in %s", cert, name, dir)
			}
		}
	}
	return nil
}
