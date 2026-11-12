package clientconf

import (
	"errors"
	"fmt"
	"net/url"
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
	Registry struct {
		ConfigPath string `toml:"config_path"`
		Mirrors    map[string]struct {
			Endpoints []string `toml:"endpoint"`
		} `toml:"mirrors"`
		Configs map[string]struct {
			Auth *containerdAuthConfig `toml:"auth"`
		} `toml:"configs"`
		Auths   map[string]containerdAuthConfig `toml:"auths"`
		Headers map[string][]string             `toml:"headers"`
	} `toml:"registry"`
	ImageDecryption struct {
		KeyModel string `toml:"key_model"`
	} `toml:"image_decryption"`
	MaxConcurrentDownloads     int    `toml:"max_concurrent_downloads"`
	ConcurrentLayerFetchBuffer int    `toml:"concurrent_layer_fetch_buffer"`
	ImagePullProgressTimeout   string `toml:"image_pull_progress_timeout"`
	ImagePullWithSyncFs        bool   `toml:"image_pull_with_sync_fs"`
	StatsCollectPeriod         int    `toml:"stats_collect_period"`
	UseLocalImagePull          bool   `toml:"use_local_image_pull"`
}

type containerdAuthConfig struct {
	Username      string `toml:"username"`
	Password      string `toml:"password"`
	Auth          string `toml:"auth"`
	IdentityToken string `toml:"identitytoken"`
}

// containerdImagePluginError is why the CRI image plugin of containerd v2.2.0
// does not start on the version 3 config.toml in data, or nil when it does.
// The plugin decodes its own table into ImageConfig (Config.Decode in
// cmd/containerd/server/config/config.go, lines 262-290, where a key the
// struct does not know is a warning and a value of the wrong type the error)
// and then runs ValidateImageConfig (internal/cri/config/config.go) on it.
// containerd logs the failure and goes on without the plugin, so the CRI
// pulls nothing and no hosts.toml under config_path is read. mirrors beside
// config_path, which ValidateImageConfig also refuses, is reported apart, as
// ContainerdRegistry.Legacy.
//
// The table is decoded where it stands in the file, by the same go-toml
// v2.2.4, in place of containerd's marshal and decode of the generic table.
func containerdImagePluginError(data []byte) error {
	var doc struct {
		Plugins struct {
			Images containerdImageConfig `toml:"io.containerd.cri.v1.images"`
		} `toml:"plugins"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return tomlPlaced(err)
	}
	c := doc.Plugins.Images
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
