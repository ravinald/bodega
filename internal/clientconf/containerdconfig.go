package clientconf

import (
	"errors"
	"fmt"
	"strings"

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
		var derr *toml.DecodeError
		if errors.As(err, &derr) {
			row, column := derr.Position()
			return nil, fmt.Errorf("failed to unmarshal TOML at row %d column %d: %w", row, column, err)
		}
		return nil, fmt.Errorf("failed to unmarshal TOML: %w", err)
	}
	return cfg, nil
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
