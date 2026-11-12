package clientconf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"
)

// HelmFile is helm's repositories.yaml as helm decodes it: File in
// pkg/repo/v1/repo.go at helm v4.3.0, every field with its JSON tag and Go
// type. Fields doctor never edits are here because helm refuses the whole
// file over a wrong type in any of them.
type HelmFile struct {
	APIVersion   string       `json:"apiVersion"`
	Generated    time.Time    `json:"generated"`
	Repositories []*HelmEntry `json:"repositories"`
}

// HelmEntry is one repository: Entry in pkg/repo/v1/chartrepo.go at helm
// v4.3.0.
type HelmEntry struct {
	Name                  string `json:"name"`
	URL                   string `json:"url"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	CertFile              string `json:"certFile"`
	KeyFile               string `json:"keyFile"`
	CAFile                string `json:"caFile"`
	InsecureSkipTLSVerify bool   `json:"insecure_skip_tls_verify"`
	PassCredentialsAll    bool   `json:"pass_credentials_all"`
}

// ParseHelmFile decodes data as helm's LoadFile does: sigs.k8s.io/yaml, at
// the version helm v4.3.0 pins, converts the YAML to JSON and encoding/json
// fills the structs. The error is the one helm prints.
func ParseHelmFile(data []byte) (*HelmFile, error) {
	f := new(HelmFile)
	if err := yaml.Unmarshal(data, f); err != nil {
		return nil, err
	}
	return f, nil
}

// HelmRepositoryFile is the one repositories.yaml helm reads, resolved as
// helm's helmpath does on every platform: the file HELM_REPOSITORY_CONFIG
// names, else the one under HELM_CONFIG_HOME, else under
// $XDG_CONFIG_HOME/helm, else the platform default under home. It is "" when
// nothing names a file and home is unknown.
func HelmRepositoryFile(getenv func(string) string, goos, home string) string {
	env := func(key string) string {
		if getenv == nil {
			return ""
		}
		return getenv(key)
	}
	if p := env("HELM_REPOSITORY_CONFIG"); p != "" {
		return p
	}
	dir := env("HELM_CONFIG_HOME")
	switch {
	case dir != "":
	case env("XDG_CONFIG_HOME") != "":
		dir = filepath.Join(env("XDG_CONFIG_HOME"), "helm")
	case home == "":
		return ""
	case goos == OSDarwin:
		dir = filepath.Join(home, "Library", "Preferences", "helm")
	default:
		dir = filepath.Join(home, ".config", "helm")
	}
	return filepath.Join(dir, "repositories.yaml")
}

// LoadHelmFile reads the repositories.yaml at path the way helm loads it. A
// path holding no file is a helm with no repositories: nil and no error. Any
// other failure is one helm stops on too, and the error names the file.
func LoadHelmFile(path string) (*HelmFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f, err := ParseHelmFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}
