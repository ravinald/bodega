package clientconf

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"slices"
	"time"

	"github.com/ravinald/bodega/internal/plannedfs"
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
// nothing names a file and home is unknown. getenv cannot tell a variable set
// and empty from one unset; HelmRepositoryFileIn can, and is what a plan and
// a verdict call.
func HelmRepositoryFile(getenv func(string) string, goos, home string) string {
	return HelmRepositoryFileIn(NewEnviron(getenv, nil), goos, home)
}

// HelmRepositoryFileIn is HelmRepositoryFile over an environment that keeps
// presence. It is "" as well under a HELM_REPOSITORY_CONFIG set and empty,
// which helm takes for the path (HelmEnvNoFile); helmpath's lazypath reads an
// empty HELM_CONFIG_HOME or XDG_CONFIG_HOME as unset.
func HelmRepositoryFileIn(env Environ, goos, home string) string {
	value := func(key string) string {
		v, _ := env(key)
		return v
	}
	if p, set := env("HELM_REPOSITORY_CONFIG"); set {
		return p
	}
	dir := value("HELM_CONFIG_HOME")
	switch {
	case dir != "":
	case value("XDG_CONFIG_HOME") != "":
		dir = filepath.Join(value("XDG_CONFIG_HOME"), "helm")
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
	data, err := plannedfs.ReadFile(path)
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
	if err := f.RepositoryError(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// helmSchemes are the URL schemes helm v4.3.0 has a getter for with no
// plugin installed: getter.Getters in pkg/getter/getter.go, lines 203-222.
var helmSchemes = []string{"http", "https", "oci"}

// RepositoryError is the check helm v4.3.0 runs on every entry before it
// fetches from any: NewChartRepository (pkg/repo/v1/chartrepo.go, lines
// 59-68), which `helm repo update` calls for each entry in turn and returns
// from on the first error (pkg/cmd/repo_update.go, lines 100-104). The url
// must parse, with the net/url helm itself calls, and name a scheme helm has
// a getter for. One entry that fails stops the update for every repository,
// so the error is for the file. A getter plugin can add a scheme; doctor
// reads no plugin, so a scheme outside the built-in ones is refused rather
// than assumed served.
//
// A null member is neither skipped nor an error helm prints: helm reads its
// name without a nil check wherever it walks the list, and panics.
func (f *HelmFile) RepositoryError() error {
	if f == nil {
		return nil
	}
	for i, r := range f.Repositories {
		if r == nil {
			return fmt.Errorf("repository %d of %d is null, and helm stops on a nil pointer dereference reading it, before any request: checkForExpiredRepos as every command starts (pkg/cmd/root.go, line 383) and the loop of helm repo update (pkg/cmd/repo_update.go, line 101). Remove the null entry", i+1, len(f.Repositories))
		}
		u, err := url.Parse(r.URL)
		if err != nil {
			return fmt.Errorf("repository %q: invalid chart URL format (helm repo update stops on it before it fetches any repository)", r.Name)
		}
		if !slices.Contains(helmSchemes, u.Scheme) {
			return fmt.Errorf("repository %q: could not find protocol handler for: %s (helm repo update stops on it before it fetches any repository; helm reads http, https and oci without a getter plugin, and doctor reads no plugin)", r.Name, u.Scheme)
		}
	}
	return nil
}

// ClientTLSError is why helm v4.3.0 builds no HTTP client for this
// repository, or nil when it builds one: the client certificate half of
// NewTLSConfig (internal/tlsutil/tls.go, lines 43-110) as httpGetter calls
// it (pkg/getter/httpgetter.go, lines 127-144). With either of certFile and
// keyFile set, both must read and hold a matching pair. helm skips that
// whole step for an entry naming no caFile, no pair and no
// insecure_skip_tls_verify; withCA says the entry holds, or is about to be
// given, a caFile, which takes it out of that case. caFile itself is the
// trust store, and is read where trust is judged.
//
// helm opens a relative path against the directory it is started in, which
// doctor does not know, so one is refused as not interpreted.
func (e *HelmEntry) ClientTLSError(withCA bool) error {
	if e.CertFile == "" && e.KeyFile == "" {
		return nil
	}
	if !withCA && !e.InsecureSkipTLSVerify && (e.CertFile == "" || e.KeyFile == "") {
		return nil
	}
	for _, f := range []struct{ field, path string }{{"certFile", e.CertFile}, {"keyFile", e.KeyFile}} {
		if f.path != "" && !filepath.IsAbs(f.path) {
			return fmt.Errorf("repository %q: %s is the relative path %s, which helm opens against the directory it is started in and doctor does not interpret", e.Name, f.field, f.path)
		}
	}
	cert, err := plannedfs.ReadFile(e.CertFile)
	if err != nil {
		return fmt.Errorf("repository %q: can't create TLS config for client: unable to read cert file: %q: %w", e.Name, e.CertFile, err)
	}
	key, err := plannedfs.ReadFile(e.KeyFile)
	if err != nil {
		return fmt.Errorf("repository %q: can't create TLS config for client: unable to read key file: %q: %w", e.Name, e.KeyFile, err)
	}
	if len(cert) > 0 && len(key) > 0 {
		if _, err := tls.X509KeyPair(cert, key); err != nil {
			return fmt.Errorf("repository %q: can't create TLS config for client: unable to load cert from key pair: %w", e.Name, err)
		}
	}
	return nil
}
