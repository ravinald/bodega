package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// Mode says which way a source's reports travel.
type Mode string

const (
	// ModePush sources receive reports: something on or near the host sends
	// them to a route the source registers.
	ModePush Mode = "push"
	// ModePull sources poll a vendor's management API on a timer. They never
	// poll a host, so bodega holds no credential into any host.
	ModePull Mode = "pull"
)

// Capability names one kind of evidence a source can deliver.
type Capability string

const (
	// CapInventory is installed components.
	CapInventory Capability = "inventory"
	// CapAttempts is evidence that a host tried to reach a package registry
	// directly rather than through bodega.
	CapAttempts Capability = "attempts"
)

// EcosystemOther is the ecosystem of a component bodega serves no type for.
const EcosystemOther = "other"

// ValidEcosystem reports whether e is one of bodega's type names or "other".
func ValidEcosystem(e string) bool {
	return e == EcosystemOther || manifest.IsKnownType(e)
}

// Component is one installed component in the common model every source
// normalizes into. DigestAlgorithm and DigestValue are empty when the source
// reports no digest; PURL is empty when it reports none.
type Component struct {
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Path            string `json:"path,omitempty"`
	DigestAlgorithm string `json:"digest_algorithm,omitempty"`
	DigestValue     string `json:"digest_value,omitempty"`
	Origin          string `json:"origin,omitempty"`
	PURL            string `json:"purl,omitempty"`
}

// Report is one host's installed set as one source instance saw it.
//
// A normalizer fills ExternalID (when the document names its host),
// ObservedAt and Components. The frame fills the rest: Source is the
// instance, Identity comes from the host mapping alone, ReceivedAt is the
// arrival time, and Seq and PrevSHA256 are assigned by the store, which
// chains each report to the previous one from the same host and source.
type Report struct {
	Source     string      `json:"source"`
	ExternalID string      `json:"external_id"`
	Identity   string      `json:"identity"`
	ObservedAt time.Time   `json:"observed_at"`
	ReceivedAt time.Time   `json:"received_at"`
	Seq        int64       `json:"seq"`
	PrevSHA256 string      `json:"prev_sha256"`
	Components []Component `json:"components"`
}

// Attempt is evidence that a host reached for a registry directly.
// Ecosystem is empty when the destination does not say which one.
type Attempt struct {
	Source      string    `json:"source"`
	ExternalID  string    `json:"external_id"`
	Identity    string    `json:"identity"`
	ObservedAt  time.Time `json:"observed_at"`
	Destination string    `json:"destination"`
	Ecosystem   string    `json:"ecosystem,omitempty"`
	Detail      string    `json:"detail,omitempty"`
}

// Batch is what one normalized document yields.
type Batch struct {
	Reports  []Report
	Attempts []Attempt
}

// Source is one inventory collector. Every source declares its type name,
// its mode, its capabilities and a normalizer from its own format into the
// common model. A push source also implements PushSource and a pull source
// PullSource; the frame refuses a source whose mode and interface disagree.
type Source interface {
	Type() string
	Mode() Mode
	Capabilities() []Capability
	// Normalize maps one document in the source's own format into the
	// common model. externalID is the host the transport authenticated, or
	// "" when the document names its own hosts.
	Normalize(doc []byte, externalID string) (Batch, error)
}

// Route is one push route, mounted at
// /api/v1/inventory/sources/{instance}/{Path}.
type Route struct {
	Method string
	Path   string
	// MaxBody caps the request body; a larger one is refused with 413.
	MaxBody int64
	// Handler, when set, answers the route itself in place of the frame's
	// authenticate, normalize and ingest sequence. It is for a protocol
	// whose responses carry more than an ingest count, such as osquery's
	// enroll and config, and it authenticates the request on its own:
	// Authenticate is not called first.
	Handler func(w http.ResponseWriter, r *http.Request, env *RouteEnv)
}

// Principal is who a push request speaks for. Identity is set only when the
// source authenticated the host to a bodega identity by its own means, and
// the frame then writes the host mapping itself.
type Principal struct {
	ExternalID string
	Identity   string
}

// Token is a bodega API token as a push source sees it.
type Token struct {
	ID       string
	Scope    string
	Identity string // from an identity binding on the token; "" when none
}

// Credentials is how a push source checks a request against bodega's own
// tokens. The server implements it.
type Credentials interface {
	// Token resolves the request's credential to the token it names. It
	// returns an *AuthError for a missing, unknown or expired credential.
	Token(r *http.Request) (Token, error)
}

// PushSource is a source that receives reports on routes it registers. Those
// routes, and no others, are exempt from the admin_permit_cidr gate, so
// Authenticate is the only thing standing between them and the network.
type PushSource interface {
	Source
	Routes() []Route
	Authenticate(r *http.Request, creds Credentials) (Principal, error)
}

// Document is one unit a pull source fetched, in its own format.
type Document struct {
	ExternalID string
	Body       []byte
}

// PullSource is a source that polls a management API.
type PullSource interface {
	Source
	Poll(ctx context.Context) ([]Document, error)
}

// AuthError is a refusal a push source returns from Authenticate. Reason is
// the audit denial status it is recorded under.
type AuthError struct {
	Status  int
	Reason  string
	Message string
}

func (e *AuthError) Error() string { return e.Message }

// Factory builds one configured instance of a source type from its
// type-specific settings. It reads each key it accepts through settings;
// any key it does not read is refused as unknown.
type Factory func(instance string, settings *Settings) (Source, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register adds a source type. A source package calls it from init, and one
// blank import of that package is the registration line.
func Register(typeName string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[typeName]; dup {
		panic("inventory: source type registered twice: " + typeName)
	}
	registry[typeName] = f
}

// Types returns the registered source type names, sorted.
func Types() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func factory(typeName string) (Factory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[typeName]
	return f, ok
}

// Pull interval bounds. The floor keeps a typo from hammering a vendor API
// that rate-limits per tenant.
const (
	DefaultPullInterval = time.Hour
	MinPullInterval     = 5 * time.Minute
)

// Instance is one configured source.
type Instance struct {
	Name    string
	Enabled bool
	// Interval is the poll interval of a pull source; zero for push.
	Interval time.Duration
	// Retention is how long stored rows are kept; zero keeps them forever.
	Retention time.Duration
	Source    Source
}

// instanceName is the form a name must take to sit in a URL path segment
// and a log line without quoting.
var instanceName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Configure builds every instance in inventory_sources, sorted by name. The
// first error names the instance and the key at fault.
func Configure(raw map[string]config.InventorySource) ([]*Instance, error) {
	names := make([]string, 0, len(raw))
	for n := range raw {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*Instance, 0, len(names))
	for _, n := range names {
		inst, err := configureOne(n, raw[n])
		if err != nil {
			return nil, err
		}
		out = append(out, inst)
	}
	return out, nil
}

func configureOne(name string, raw config.InventorySource) (*Instance, error) {
	if !instanceName.MatchString(name) {
		return nil, fmt.Errorf("inventory_sources.%s: instance names are lowercase letters, digits, '.', '_' and '-', starting with a letter or digit", name)
	}
	s := &Settings{instance: name, raw: raw, used: map[string]bool{}}
	typeName, err := s.String("type", "")
	if err != nil {
		return nil, err
	}
	if typeName == "" {
		return nil, fmt.Errorf("inventory_sources.%s.type: required (registered types: %s)", name, strings.Join(Types(), ", "))
	}
	f, ok := factory(typeName)
	if !ok {
		return nil, fmt.Errorf("inventory_sources.%s.type: unknown source type %q (registered types: %s)", name, typeName, strings.Join(Types(), ", "))
	}
	enabled, err := s.Bool("enabled", false)
	if err != nil {
		return nil, err
	}
	retention, err := s.Duration("retention", 0)
	if err != nil {
		return nil, err
	}
	src, err := f(name, s)
	if err != nil {
		return nil, err
	}
	inst := &Instance{Name: name, Enabled: enabled, Retention: retention, Source: src}
	switch src.Mode() {
	case ModePush:
		if _, ok := src.(PushSource); !ok {
			return nil, fmt.Errorf("inventory_sources.%s: source type %q declares push mode and registers no routes", name, typeName)
		}
	case ModePull:
		if _, ok := src.(PullSource); !ok {
			return nil, fmt.Errorf("inventory_sources.%s: source type %q declares pull mode and cannot poll", name, typeName)
		}
		if inst.Interval, err = s.Duration("interval", DefaultPullInterval); err != nil {
			return nil, err
		}
		if inst.Interval < MinPullInterval {
			return nil, fmt.Errorf("inventory_sources.%s.interval: %s is below the %s minimum", name, inst.Interval, MinPullInterval)
		}
	default:
		return nil, fmt.Errorf("inventory_sources.%s: source type %q declares unknown mode %q", name, typeName, src.Mode())
	}
	if unknown := s.unused(); len(unknown) > 0 {
		return nil, fmt.Errorf("inventory_sources.%s.%s: unknown key for source type %q", name, unknown[0], typeName)
	}
	return inst, nil
}

// HasCapability reports whether src declares c.
func HasCapability(src Source, c Capability) bool {
	for _, have := range src.Capabilities() {
		if have == c {
			return true
		}
	}
	return false
}

// Settings is one instance's keys as a Factory reads them. Every getter
// marks its key as read, and Configure refuses any key nothing read, so a
// misspelled key fails the load rather than leaving a default in force.
type Settings struct {
	instance string
	raw      map[string]any
	used     map[string]bool
}

// Errorf returns an error naming the instance and key, for a Factory's own
// validation.
func (s *Settings) Errorf(key, format string, args ...any) error {
	return fmt.Errorf("inventory_sources.%s.%s: %s", s.instance, key, fmt.Sprintf(format, args...))
}

func (s *Settings) take(key string) (any, bool) {
	s.used[key] = true
	v, ok := s.raw[key]
	return v, ok && v != nil
}

// String reads a string key.
func (s *Settings) String(key, def string) (string, error) {
	v, ok := s.take(key)
	if !ok {
		return def, nil
	}
	str, isStr := v.(string)
	if !isStr {
		return "", s.Errorf(key, "want a string, got %v", v)
	}
	return str, nil
}

// Bool reads a boolean key.
func (s *Settings) Bool(key string, def bool) (bool, error) {
	v, ok := s.take(key)
	if !ok {
		return def, nil
	}
	b, isBool := v.(bool)
	if !isBool {
		return false, s.Errorf(key, "want true or false, got %v", v)
	}
	return b, nil
}

// Int64 reads a whole-number key.
func (s *Settings) Int64(key string, def int64) (int64, error) {
	v, ok := s.take(key)
	if !ok {
		return def, nil
	}
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case json.Number:
		parsed, err := n.Float64()
		if err != nil {
			return 0, s.Errorf(key, "want a whole number, got %v", v)
		}
		f = parsed
	default:
		return 0, s.Errorf(key, "want a whole number, got %v", v)
	}
	if f != float64(int64(f)) {
		return 0, s.Errorf(key, "want a whole number, got %v", v)
	}
	return int64(f), nil
}

// Duration reads a Go duration string such as "1h" or "30m".
func (s *Settings) Duration(key string, def time.Duration) (time.Duration, error) {
	str, err := s.String(key, "")
	if err != nil {
		return 0, err
	}
	if str == "" {
		return def, nil
	}
	d, err := time.ParseDuration(str)
	if err != nil || d < 0 {
		return 0, s.Errorf(key, "want a Go duration such as \"1h\", got %q", str)
	}
	return d, nil
}

func (s *Settings) unused() []string {
	var out []string
	for k := range s.raw {
		if !s.used[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func init() {
	config.ValidateInventorySources = func(raw map[string]config.InventorySource) error {
		_, err := Configure(raw)
		return err
	}
}
