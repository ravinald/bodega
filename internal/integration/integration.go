// Package integration is the frame every external admission check is built
// on. A type registers one Descriptor, and the config file's integrations
// block, the `bodega integration` CLI and the TUI's Integrations view are all
// generated from it, so the three cannot disagree about which keys a type
// takes or what a value may be.
//
// The frame owns what every type would otherwise repeat: validation, secret
// lookup, the per-ecosystem action, a per-purl answer cache, the timeout, and
// turning an outage into a recorded error rather than a silent pass.
package integration

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/policy"
)

// Cost is what an operator pays to turn a type on.
type Cost string

const (
	CostFree     Cost = "free"
	CostFreeTier Cost = "free-tier"
	CostPaid     Cost = "paid"
)

// Flag is what a flagged answer from a type says about the version.
type Flag string

const (
	// FlagMalware means the version was published to do harm, the fact an
	// OSV MAL- record states. No override or queue approval admits past it.
	FlagMalware Flag = "malware"
	// FlagRisk means the vendor judges the version risky against some
	// threshold. An override may admit past it.
	FlagRisk Flag = "risk"
)

// Kind is what a field's value is, and what input the TUI draws for it.
type Kind string

const (
	KindString   Kind = "string"
	KindInt      Kind = "int"
	KindDuration Kind = "duration"
	KindBool     Kind = "bool"
	KindEnum     Kind = "enum"
	KindURL      Kind = "url"
)

// Field is one setting a type takes.
type Field struct {
	Key   string
	Label string
	Help  string
	Kind  Kind
	// Default is the value's text form, as an operator would type it. Empty
	// means the field has no default.
	Default string
	// Options are the values an enum accepts.
	Options []string
	// Min and Max bound an int, or a duration in the duration's own units
	// via MinDuration and MaxDuration. Zero means unbounded.
	Min, Max                 int64
	MinDuration, MaxDuration time.Duration
	// Required refuses an instance with no value. A required secret is only
	// required of an enabled instance, so one can be added before its
	// credential exists.
	Required bool
	// Secret values never sit in the config file; see Secret.
	Secret bool
	// Validate is a type's own rule over a value that already has the right
	// kind, for what the kind cannot say.
	Validate func(v any) error
}

// Query is one version an integration is asked about. Ecosystem is a bodega
// package type.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

// PURL is the package URL a query names, the cache key and what a per-package
// vendor API is sent.
func (q Query) PURL() string {
	typ := q.Ecosystem
	if typ == "gomod" {
		typ = "golang"
	}
	return "pkg:" + typ + "/" + q.Name + "@" + q.Version
}

// Answer is what a vendor said about a query.
type Answer struct {
	// Flagged means the vendor names the version as a risk; the action
	// decides what that does.
	Flagged bool
	Reason  string
	// Quota is whatever the vendor reported about remaining requests, in its
	// own words, for `bodega integration test`. Empty when it said nothing.
	Quota string
	// Flag is what this hit means, when it means less than the descriptor's
	// Flags: a malware list that also carries telemetry rows answers those
	// FlagRisk. Empty means the descriptor's Flags. See EffectiveFlag.
	Flag Flag
}

// EffectiveFlag is what a flagged answer from d means. An answer can lower a
// malware type's hit to risk, never raise a risk type's hit to malware: the
// descriptor is what an operator read before enabling the instance, and a
// type that could make its hits unwaivable one by one would not be the type
// they enabled.
func (d *Descriptor) EffectiveFlag(a Answer) Flag {
	if d.Flags == FlagMalware && a.Flag != FlagRisk {
		return FlagMalware
	}
	return FlagRisk
}

// Checker is what a type builds from one configured instance. Lookup returns
// an error for every answer it could not get: a network failure, a timeout,
// a 5xx or a rate limit. The frame records each as an error under the
// instance's action, so a vendor outage never reads as a pass.
type Checker interface {
	Lookup(ctx context.Context, q Query) (Answer, error)
}

// BatchResult is one query's outcome in a batch: an answer, or the error
// Lookup would have returned for it.
type BatchResult struct {
	Answer Answer
	Err    error
}

// BatchChecker is a Checker whose vendor answers many queries in one
// request, for a vendor that meters requests rather than queries. The frame
// asks it about every uncached version of an admission at once, in chunks of
// at most BatchLimit, and asks Lookup about one version at a time everywhere
// else.
type BatchChecker interface {
	Checker
	// BatchLimit is the most queries one LookupBatch call may carry.
	BatchLimit() int
	// LookupBatch answers qs keyed by each query's PURL. A query missing
	// from the map is an error the frame names.
	LookupBatch(ctx context.Context, qs []Query) map[string]BatchResult
}

// Preparer is a Checker that has state to get ready before it can answer for
// an ecosystem, such as a list to download. The frame calls Prepare before it
// starts the instance's timeout, so the timeout bounds one query and not the
// preparation, which the type bounds itself. An error is recorded the way a
// Lookup error is.
type Preparer interface {
	Prepare(ctx context.Context, ecosystem string) error
}

// Descriptor declares one integration type.
type Descriptor struct {
	Type        string
	DisplayName string
	VendorURL   string
	Cost        Cost
	// Ecosystems are the bodega package types the integration can answer
	// for. Any other type is recorded not evaluated.
	Ecosystems []string
	// DataSent is one sentence saying what leaves the host per query, shown
	// before an instance is enabled.
	DataSent string
	// DefaultAction applies to an ecosystem with no integration_policy row:
	// warn, block or ignore.
	DefaultAction string
	// Flags is what a flagged answer means. Register refuses a type that
	// leaves it unset, so no type is overridable by omission.
	Flags  Flag
	Fields []Field
	// Probe is the well-known package `bodega integration test` asks about.
	Probe Query
	New   func(inst *Instance) (Checker, error)
}

// Field returns the descriptor's field for key.
func (d *Descriptor) Field(key string) (Field, bool) {
	for _, f := range d.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

// Covers reports whether the type answers for ecosystem.
func (d *Descriptor) Covers(ecosystem string) bool {
	return slices.Contains(d.Ecosystems, ecosystem)
}

// Common field keys every descriptor carries, added by Register when the
// type does not declare them itself.
const (
	KeyCacheTTL = "cache_ttl"
	KeyTimeout  = "timeout"
	KeyRevet    = "revet"
)

// commonFields are the fields every type carries. revet defaults on only for
// a free type: a sweep asks about every admitted version the instance
// covers, which on a metered API spends the quota admission needs.
func commonFields(cost Cost) []Field {
	return []Field{
		{Key: KeyCacheTTL, Label: "Cache TTL", Kind: KindDuration, Default: "1h",
			MinDuration: time.Minute, MaxDuration: 7 * 24 * time.Hour,
			Help: "How long an answer for one package version is reused before the integration is asked again."},
		{Key: KeyTimeout, Label: "Timeout", Kind: KindDuration, Default: "10s",
			MinDuration: time.Second, MaxDuration: 5 * time.Minute,
			Help: "How long one query may take before it is recorded as an error under the instance's action."},
		{Key: KeyRevet, Label: "Re-vet", Kind: KindBool, Default: strconv.FormatBool(cost == CostFree),
			Help: "Ask this instance again on re-vet. Each re-vet sweep asks it about every admitted version it covers that is not in its answer cache."},
	}
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*Descriptor{}
)

var kinds = []Kind{KindString, KindInt, KindDuration, KindBool, KindEnum, KindURL}

// reservedKeys are the instance keys the frame reads itself.
var reservedKeys = []string{"type", "enabled"}

// Register adds a type. A type package calls it from init. A duplicate type
// name, a field with no kind or a malformed descriptor panics, because each
// is a programming error the binary must not start with.
func Register(d Descriptor) {
	if d.Type == "" || d.New == nil {
		panic("integration: descriptor needs a type name and a constructor")
	}
	switch d.DefaultAction {
	case policy.ActionWarn, policy.ActionBlock, policy.ActionIgnore:
	default:
		panic(fmt.Sprintf("integration %s: default action %q is not warn, block or ignore", d.Type, d.DefaultAction))
	}
	switch d.Cost {
	case CostFree, CostFreeTier, CostPaid:
	default:
		panic(fmt.Sprintf("integration %s: cost %q is not free, free-tier or paid", d.Type, d.Cost))
	}
	switch d.Flags {
	case FlagMalware, FlagRisk:
	default:
		panic(fmt.Sprintf("integration %s: flags %q is not malware or risk", d.Type, d.Flags))
	}
	if strings.TrimSpace(d.DataSent) == "" {
		panic("integration " + d.Type + ": a descriptor must say what leaves the host")
	}
	for _, c := range commonFields(d.Cost) {
		if _, ok := d.Field(c.Key); !ok {
			d.Fields = append(d.Fields, c)
		}
	}
	seen := map[string]bool{}
	for _, f := range d.Fields {
		if f.Kind == "" {
			panic(fmt.Sprintf("integration %s: field %q has no kind", d.Type, f.Key))
		}
		if !slices.Contains(kinds, f.Kind) {
			panic(fmt.Sprintf("integration %s: field %q has unknown kind %q", d.Type, f.Key, f.Kind))
		}
		if f.Key == "" || seen[f.Key] || slices.Contains(reservedKeys, f.Key) || strings.HasSuffix(f.Key, secretFileSuffix) {
			panic(fmt.Sprintf("integration %s: field key %q is empty, repeated, reserved or ends in %s", d.Type, f.Key, secretFileSuffix))
		}
		if f.Kind == KindEnum && len(f.Options) == 0 {
			panic(fmt.Sprintf("integration %s: enum field %q has no options", d.Type, f.Key))
		}
		if f.Default != "" {
			if _, err := ParseText(f, f.Default); err != nil {
				panic(fmt.Sprintf("integration %s: field %q default: %v", d.Type, f.Key, err))
			}
		}
		seen[f.Key] = true
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[d.Type]; dup {
		panic("integration: type registered twice: " + d.Type)
	}
	registry[d.Type] = &d
}

// Types returns every registered descriptor, sorted by type name.
func Types() []*Descriptor {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]*Descriptor, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Type < out[b].Type })
	return out
}

// Lookup returns the descriptor for a type name.
func Lookup(typeName string) (*Descriptor, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	d, ok := registry[typeName]
	return d, ok
}

func typeNames() string {
	var names []string
	for _, d := range Types() {
		names = append(names, d.Type)
	}
	if len(names) == 0 {
		return "none registered"
	}
	return strings.Join(names, ", ")
}

// instanceName is the form an instance name takes: it is part of a check
// name, a credential file name and an environment variable.
var instanceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidInstanceName reports whether name is a legal instance name.
func ValidInstanceName(name string) bool { return instanceName.MatchString(name) }

// Instance is one validated integrations entry.
type Instance struct {
	Name       string
	Enabled    bool
	Descriptor *Descriptor
	// StateDir is the directory the instance may keep files in across
	// processes, <log_dir>/integrations/<name>. Empty when there is no
	// log_dir, and then a type keeps its state in memory only. The type
	// creates it when it first writes.
	StateDir string
	values   map[string]any
	// secretFiles are the <key>_file paths the entry names.
	secretFiles map[string]string
}

// CheckName is the name the instance's verdicts carry in an admission row.
func (i *Instance) CheckName() string { return CheckPrefix + i.Name }

// StateDir is where instance name keeps its files under logDir, or "" when
// logDir is "".
func StateDir(logDir, name string) string {
	if logDir == "" {
		return ""
	}
	return filepath.Join(logDir, "integrations", name)
}

// CheckPrefix starts every integration's check name.
const CheckPrefix = "integration:"

// String returns a string, url or enum value.
func (i *Instance) String(key string) string { s, _ := i.values[key].(string); return s }

// Int returns an int value.
func (i *Instance) Int(key string) int64 { n, _ := i.values[key].(int64); return n }

// Bool returns a bool value.
func (i *Instance) Bool(key string) bool { b, _ := i.values[key].(bool); return b }

// Duration returns a duration value.
func (i *Instance) Duration(key string) time.Duration {
	d, _ := i.values[key].(time.Duration)
	return d
}

// SecretFile is the <key>_file path the entry names for a secret field.
func (i *Instance) SecretFile(key string) string { return i.secretFiles[key] }

// Validate checks every instance in an integrations block. It is the one
// validator: config.Load, the CLI and the TUI all reach it.
func Validate(raw map[string]config.Integration) error {
	names := make([]string, 0, len(raw))
	for n := range raw {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, err := ValidateInstance(n, raw[n]); err != nil {
			return err
		}
	}
	return nil
}

// ValidateInstance checks one entry against its type's descriptor and returns
// it parsed. Every error names the instance, the key and what was expected.
// A disabled instance is held to the same rules, except that a required
// secret need not exist yet.
func ValidateInstance(name string, raw config.Integration) (*Instance, error) {
	where := func(key string) string {
		if key == "" {
			return "integrations." + name
		}
		return "integrations." + name + "." + key
	}
	if !instanceName.MatchString(name) {
		return nil, fmt.Errorf("%s: an instance name is lowercase letters, digits, '_' and '-', starting with a letter or digit, at most 63 characters", where(""))
	}
	typeName, ok := raw["type"].(string)
	if !ok || typeName == "" {
		return nil, fmt.Errorf("%s: required, a string naming the integration type (registered: %s)", where("type"), typeNames())
	}
	d, ok := Lookup(typeName)
	if !ok {
		return nil, fmt.Errorf("%s: unknown integration type %q (registered: %s)", where("type"), typeName, typeNames())
	}
	inst := &Instance{Name: name, Descriptor: d, values: map[string]any{}, secretFiles: map[string]string{}}
	if v, present := raw["enabled"]; present {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%s: want true or false, got %s", where("enabled"), describe(v))
		}
		inst.Enabled = b
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if slices.Contains(reservedKeys, k) {
			continue
		}
		v := raw[k]
		if base, isFile := strings.CutSuffix(k, secretFileSuffix); isFile {
			if f, ok := d.Field(base); ok && f.Secret {
				p, ok := v.(string)
				if !ok || !filepath.IsAbs(p) {
					return nil, fmt.Errorf("%s: want an absolute path to a file holding %s, got %s", where(k), base, describe(v))
				}
				inst.secretFiles[base] = p
				continue
			}
		}
		f, ok := d.Field(k)
		if !ok {
			return nil, fmt.Errorf("%s: unknown key for type %s (accepted: %s)", where(k), d.Type, acceptedKeys(d))
		}
		if f.Secret {
			return nil, fmt.Errorf("%s: a secret is never written in the config file; remove the key and run: bodega integration secret %s %s", where(k), name, k)
		}
		parsed, err := parseJSON(f, v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where(k), err)
		}
		inst.values[k] = parsed
	}
	for _, f := range d.Fields {
		if f.Secret {
			if f.Required && inst.Enabled {
				if _, _, err := inst.Secret(f.Key); err != nil {
					return nil, fmt.Errorf("%s: %w", where(f.Key), err)
				}
			}
			continue
		}
		if _, set := inst.values[f.Key]; set {
			continue
		}
		if f.Default == "" {
			if f.Required {
				return nil, fmt.Errorf("%s: required, %s", where(f.Key), expected(f))
			}
			continue
		}
		v, err := ParseText(f, f.Default)
		if err != nil {
			return nil, fmt.Errorf("%s: default: %w", where(f.Key), err)
		}
		inst.values[f.Key], _ = parseJSON(f, v)
	}
	return inst, nil
}

func acceptedKeys(d *Descriptor) string {
	keys := append([]string(nil), reservedKeys...)
	for _, f := range d.Fields {
		if f.Secret {
			keys = append(keys, f.Key+secretFileSuffix)
			continue
		}
		keys = append(keys, f.Key)
	}
	return strings.Join(keys, ", ")
}

// expected says what a field's value must be, for an error message.
func expected(f Field) string {
	switch f.Kind {
	case KindInt:
		switch {
		case f.Min != 0 && f.Max != 0:
			return fmt.Sprintf("want a whole number from %d to %d", f.Min, f.Max)
		case f.Min != 0:
			return fmt.Sprintf("want a whole number of at least %d", f.Min)
		case f.Max != 0:
			return fmt.Sprintf("want a whole number of at most %d", f.Max)
		}
		return "want a whole number"
	case KindDuration:
		s := `want a duration such as "30s", "6h" or "1d"`
		if f.MinDuration != 0 && f.MaxDuration != 0 {
			s += fmt.Sprintf(", from %s to %s", formatDuration(f.MinDuration), formatDuration(f.MaxDuration))
		}
		return s
	case KindBool:
		return "want true or false"
	case KindEnum:
		return "want one of " + strings.Join(f.Options, ", ")
	case KindURL:
		return "want an http or https URL with no user, password or fragment"
	}
	return "want a string"
}

// formatDuration writes a duration the way an operator types one: whole days
// as "7d", and no trailing zero units.
func formatDuration(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func describe(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(t)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	}
	return fmt.Sprintf("%T", v)
}

// parseJSON checks a value as the config file carries it and returns it in
// its Go form: string, int64, time.Duration or bool.
func parseJSON(f Field, v any) (any, error) {
	bad := func() error { return fmt.Errorf("%s, got %s", expected(f), describe(v)) }
	var out any
	switch f.Kind {
	case KindInt:
		n, ok := v.(float64)
		if !ok || n != float64(int64(n)) {
			return nil, bad()
		}
		i := int64(n)
		if (f.Min != 0 && i < f.Min) || (f.Max != 0 && i > f.Max) {
			return nil, bad()
		}
		out = i
	case KindBool:
		b, ok := v.(bool)
		if !ok {
			return nil, bad()
		}
		out = b
	case KindDuration:
		s, ok := v.(string)
		if !ok {
			return nil, bad()
		}
		d, err := config.ParseTTL(s)
		if err != nil || (f.MinDuration != 0 && d < f.MinDuration) || (f.MaxDuration != 0 && d > f.MaxDuration) {
			return nil, bad()
		}
		out = d
	case KindEnum:
		s, ok := v.(string)
		if !ok || !slices.Contains(f.Options, s) {
			return nil, bad()
		}
		out = s
	case KindURL:
		s, ok := v.(string)
		if !ok {
			return nil, bad()
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, bad()
		}
		out = s
	default:
		s, ok := v.(string)
		if !ok {
			return nil, bad()
		}
		out = s
	}
	if f.Validate != nil {
		if err := f.Validate(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ParseText turns a value typed at the CLI or in the TUI into the form the
// config file carries it in, so it can go through the same validator as a
// hand-written one.
func ParseText(f Field, s string) (any, error) {
	switch f.Kind {
	case KindInt:
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s, got %q", expected(f), s)
		}
		v := float64(n)
		_, err = parseJSON(f, v)
		return v, err
	case KindBool:
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true", "yes", "on", "1":
			return true, nil
		case "false", "no", "off", "0":
			return false, nil
		}
		return nil, fmt.Errorf("%s, got %q", expected(f), s)
	}
	_, err := parseJSON(f, s)
	return s, err
}

// FormatValue renders a value from the config file as text, the inverse of
// ParseText.
func FormatValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(t, 10)
	case time.Duration:
		return formatDuration(t)
	}
	return fmt.Sprint(v)
}

func init() { config.ValidateIntegrations = Validate }
