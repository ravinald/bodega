package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// AgeStore is the subset of audit.DB the age checker needs. Tests can supply
// an in-memory fake without pulling in the full DB.
type AgeStore interface {
	GetAgePolicy(ctx context.Context, ecosystem string) (audit.AgePolicy, error)
}

// agePublishers maps a registry type to the call that retrieves its upstream
// publish timestamp. It is the one source for both dispatch and the
// `bodega policy age set` validation, so an ecosystem gains age coverage and
// becomes settable in the same edit.
var agePublishers = map[string]func(*AgeChecker, context.Context, string, string) (time.Time, error){
	manifest.TypeNpm:      (*AgeChecker).npmPublishedAt,
	manifest.TypePypi:     (*AgeChecker).pypiPublishedAt,
	manifest.TypeGomod:    (*AgeChecker).gomodPublishedAt,
	manifest.TypeCargo:    (*AgeChecker).cratesPublishedAt,
	manifest.TypeRubygems: (*AgeChecker).gemPublishedAt,
	manifest.TypeMaven:    (*AgeChecker).mavenPublishedAt,
	manifest.TypeComposer: (*AgeChecker).composerPublishedAt,
	manifest.TypeOCI:      (*AgeChecker).ociPublishedAt,
}

// An oci tag is dated by bodega's registry when it resolves the tag, from the
// image config, and the time reaches the check on the entry: PublishedAt holds
// it and OCIDatedByKey in Metadata says which time it is. No registry answers
// a lookup by repository and tag with a time, so there is nothing for the
// check to ask.
const (
	OCIDatedByKey = "oci_dated_by"
	// OCIDatedByCreated is the image config's created field.
	OCIDatedByCreated = "created"
	// OCIDatedByFirstSeen is when bodega first resolved the tag to its digest,
	// used for a config with no created field or one at the Unix epoch, which
	// reproducible builds write and which would pass any age floor.
	OCIDatedByFirstSeen = "first_seen"
	// OCIDateErrorKey is why the registry could not date the tag.
	OCIDateErrorKey = "oci_date_error"
)

// LookupDatedEcosystems is AgeEcosystems less oci: the types whose publish
// time a lookup by name and version reads, which is what recording one on a
// manifest entry needs. An oci tag is dated only as bodega resolves it.
func LookupDatedEcosystems() []string {
	return slices.DeleteFunc(AgeEcosystems(), func(t string) bool { return t == manifest.TypeOCI })
}

// AgeEcosystems returns the registry types the age gate can date, sorted.
func AgeEcosystems() []string {
	out := make([]string, 0, len(agePublishers))
	for eco := range agePublishers {
		out = append(out, eco)
	}
	sort.Strings(out)
	return out
}

// AgeChecker rejects (or warns on) versions whose upstream publish timestamp
// is newer than the ecosystem's min-age policy. Ecosystems where an upstream
// timestamp isn't reliably retrievable (apt/binary/git/helm) have no entry in
// agePublishers, and `bodega policy age set` refuses one.
type AgeChecker struct {
	store AgeStore

	// Endpoints can be overridden in tests.
	NpmRegistry string
	PypiBase    string
	GoProxy     string
	CratesBase  string
	// RubygemsBase is rubygems_upstream: the versions API is served from the
	// same root as the gem files.
	RubygemsBase string
	// MavenBases is maven_upstreams, the repository roots the artifacts come
	// from in the order /maven/ asks them: a POM's response headers are the
	// only place a Maven repository dates a release.
	MavenBases []string
	// ComposerBase is composer_upstream: Packagist's p2 metadata dates every
	// version it lists.
	ComposerBase string

	// HTTP gets a conservative timeout so a slow upstream doesn't stall
	// admission.
	HTTP *http.Client
	Now  func() time.Time
}

func NewAgeChecker(store AgeStore) *AgeChecker {
	return &AgeChecker{
		store:        store,
		NpmRegistry:  "https://registry.npmjs.org",
		PypiBase:     "https://pypi.org",
		GoProxy:      "https://proxy.golang.org",
		CratesBase:   "https://crates.io",
		RubygemsBase: "https://rubygems.org",
		MavenBases:   []string{"https://repo.maven.apache.org/maven2", "https://plugins.gradle.org/m2"},
		ComposerBase: "https://repo.packagist.org",
		HTTP:         &http.Client{Timeout: 10 * time.Second},
		Now:          time.Now,
	}
}

func (c *AgeChecker) Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Result {
	if pm == nil || ve == nil {
		return Result{Check: "age", Action: ActionPass}
	}

	policy, err := c.store.GetAgePolicy(ctx, pm.Type)
	if errors.Is(err, audit.ErrAgePolicyNotFound) {
		return Result{Check: "age", Action: ActionPass}
	}
	if err != nil {
		return Result{Check: "age", Action: ActionWarn,
			Reason: "load age policy: " + err.Error()}
	}
	if policy.Action == ActionIgnore {
		return Result{Check: "age", Action: ActionPass}
	}

	// An entry that pins nothing cannot be dated. Every registry the gate reads
	// composes the version into the URL it queries, so an unpinned one resolves
	// to https://pypi.org/pypi/<dist>/*/json or its equivalent, which 404s and
	// warns: a correct entry reported as an import that half failed, once per
	// entry. "*" and "any" are the two spellings of unpinned beside the empty
	// string, and this passes all three for every ecosystem agePublishers
	// covers.
	//
	// A tag bodega's registry resolved is the exception: it names the image it
	// resolved to, dated on the entry, and "any" is as legal a tag as "latest".
	version := strings.TrimSpace(ve.Version)
	resolvedOCI := pm.Type == manifest.TypeOCI && (ve.Metadata[OCIDatedByKey] != "" || ve.Metadata[OCIDateErrorKey] != "")
	if !resolvedOCI && (version == "" || version == "*" || version == manifest.ConstraintAny) {
		return Result{Check: "age", Action: ActionPass,
			Reason: "version " + versionLabel(version) + " pins nothing; age gate is version-aware"}
	}

	var publishedAt time.Time
	datedBy := ""
	if pm.Type == manifest.TypeOCI {
		publishedAt, datedBy, err = ociDated(ve)
	} else {
		type dated struct {
			at  time.Time
			err error
		}
		d := SharedLookup(ctx, "age\x00"+pm.Type+"\x00"+pm.Name+"\x00"+version, func() dated {
			at, err := c.PublishedAt(ctx, pm.Type, pm.Name, version)
			return dated{at, err}
		})
		publishedAt, err = d.at, d.err
	}
	if err != nil {
		// Not having an upstream timestamp shouldn't fail-closed; short-circuit
		// with a warn that shows up in the audit but doesn't block.
		return Result{Check: "age", Action: ActionWarn,
			Reason: fmt.Sprintf("upstream timestamp unavailable for %s/%s@%s: %v", pm.Type, pm.Name, version, err)}
	}

	age := c.Now().Sub(publishedAt)
	minAge := time.Duration(policy.MinAgeSeconds) * time.Second
	if age >= minAge {
		r := Result{Check: "age", Action: ActionPass,
			Details: map[string]any{"published_at": publishedAt.UTC().Format(time.RFC3339), "age_seconds": int64(age.Seconds())}}
		if datedBy != "" {
			r.Details["dated_by"] = datedBy
			r.Reason = ociDatedPhrase(datedBy)
		}
		return r
	}

	r := Result{
		Check:  "age",
		Action: policy.Action,
		Reason: fmt.Sprintf("%s@%s is %s old, policy requires %s",
			pm.Name, version, ShortDuration(age), ShortDuration(minAge)),
		Details: map[string]any{
			"published_at":    publishedAt.UTC().Format(time.RFC3339),
			"age_seconds":     int64(age.Seconds()),
			"min_age_seconds": policy.MinAgeSeconds,
		},
	}
	if datedBy != "" {
		r.Details["dated_by"] = datedBy
		r.Reason += " (" + ociDatedPhrase(datedBy) + ")"
	}
	return r
}

// ociDated reads the time bodega's registry recorded for an oci tag off its
// entry, and which time it is.
func ociDated(ve *manifest.VersionEntry) (time.Time, string, error) {
	if msg := ve.Metadata[OCIDateErrorKey]; msg != "" {
		return time.Time{}, "", errors.New(msg)
	}
	by := ve.Metadata[OCIDatedByKey]
	if ve.PublishedAt == "" || (by != OCIDatedByCreated && by != OCIDatedByFirstSeen) {
		return time.Time{}, "", errors.New("an image is dated by bodega's registry when it resolves the tag, and this entry carries no time from it")
	}
	t, err := time.Parse(time.RFC3339Nano, ve.PublishedAt)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("the time recorded for the tag does not parse: %w", err)
	}
	return t, by, nil
}

// ociDatedPhrase says which time an oci verdict used.
func ociDatedPhrase(datedBy string) string {
	if datedBy == OCIDatedByFirstSeen {
		return "dated by when bodega first resolved the tag: the image config carries no created time, or the Unix epoch"
	}
	return "dated by the image config's created time"
}

// versionLabel names an unpinned version in a Reason, where the empty string
// would read as a truncated sentence.
func versionLabel(version string) string {
	if version == "" {
		return "(unset)"
	}
	return strconv.Quote(version)
}

// PublishedAt returns the upstream publish timestamp for a given ecosystem's
// package version. Returns an error for ecosystems without a known upstream
// timestamp endpoint. Fetch and import call it too, to record the time a
// hosted index publishes, so the gate and the index read the same field.
func (c *AgeChecker) PublishedAt(ctx context.Context, ecosystem, name, version string) (time.Time, error) {
	fn, ok := agePublishers[ecosystem]
	if !ok {
		return time.Time{}, fmt.Errorf("ecosystem %q has no upstream timestamp source", ecosystem)
	}
	return fn(c, ctx, name, version)
}

// AtUpstream returns a copy of c that reads typ's publish times from
// upstream, the registry root a manifest entry names in its url, so a recorded
// time is the one the registry the entry is fetched from publishes. An empty
// upstream keeps c's endpoint. Cargo is left alone: crates publish their times
// on an API host that neither the download url nor the index url names.
func (c *AgeChecker) AtUpstream(typ, upstream string) *AgeChecker {
	cp := *c
	upstream = strings.TrimRight(strings.TrimSpace(upstream), "/")
	if upstream == "" {
		return &cp
	}
	switch typ {
	case manifest.TypeNpm:
		cp.NpmRegistry = upstream
	case manifest.TypePypi:
		cp.PypiBase = upstream
	case manifest.TypeGomod:
		cp.GoProxy = upstream
	}
	return &cp
}

// UndatableVersion reports a version string that names no single release:
// unset, "*", "any", an npm dist-tag, or any oci tag, since a tag moves to
// whatever its publisher pushes next. No registry can date one, so a caller
// recording publish times passes it over rather than reporting a failure.
func UndatableVersion(typ, version string) bool {
	v := strings.TrimSpace(version)
	if v == "" || v == "*" || v == manifest.ConstraintAny || typ == manifest.TypeOCI {
		return true
	}
	return typ == manifest.TypeNpm && v == "latest"
}

// ociPublishedAt is the oci entry in agePublishers, which makes the gate
// settable for oci. The time itself arrives on the entry; see ociDated.
func (c *AgeChecker) ociPublishedAt(_ context.Context, name, tag string) (time.Time, error) {
	return time.Time{}, fmt.Errorf("oci %s:%s is dated by bodega's registry from the image config when it resolves the tag, not by a lookup", name, tag)
}

func (c *AgeChecker) npmPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	url := c.NpmRegistry + "/" + name
	var doc struct {
		Time map[string]string `json:"time"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return time.Time{}, err
	}
	ts, ok := doc.Time[version]
	if !ok {
		return time.Time{}, fmt.Errorf("npm packument has no time entry for %s", version)
	}
	return time.Parse(time.RFC3339Nano, ts)
}

func (c *AgeChecker) pypiPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	// PyPI JSON API: /pypi/{name}/{version}/json; upload_time_iso_8601 lives
	// under urls[].upload_time_iso_8601. Use the earliest.
	url := c.PypiBase + "/pypi/" + name + "/" + version + "/json"
	var doc struct {
		URLs []struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return time.Time{}, err
	}
	if len(doc.URLs) == 0 {
		return time.Time{}, fmt.Errorf("pypi response for %s@%s has no urls[]", name, version)
	}
	var earliest time.Time
	for _, u := range doc.URLs {
		if u.UploadTime == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, u.UploadTime)
		if err != nil {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return time.Time{}, fmt.Errorf("pypi response for %s@%s has no parseable upload_time", name, version)
	}
	return earliest, nil
}

func (c *AgeChecker) gomodPublishedAt(ctx context.Context, module, version string) (time.Time, error) {
	url := c.GoProxy + "/" + strings.ToLower(module) + "/@v/" + version + ".info"
	var doc struct {
		Time string `json:"Time"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return time.Time{}, err
	}
	if doc.Time == "" {
		return time.Time{}, fmt.Errorf("gomod .info has no Time field for %s@%s", module, version)
	}
	return time.Parse(time.RFC3339Nano, doc.Time)
}

func (c *AgeChecker) cratesPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	url := c.CratesBase + "/api/v1/crates/" + name + "/" + version
	var doc struct {
		Version struct {
			CreatedAt string `json:"created_at"`
		} `json:"version"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return time.Time{}, err
	}
	if doc.Version.CreatedAt == "" {
		return time.Time{}, fmt.Errorf("crates.io response has no version.created_at for %s@%s", name, version)
	}
	return time.Parse(time.RFC3339Nano, doc.Version.CreatedAt)
}

// gemPublishedAt reads created_at for one build from the versions API, which
// lists every version and platform of a gem in one document. version is the
// form a gem file names, "1.16.7-x86_64-linux" for a platform build and
// "1.16.7" for the "ruby" one: a Gem::Version never holds "-", so the first
// one opens the platform. A build the document does not list is an error, as
// crates.io's 404 for an unknown crate version is.
func (c *AgeChecker) gemPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	number, platform, ok := strings.Cut(version, "-")
	if !ok {
		platform = "ruby"
	}
	endpoint := c.RubygemsBase + "/api/v1/versions/" + neturl.PathEscape(name) + ".json"
	var doc []struct {
		Number    string `json:"number"`
		Platform  string `json:"platform"`
		CreatedAt string `json:"created_at"`
	}
	if err := c.getJSON(ctx, endpoint, &doc); err != nil {
		return time.Time{}, err
	}
	for _, v := range doc {
		if v.Number != number || v.Platform != platform {
			continue
		}
		if v.CreatedAt == "" {
			return time.Time{}, fmt.Errorf("rubygems versions API lists %s %s (%s) with no created_at", name, number, platform)
		}
		return time.Parse(time.RFC3339Nano, v.CreatedAt)
	}
	return time.Time{}, fmt.Errorf("rubygems versions API does not list %s %s for platform %s", name, number, platform)
}

// mavenPublishedAt reads the Last-Modified header of a version's POM. No
// document in a Maven repository dates a single release: maven-metadata.xml
// carries one lastUpdated for the whole artifact. Maven Central sets a POM's
// Last-Modified to the moment it was deployed, and a release path is never
// rewritten there, so the header is the deploy time. A POM answered without
// one cannot be dated and is an error, as crates.io's 404 for an unknown crate
// version is.
func (c *AgeChecker) mavenPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	p, ok := manifest.MavenArtifactPath(name, version)
	if ok {
		_, ok = manifest.ParseMavenPath(p)
	}
	if !ok {
		return time.Time{}, fmt.Errorf("maven %q at %q names no POM in the repository layout", name, version)
	}
	// Dated by the repository /maven/ would serve the POM from: the first to
	// answer it 200, whether or not its headers date it, a 404 passing to the
	// next. Any other failure is reported only if no later repository answers,
	// as the route reports it.
	var notFound, failed error
	for _, base := range c.MavenBases {
		t, answered, err := c.mavenPOMModified(ctx, base+"/"+p, name, version)
		switch {
		case answered:
			return t, err
		case errors.Is(err, errMavenPOMNotFound):
			if notFound == nil {
				notFound = err
			}
		case failed == nil:
			failed = err
		}
	}
	switch {
	case failed != nil:
		return time.Time{}, failed
	case notFound != nil:
		return time.Time{}, notFound
	}
	return time.Time{}, fmt.Errorf("maven %s %s: no maven upstream is configured to date it", name, version)
}

// composerPublishedAt reads a version's time from Packagist's p2 metadata,
// which lists every tagged release of a package in one document and every
// branch in a second, ~dev.json. A version is matched as listed, then with
// the optional leading "v" Composer itself ignores, so a manifest naming
// 5.4.0 finds Packagist's v5.4.0. A version the document does not list, or
// lists with no time, is an error, as a gem build the versions API does not
// list is.
func (c *AgeChecker) composerPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	name = strings.ToLower(name)
	file := name + ".json"
	if strings.HasPrefix(version, "dev-") || strings.HasSuffix(version, "-dev") {
		file = name + "~dev.json"
	}
	var doc json.RawMessage
	if err := c.getJSON(ctx, c.ComposerBase+"/p2/"+file, &doc); err != nil {
		return time.Time{}, err
	}
	listed, times, err := ComposerPublishTimes(doc, name)
	if err != nil {
		return time.Time{}, fmt.Errorf("packagist metadata for %s: %w", name, err)
	}
	match := ""
	for _, v := range listed {
		if v == version {
			match = v
			break
		}
		if match == "" && composerBareVersion(v) == composerBareVersion(version) {
			match = v
		}
	}
	if match == "" {
		return time.Time{}, fmt.Errorf("packagist metadata does not list %s %s", name, version)
	}
	t, ok := times[match]
	if !ok {
		return time.Time{}, fmt.Errorf("packagist metadata lists %s %s with no readable time", name, match)
	}
	return t, nil
}

// ComposerPublishTimes reads the versions a p2 document lists for name, in
// document order, and the time each carries. A version with no time, or one
// that does not parse, is listed and absent from times. Under
// "minified":"composer/2.0" a version carries only the keys that differ from
// the version before it and "__unset" removes one, so a time is inherited
// until a later version replaces or unsets it.
func ComposerPublishTimes(doc []byte, name string) (versions []string, times map[string]time.Time, err error) {
	var p2 struct {
		Minified string          `json:"minified"`
		Packages json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(doc, &p2); err != nil {
		return nil, nil, err
	}
	var pkgs map[string][]map[string]json.RawMessage
	// Packagist answers an unknown package with an empty "packages" array.
	if len(p2.Packages) > 0 && p2.Packages[0] == '{' {
		if err := json.Unmarshal(p2.Packages, &pkgs); err != nil {
			return nil, nil, err
		}
	}
	minified := p2.Minified == "composer/2.0"
	times = map[string]time.Time{}
	var stamp string
	for _, v := range pkgs[name] {
		if !minified {
			stamp = ""
		}
		if raw, ok := v["time"]; ok {
			stamp = ""
			_ = json.Unmarshal(raw, &stamp)
		}
		var version string
		if raw, ok := v["version"]; !ok || json.Unmarshal(raw, &version) != nil || version == "" {
			continue
		}
		versions = append(versions, version)
		if t, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
			times[version] = t
		}
	}
	return versions, times, nil
}

// composerBareVersion drops the "v" a Packagist tag may open with. Composer
// normalizes v1.2.3 and 1.2.3 to one version, and OSV's Packagist records and
// a manifest entry may each use either spelling.
func composerBareVersion(v string) string {
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// errMavenPOMNotFound is a repository answering 404 for a POM, which sends the
// lookup to the next repository rather than ending it.
var errMavenPOMNotFound = errors.New("the repository does not publish this POM")

// mavenPOMModified reads one repository's Last-Modified for a POM. answered
// reports a 200, after which no other repository is asked.
func (c *AgeChecker) mavenPOMModified(ctx context.Context, endpoint, name, version string) (t time.Time, answered bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return time.Time{}, false, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return time.Time{}, false, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return time.Time{}, false, fmt.Errorf("HEAD %s: HTTP 404: %w", endpoint, errMavenPOMNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, false, fmt.Errorf("HEAD %s: HTTP %d", endpoint, resp.StatusCode)
	}
	lm := resp.Header.Get("Last-Modified")
	if lm == "" {
		return time.Time{}, true, fmt.Errorf("HEAD %s answered with no Last-Modified, so %s %s has no deploy time", endpoint, name, version)
	}
	if t, err = http.ParseTime(lm); err != nil {
		return time.Time{}, true, fmt.Errorf("HEAD %s: Last-Modified %q: %w", endpoint, lm, err)
	}
	return t, true, nil
}

func (c *AgeChecker) getJSON(ctx context.Context, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// crates.io answers 403 to a request with no User-Agent.
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	// 32 MiB because the npm document is the whole packument, and a package
	// with a long release history (@types/node, aws-sdk) runs past 4 MiB:
	// truncated, it fails to parse and the version goes undated.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, into)
}

// ShortDuration renders a policy window the way an operator wrote it: "7d"
// rather than "168h0m0s". The startup banner, the doctor report and a gate's
// own reason string quote the same duration, so they render it the same way.
func ShortDuration(d time.Duration) string {
	days := int64(d / (24 * time.Hour))
	if days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int64(d / time.Hour)
	if hours >= 1 {
		return fmt.Sprintf("%dh", hours)
	}
	return d.Round(time.Second).String()
}
