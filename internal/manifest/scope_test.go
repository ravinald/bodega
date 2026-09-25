package manifest

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestScopeToVersion(t *testing.T) {
	cases := []struct {
		name, key, wantVer, wantRef string
		want                        bool // nil-ness flipped: true = expect non-nil
	}{
		{
			name:    "match by Version",
			key:     "1.5.0",
			wantVer: "1.5.0",
			want:    true,
		},
		{
			name:    "match by Ref (git-style)",
			key:     "main",
			wantRef: "main",
			want:    true,
		},
		{"unknown version", "99.99.99", "", "", false},
		{"empty key", "", "", "", false},
	}

	pm := &PackageManifest{
		ConfigVersion: 1,
		Name:          "pkg",
		Type:          TypeNpm,
		Description:   "test",
		Versions: []VersionEntry{
			{Version: "1.5.0", Hidden: true},
			{Ref: "main"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pm.ScopeToVersion(tc.key)
			if (got != nil) != tc.want {
				t.Fatalf("got nil=%v, want nil=%v", got == nil, !tc.want)
			}
			if got == nil {
				return
			}
			if got.Name != pm.Name || got.Type != pm.Type || got.Description != pm.Description {
				t.Errorf("top-level fields not preserved: %+v", got)
			}
			if len(got.Versions) != 1 {
				t.Fatalf("versions = %d, want 1", len(got.Versions))
			}
			ve := got.Versions[0]
			if tc.wantVer != "" && ve.Version != tc.wantVer {
				t.Errorf("Version = %q, want %q", ve.Version, tc.wantVer)
			}
			if tc.wantRef != "" && ve.Ref != tc.wantRef {
				t.Errorf("Ref = %q, want %q", ve.Ref, tc.wantRef)
			}
		})
	}
}

func TestScopeToVersionNilReceiver(t *testing.T) {
	var pm *PackageManifest
	if got := pm.ScopeToVersion("1.0.0"); got != nil {
		t.Error("nil receiver should yield nil")
	}
}

// The whole reason ScopeToVersion returns a PackageManifest rather than a
// VersionEntry: the caller writes this as JSON and re-imports it elsewhere.
func TestScopeToVersionRoundTrip(t *testing.T) {
	pm := &PackageManifest{
		ConfigVersion: 1,
		Name:          "@example-corp/widget-cli",
		Type:          TypeNpm,
		Description:   "widget CLI",
		DepPolicy:     "direct",
		Versions: []VersionEntry{
			{Version: "1.4.2", Mode: ModeHosted},
			{Version: "1.5.0", Mode: ModeHosted, Hidden: true, Frozen: true},
		},
	}

	scoped := pm.ScopeToVersion("1.5.0")
	if scoped == nil {
		t.Fatal("ScopeToVersion returned nil")
	}

	data, err := json.Marshal(scoped)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round PackageManifest
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if round.ConfigVersion != 1 || round.Name != pm.Name || round.Type != pm.Type ||
		round.Description != pm.Description || round.DepPolicy != pm.DepPolicy {
		t.Errorf("top-level fields lost: %+v", round)
	}
	if len(round.Versions) != 1 || round.Versions[0].Version != "1.5.0" {
		t.Errorf("versions = %+v", round.Versions)
	}
	if !round.Versions[0].Hidden || !round.Versions[0].Frozen {
		t.Error("flags lost")
	}
}

// Scoping is pure — callers reuse the source elsewhere in the same request.
func TestScopeToVersionDoesNotMutate(t *testing.T) {
	pm := &PackageManifest{
		Versions: []VersionEntry{
			{Version: "4.17.21"},
			{Version: "4.17.22"},
		},
	}
	_ = pm.ScopeToVersion("4.17.21")
	if len(pm.Versions) != 2 {
		t.Errorf("source mutated: %+v", pm.Versions)
	}
}

// PublicURL drops the whole userinfo, username included, in every form a
// manifest url is written: with a scheme, scheme-relative, without one (where
// url.Parse finds no userinfo at all), git's scp form (which url.Parse
// refuses), and the forms only a browser or curl reads an authority into. An
// "@" past the authority is path, and stays; the query and fragment go whole.
func TestPublicURL(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://audit-user:audit-secret@private.example/FreeBSD:14:amd64/latest", "https://private.example/FreeBSD:14:amd64/latest"},
		{"https://ghp_token@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://u:p@ss@private.example/x", "https://private.example/x"},
		{"audit-user:audit-secret@private.example/x", "private.example/x"},
		{"git@github.com:org/repo.git", "github.com:org/repo.git"},
		{"https://registry.npmjs.org/@scope/pkg", "https://registry.npmjs.org/@scope/pkg"},
		{"https://private.example/x?who=a@b", "https://private.example/x"},
		{"https://private.example", "https://private.example"},
		{"", ""},
		{"//audit-user:audit-secret@private.example/x", "//private.example/x"},
		{"//audit-user@private.example/x", "//private.example/x"},
		{"//private.example/x@y", "//private.example/x@y"},
		{"https://audit-user@private.example", "https://private.example"},
		{"https:audit-user:audit-secret@private.example/x", "private.example/x"},
		{"https:\\\\audit-user:audit-secret@private.example/x", "https:\\\\private.example/x"},
		{"https:///audit-user:audit-secret@private.example/x", "https:///private.example/x"},
		{"https://private.example\\audit-user:audit-secret@evil.example/x", "https://evil.example/x"},
		{"  https://audit-user:audit-secret@private.example/x", "https://private.example/x"},
		{"ht\ttps://audit-user:audit-\nsecret@private.example/x", "https://private.example/x"},
		{"ssh://git@private.example:22/x", "ssh://private.example:22/x"},
		{"audit-user#audit-secret@private.example:repo.git", "private.example:repo.git"},
		{"audit-user?audit-secret@private.example:repo.git", "private.example:repo.git"},
		{"audit-user#audit-secret@private.example:org/repo.git", "private.example:org/repo.git"},
		{"[audit-user#audit-secret@private.example:22]:repo.git", "[private.example:22]:repo.git"},
		{"git@github.com:org/repo@v1.git", "github.com:org/repo@v1.git"},
		{"ssh://audit-user#audit-secret@private.example/repo.git", "ssh://private.example/repo.git"},
		{"ssh://audit-user?audit-secret@private.example/repo.git", "ssh://private.example/repo.git"},
		{"ssh://[audit-user@private.example:22]/repo.git", "ssh://[private.example:22]/repo.git"},
		{"ssh://audit-user%40audit-secret/repo.git", "ssh://audit-secret/repo.git"},
		{"ssh://audit-user%40private.example/repo.git", "ssh://private.example/repo.git"},
		{"https://private.example/x#frag@y", "https://private.example/x"},
		{"audit-user#audit-secret@private.example", "private.example"},
		{"private.example/x?who=a@b", "private.example/x"},
		{"https://private.example/x?token=audit-secret", "https://private.example/x"},
		{"https://private.example/x#access_token=audit-secret", "https://private.example/x"},
		{"https://audit-user@private.example/x?token=audit-secret", "https://private.example/x"},
		{"ht\ttps://private.example/x\n?token=audit-secret", "ht\ttps://private.example/x\n"},
	} {
		if got := PublicURL(tc.raw); got != tc.want {
			t.Errorf("PublicURL(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// A metadata value is cut only when it is written as a URL. Text that happens
// to hold "@", "?" or "#" is not an authority or a query and stays whole.
func TestPublicMetadataValue(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://audit-user:audit-secret@attest.example/e.json", "https://attest.example/e.json"},
		{"https://attest.example/e.json?token=audit-secret", "https://attest.example/e.json"},
		{"HTTPS://attest.example/e.json#audit-secret", "HTTPS://attest.example/e.json"},
		{"https:audit-user:audit-secret@attest.example/e.json", "attest.example/e.json"},
		{"//audit-user@attest.example/e.json", "//attest.example/e.json"},
		{"s3://bucket/e.json?versionId=audit-secret", "s3://bucket/e.json"},
		{"Jane Doe <jane@example.org>", "Jane Doe <jane@example.org>"},
		{"mailto:jane@example.org", "mailto:jane@example.org"},
		{"FreeBSD:14:amd64", "FreeBSD:14:amd64"},
		{"a C# binding, is it?", "a C# binding, is it?"},
		{"libc6 (>= 2.34)", "libc6 (>= 2.34)"},
		{"", ""},
	} {
		if got := PublicMetadataValue(tc.raw); got != tc.want {
			t.Errorf("PublicMetadataValue(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// Public copies: the store may hand the same pointer to the next reader, and a
// redaction written through it would strip the credential the next fetch needs.
func TestPublicLeavesTheManifestAlone(t *testing.T) {
	raw := "https://u:" + "p@private.example/x"
	pm := &PackageManifest{Versions: []VersionEntry{{Version: "1", URL: raw}}}
	if got := pm.Public(nil).Versions[0].URL; got != "https://private.example/x" {
		t.Errorf("Public() url = %q", got)
	}
	if pm.Versions[0].URL != raw {
		t.Errorf("Public() rewrote the manifest it was handed: %q", pm.Versions[0].URL)
	}
}

// publishedBinaryNames returns, for every binary entry of pm, the name the web
// UI links to in pm's public copy: filename when set, the url's last segment
// otherwise.
func publishedBinaryNames(pm *PackageManifest, key []byte) []string {
	var names []string
	for _, ve := range pm.Public(key).Versions {
		name := ve.Filename
		if name == "" {
			name = lastSegment(ve.URL)
		}
		names = append(names, name)
	}
	return names
}

var aliasTestKey = []byte("alias-test-key")

// Every binary entry's published download name resolves to that entry's own
// stored name, carries no userinfo, and is shared with no other entry of its
// version. The manifest holds each collision the shared unversioned directory
// allows: a redacted name another entry is explicitly stored under, two urls
// that redact alike, and an explicit filename already shaped like an alias.
func TestBinaryDownloadNamesResolveToTheirOwnEntry(t *testing.T) {
	pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: []VersionEntry{
		{Version: "1.0.0", URL: "https://u:" + "s@private.example"},
		{Version: "2.0.0", URL: "https://private.example/dl/tool"},
		{URL: "https://audit-user:" + "audit-secret@shared.example"},
		{URL: "https://public.example/other", Filename: "shared.example"},
		{URL: "https://other-user@shared.example"},
		{URL: "https://public.example/x", Filename: "shared.example~0123456789abcdef"},
		{URL: "audit-user#audit-secret@shared.example"},
		{URL: "https://q-user@shared.example?x=1"},
	}}
	seen := map[string]int{}
	for i, name := range publishedBinaryNames(pm, aliasTestKey) {
		ve := pm.Versions[i]
		for _, secret := range []string{"audit-user", "audit-secret", "other-user", "q-user", "u:s"} {
			if strings.Contains(name, secret) {
				t.Errorf("entry %d publishes %q in %q", i, secret, name)
			}
		}
		segment := name
		if parts := strings.Split(name, "/"); IsBinaryAlias(name) && len(parts) == 3 {
			segment = parts[2]
		}
		if strings.ContainsAny(segment, "?#/") {
			t.Errorf("entry %d publishes %q, which is neither one link segment nor an alias", i, name)
		}
		key := ve.Version + "/" + name
		if j, dup := seen[key]; dup {
			t.Errorf("entries %d and %d both publish %q", j, i, key)
		}
		seen[key] = i
		got, _, ok := pm.BinaryStoredFilename(aliasTestKey, ve.Version, name)
		if want := binaryStoredName(ve); !ok || got != want {
			t.Errorf("entry %d: published %q resolves to %q, %v, want its own %q", i, name, got, ok, want)
		}
	}
	if pm.Versions[2].Filename != "" {
		t.Errorf("Public() set a filename on the manifest it was handed")
	}
	for _, tc := range []struct {
		version, requested, want string
		ok                       bool
	}{
		{"1.0.0", "u:s@private.example", "u:s@private.example", true},
		{"1.0.0", "private.example", "private.example", true},
		{"", "shared.example", "shared.example", true},
		{"", "shared.example~0123456789abcdef", "shared.example~0123456789abcdef", true},
		{"1.0.0", "private.example~0123456789abcdef0123456789abcdef", "private.example~0123456789abcdef0123456789abcdef", true},
	} {
		got, _, ok := pm.BinaryStoredFilename(aliasTestKey, tc.version, tc.requested)
		if got != tc.want || ok != tc.ok {
			t.Errorf("BinaryStoredFilename(%q, %q) = %q, %v, want %q, %v", tc.version, tc.requested, got, ok, tc.want, tc.ok)
		}
	}
}

// A published alias keeps naming the entry it was published for across every
// manifest edit, or names nothing: removing, reordering and adding entries,
// including one whose explicit filename copies the alias, never hands it to
// another entry's stored name.
func TestBinaryDownloadNamesSurviveManifestEdits(t *testing.T) {
	entries := []VersionEntry{
		{URL: "https://first-user:" + "audit-secret@shared.example"},
		{URL: "https://second-user:" + "audit-secret@shared.example"},
		{URL: "https://public.example/other", Filename: "shared.example"},
		{Version: "1.0.0", URL: "https://third-user@shared.example"},
	}
	pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: entries}
	published := publishedBinaryNames(pm, aliasTestKey)

	edits := map[string][]VersionEntry{
		"reversed":   {entries[3], entries[2], entries[1], entries[0]},
		"added":      append([]VersionEntry{{URL: "https://new-user@shared.example"}}, entries...),
		"copied":     append([]VersionEntry{{URL: "https://public.example/copy", Filename: published[0]}}, entries[1:]...),
		"copied-url": append([]VersionEntry{{URL: "https://public.example/" + published[1]}}, entries[0], entries[2], entries[3]),
	}
	for i := range entries {
		edits["without "+strconv.Itoa(i)] = append(append([]VersionEntry{}, entries[:i]...), entries[i+1:]...)
	}
	for label, versions := range edits {
		edited := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: versions}
		for i, name := range published {
			ve := entries[i]
			got, _, ok := edited.BinaryStoredFilename(aliasTestKey, ve.Version, name)
			if ok && got != binaryStoredName(ve) {
				t.Errorf("%s: entry %d's link %q now resolves to %q, not its own %q", label, i, name, got, binaryStoredName(ve))
			}
		}
	}
}

// With no key there is nothing to tag an alias with that a reader could not
// reproduce, so the name published resolves nowhere rather than to a guess,
// and once a key is in force it still reaches no entry: a key transition never
// turns an alias into a request for a stored name, even one stored under the
// alias's own spelling.
func TestBinaryDownloadNamesFailClosedAcrossKeys(t *testing.T) {
	entries := []VersionEntry{{URL: "https://audit-user:" + "audit-secret@shared.example"}}
	pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: entries}
	unkeyed := publishedBinaryNames(pm, nil)[0]
	keyed := publishedBinaryNames(pm, aliasTestKey)[0]
	if !IsWithheldBinaryAlias(unkeyed) || IsWithheldBinaryAlias(keyed) {
		t.Errorf("withheld: unkeyed %q = %v, keyed %q = %v; want only the unkeyed name withheld",
			unkeyed, IsWithheldBinaryAlias(unkeyed), keyed, IsWithheldBinaryAlias(keyed))
	}
	for _, name := range []string{unkeyed, keyed} {
		if strings.Contains(name, "audit") {
			t.Fatalf("published %q", name)
		}
		squatted := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: append(entries[:1:1],
			VersionEntry{URL: "https://public.example/copy", Filename: name})}
		for _, key := range [][]byte{nil, []byte("rotated-key")} {
			if got, _, ok := squatted.BinaryStoredFilename(key, "", name); ok {
				t.Errorf("key %q: %q resolves to %q", key, name, got)
			}
		}
	}
	if got, _, ok := pm.BinaryStoredFilename(aliasTestKey, "", keyed); !ok || got != binaryStoredName(entries[0]) {
		t.Errorf("under its own key %q resolves to %q, %v", keyed, got, ok)
	}
}

// The display half of an alias comes from the public url, never the raw one,
// however the stored name is spelled: a stored name ending in something shaped
// like a tag is still the raw authority, userinfo and all.
func TestBinaryDownloadNamesNeverDisplayTheRawURL(t *testing.T) {
	forged := "~" + strings.Repeat("0123456789abcdef", 2)
	pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: []VersionEntry{
		{Version: "1", URL: "http://audit-user:" + "audit-secret@127.0.0.1:8080#~0123456789abcdef"},
		{Version: "2", URL: "http://audit-user:" + "audit-secret@127.0.0.1:8080#" + forged},
		{Version: "3", URL: "http://audit-user:" + "audit-secret@127.0.0.1:8080?x=" + forged},
		{Version: "4", URL: "audit-user:" + "audit-secret@127.0.0.1" + forged},
	}}
	for i, name := range publishedBinaryNames(pm, aliasTestKey) {
		for _, secret := range []string{"audit-user", "audit-secret"} {
			if strings.Contains(name, secret) {
				t.Errorf("entry %d publishes %q in %q", i, secret, name)
			}
		}
		ve := pm.Versions[i]
		if got, _, ok := pm.BinaryStoredFilename(aliasTestKey, ve.Version, name); !ok || got != binaryStoredName(ve) {
			t.Errorf("entry %d: published %q resolves to %q, %v, want its own stored name", i, name, got, ok)
		}
	}
}

// A stored name is served as itself however it is spelled: a link saved
// before aliases existed, or printed by a TUI with no pepper, requests it by
// that name. The read API publishes each entry by its alias, which resolves to
// that entry's stored name. An alias bodega
// minted and an operator then copied into an explicit filename is not a
// stored name the route can reach: the alias keeps reaching the entry it was
// minted for, that entry's absence is a 404 rather than the copy's bytes, and
// the copy is published under an alias of its own.
func TestBinaryStoredNamesShapedLikeAliases(t *testing.T) {
	pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: []VersionEntry{
		{Version: "1.0.0", URL: "https://public.example/tool~0123456789abcdef"},
		{Version: "1.0.0", URL: "https://public.example/dl", Filename: "tool~" + strings.Repeat("0123456789abcdef", 2)},
		{Version: "1.0.0", URL: "https://public.example/dl", Filename: "~"},
		{Version: "1.0.0", URL: "https://audit-user@private.example"},
	}}
	names := publishedBinaryNames(pm, aliasTestKey)
	for i := range 3 {
		stored := binaryStoredName(pm.Versions[i])
		if got, entry, ok := pm.BinaryStoredFilename(aliasTestKey, "1.0.0", names[i]); !IsBinaryAlias(names[i]) || !ok || got != stored || entry == nil {
			t.Errorf("entry %d publishes %q, resolving to %q, %v; want an alias of %q", i, names[i], got, ok, stored)
		}
		if got, _, ok := pm.BinaryStoredFilename(aliasTestKey, "1.0.0", stored); !ok || got != stored {
			t.Errorf("stored name %q resolves to %q, %v", stored, got, ok)
		}
	}

	minted := names[3]
	if !IsBinaryAlias(minted) {
		t.Fatalf("entry 3 publishes %q, not an alias", minted)
	}
	copied := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: append(pm.Versions,
		VersionEntry{Version: "1.0.0", URL: "https://public.example/copy", Filename: minted})}
	if got, _, ok := copied.BinaryStoredFilename(aliasTestKey, "1.0.0", minted); !ok || got != binaryStoredName(pm.Versions[3]) {
		t.Errorf("minted %q resolves to %q, %v, want the entry it was minted for", minted, got, ok)
	}
	copyName := publishedBinaryNames(copied, aliasTestKey)[4]
	if copyName == minted {
		t.Fatalf("the copy publishes the alias it copied")
	}
	if got, _, ok := copied.BinaryStoredFilename(aliasTestKey, "1.0.0", copyName); !ok || got != minted {
		t.Errorf("the copy's own alias %q resolves to %q, %v", copyName, got, ok)
	}
	copied.Versions = append(copied.Versions[:3:3], copied.Versions[4])
	if got, _, ok := copied.BinaryStoredFilename(aliasTestKey, "1.0.0", minted); ok {
		t.Errorf("minted %q resolves to %q after its entry is gone", minted, got)
	}
}

// An alias identifies its entry's backend as well as its key: two entries of
// one version sharing a stored name on different backends get different
// aliases, each resolves to its own entry, and moving an entry to another
// backend retires the alias it had. "default" and the empty name are one
// backend.
func TestBinaryAliasBindsTheBackend(t *testing.T) {
	const authority = "u:p@host"
	a := VersionEntry{Version: "1.0.0", URL: "https://" + authority}
	b := VersionEntry{Version: "1.0.0", URL: "https://other/x", Filename: authority, Storage: "other"}
	pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: []VersionEntry{b, a}}
	aliasA := pm.binaryAliasName(aliasTestKey, a)
	aliasB := pm.binaryAliasName(aliasTestKey, b)
	if aliasA == aliasB {
		t.Fatalf("entries on two backends share the alias %q", aliasA)
	}
	for alias, want := range map[string]string{aliasA: "", aliasB: "other"} {
		_, entry, ok := pm.BinaryStoredFilename(aliasTestKey, "1.0.0", alias)
		if !ok || entry == nil || entry.Storage != want {
			t.Errorf("alias %q resolved to %+v, %v, want the entry on %q", alias, entry, ok, want)
		}
	}
	moved := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: []VersionEntry{{Version: "1.0.0", URL: a.URL, Storage: "other"}}}
	if _, _, ok := moved.BinaryStoredFilename(aliasTestKey, "1.0.0", aliasA); ok {
		t.Error("an alias survives its entry moving backend")
	}
	spelled := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: []VersionEntry{{Version: "1.0.0", URL: a.URL, Storage: "default"}}}
	if _, _, ok := spelled.BinaryStoredFilename(aliasTestKey, "1.0.0", aliasA); !ok {
		t.Error(`Storage "default" gives a different alias from the empty name`)
	}
}

// BinaryLinkName links by alias whenever it has a key, and with none by
// stored name exactly when the route reads that spelling back as the entry's
// own object on its own backend.
func TestBinaryLinkNameAgreesWithTheRoute(t *testing.T) {
	const authority = "u:p@h"
	for _, tc := range []struct {
		label       string
		versions    []VersionEntry
		typeBackend string
		literal     string
	}{
		{"plain", []VersionEntry{{Version: "1.0.0", URL: "https://h/tool"}}, "", "tool/1.0.0/tool"},
		{"no version", []VersionEntry{{URL: "https://h/tool"}}, "", "tool/tool"},
		{"tilde name, no version", []VersionEntry{{URL: "https://h/tool", Filename: "~/tool"}}, "", "tool/~/tool"},
		{"tilde name, no version, type backend spelled default", []VersionEntry{{URL: "https://h/tool", Filename: "~/tool"}}, "default", "tool/~/tool"},
		{"tilde name, no version, recorded on another backend", []VersionEntry{{URL: "https://h/tool", Filename: "~/tool", Storage: "other"}}, "", ""},
		{"tilde name, no version, type backend elsewhere", []VersionEntry{{URL: "https://h/tool", Filename: "~/tool"}}, "bulk", ""},
		{"tilde name, no version, on the type backend", []VersionEntry{{URL: "https://h/tool", Filename: "~/tool", Storage: "bulk"}}, "bulk", "tool/~/tool"},
		{"userinfo authority", []VersionEntry{{Version: "1.0.0", URL: "https://" + authority}}, "", "tool/1.0.0/" + authority},
		{"copied alias", []VersionEntry{{Version: "1.0.0", URL: "https://h/x", Filename: "~/" + strings.Repeat("0", 32) + "/x"}}, "", ""},
		{"nested name", []VersionEntry{{Version: "1.0.0", URL: "https://h/x", Filename: "a/b"}}, "", ""},
		{"query mark", []VersionEntry{{Version: "1.0.0", URL: "https://h/x", Filename: "a?b"}}, "", ""},
		{"percent", []VersionEntry{{Version: "1.0.0", URL: "https://h/x", Filename: "a%2eb"}}, "", ""},
		{"dot dot", []VersionEntry{{Version: "1.0.0", URL: "https://h/x", Filename: "a..b"}}, "", ""},
		{"earlier entry on the same backend", []VersionEntry{{Version: "1.0.0", URL: "https://h/one"}, {Version: "1.0.0", URL: "https://h/tool"}}, "", "tool/1.0.0/tool"},
		{"earlier entry on another backend", []VersionEntry{{Version: "1.0.0", URL: "https://h/one", Storage: "other"}, {Version: "1.0.0", URL: "https://h/tool"}}, "", ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: tc.versions}
			i := len(tc.versions) - 1
			keyless, ok := pm.BinaryLinkName(nil, tc.typeBackend, i)
			switch {
			case tc.literal != "" && (!ok || keyless != tc.literal):
				t.Fatalf("BinaryLinkName with no key = %q, %v, want %q", keyless, ok, tc.literal)
			case tc.literal == "" && ok:
				t.Fatalf("BinaryLinkName with no key = %q, want no link", keyless)
			}
			link, ok := pm.BinaryLinkName(aliasTestKey, tc.typeBackend, i)
			if !ok {
				t.Fatal("BinaryLinkName with a key offers no link")
			}
			if strings.Contains(link, "..") {
				t.Errorf("link %q is refused by the route's path check", link)
			}
			pkg, version, name := BinaryPathIdentity(link)
			if pkg != "tool" || version != tc.versions[i].Version || !IsBinaryAlias(name) {
				t.Fatalf("link %q routes as %q %q %q, not an alias", link, pkg, version, name)
			}
			stored, entry, ok := pm.BinaryStoredFilename(aliasTestKey, version, name)
			if !ok || entry == nil || stored != binaryStoredName(tc.versions[i]) || entry.Storage != tc.versions[i].Storage {
				t.Errorf("link %q resolves to %q %+v %v", link, stored, entry, ok)
			}
		})
	}
}
