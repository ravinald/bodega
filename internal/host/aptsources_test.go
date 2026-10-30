package host

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ubuntuResoluteSources is Ubuntu 26.04's stock ubuntu.sources: a comment
// header, then two stanzas, the second with its comment attached.
const ubuntuResoluteSources = `## Ubuntu distribution repository
##
## The following settings can be adjusted to configure which packages to use from Ubuntu.
## Mirror your choices (except for URIs and Suites) in the security section below to
## ensure timely security updates.
##
## See the sources.list(5) manual page for further settings.

Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: resolute resolute-updates resolute-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

## Ubuntu security updates. Aside from URIs and Suites,
## this should mirror your choices in the previous section.
Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: resolute-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
`

const legacySourcesList = `# deb cdrom:[Debian GNU/Linux 12]/ bookworm main
deb http://deb.debian.org/debian bookworm main
deb-src http://deb.debian.org/debian bookworm main

deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://security.debian.org/debian-security bookworm-security main
deb https://bodega.internal/apt/debian bookworm main`

// disableAll plans and applies the edit that disables every public source
// under root, and returns the edits.
func disableAll(t *testing.T, root string) []AptEdit {
	t.Helper()
	sources, err := AptSources(root)
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string][]int{}
	deb822 := map[string]bool{}
	var files []string
	for _, s := range sources {
		if s.Public == "" {
			continue
		}
		if _, ok := byFile[s.File]; !ok {
			files = append(files, s.File)
		}
		byFile[s.File] = append(byFile[s.File], s.Line)
		deb822[s.File] = s.Deb822
	}
	var edits []AptEdit
	for _, f := range files {
		e := DisableAptSources(f, deb822[f], byFile[f])
		back, err := ParseAptEdit(e.String())
		if err != nil || back.String() != e.String() {
			t.Fatalf("ParseAptEdit(%q) = %v, %v", e.String(), back, err)
		}
		if err := back.Apply(root); err != nil {
			t.Fatal(err)
		}
		edits = append(edits, back)
	}
	return edits
}

func readTree(t *testing.T, root string, paths []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		out[p] = string(b)
	}
	return out
}

// Every fixture disables to an OK apt-sources row and reverts byte for byte.
func TestAptEditDisablesWhatTheCheckFindsAndReverts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		disable int
		want    map[string]string
	}{
		{
			name:    "ubuntu 26.04",
			files:   map[string]string{"/etc/apt/sources.list.d/ubuntu.sources": ubuntuResoluteSources},
			disable: 2,
			want: map[string]string{"/etc/apt/sources.list.d/ubuntu.sources": strings.Replace(
				strings.Replace(ubuntuResoluteSources, "\nTypes: deb\n", "\nEnabled: no\nTypes: deb\n", 1),
				"section.\nTypes: deb\n", "section.\nEnabled: no\nTypes: deb\n", 1)},
		},
		{
			name: "debian 13 mirror+file",
			files: map[string]string{
				"/etc/apt/sources.list.d/debian.sources": debianSources,
				"/etc/apt/mirrors/debian.list":           "https://deb.debian.org/debian\n",
				"/etc/apt/mirrors/debian-security.list":  "https://deb.debian.org/debian-security\n",
			},
			disable: 2,
			want: map[string]string{"/etc/apt/sources.list.d/debian.sources": "Enabled: no\n" +
				strings.Replace(debianSources, "\n\nTypes:", "\n\nEnabled: no\nTypes:", 1)},
		},
		{
			name:    "legacy one-line",
			files:   map[string]string{"/etc/apt/sources.list": legacySourcesList},
			disable: 3,
			want: map[string]string{"/etc/apt/sources.list": `# deb cdrom:[Debian GNU/Linux 12]/ bookworm main
# deb http://deb.debian.org/debian bookworm main
# deb-src http://deb.debian.org/debian bookworm main

# deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://security.debian.org/debian-security bookworm-security main
deb https://bodega.internal/apt/debian bookworm main`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, tc.files)
			paths := slices.Sorted(func(yield func(string) bool) {
				for p := range tc.files {
					if !yield(p) {
						return
					}
				}
			})
			before := readTree(t, root, paths)
			assertFinding(t, checkAptSources(root, "linux"), StatusWarn)

			edits := disableAll(t, root)
			n := 0
			for _, e := range edits {
				n += len(e.Lines)
			}
			if n != tc.disable {
				t.Errorf("disabled %d sources (%v), want %d", n, edits, tc.disable)
			}
			for p, want := range tc.want {
				if got := readTree(t, root, []string{p})[p]; got != want {
					t.Errorf("%s after the edit:\n%s\nwant:\n%s", p, got, want)
				}
			}
			assertFinding(t, checkAptSources(root, "linux"), StatusOK)
			if again := disableAll(t, root); len(again) != 0 {
				t.Errorf("a host already disabled plans %v", again)
			}

			for _, e := range slices.Backward(edits) {
				if err := e.Revert(root); err != nil {
					t.Fatal(err)
				}
			}
			after := readTree(t, root, paths)
			for _, p := range paths {
				if after[p] != before[p] {
					t.Errorf("%s not restored byte for byte:\n%q\nwant:\n%q", p, after[p], before[p])
				}
			}
		})
	}
}

func TestAptSourcesClassifiesWhatItLeaves(t *testing.T) {
	root := writeTree(t, map[string]string{
		"/etc/apt/sources.list.d/ubuntu.sources":   strings.Replace(ubuntuResoluteSources, "Types: deb\n", "Types: deb\nEnabled: no\n", 1),
		"/etc/apt/sources.list.d/docker.sources":   "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: resolute\nComponents: stable\n",
		"/etc/apt/sources.list.d/explicit.sources": "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: resolute\nEnabled: yes\n",
	})
	sources, err := AptSources(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]AptSource{}
	for _, s := range sources {
		got[filepath.Base(s.File)+":"+s.URIs[0]] = s
	}
	if len(got) != 3 {
		t.Fatalf("sources = %+v, want docker, explicit and ubuntu's security stanza", sources)
	}
	if s := got["docker.sources:https://download.docker.com/linux/ubuntu"]; s.Public != "" || s.Line != 1 {
		t.Errorf("third-party stanza = %+v, want no public host", s)
	}
	if s := got["explicit.sources:http://archive.ubuntu.com/ubuntu"]; !s.SetsEnabled || s.Public != "archive.ubuntu.com" {
		t.Errorf("Enabled: yes stanza = %+v", s)
	}
	if s, ok := got["ubuntu.sources:http://security.ubuntu.com/ubuntu/"]; !ok || s.Line != 18 {
		t.Errorf("security stanza = %+v, want line 18; the Enabled: no stanza must not appear", s)
	}

	unread := writeTree(t, map[string]string{"/etc/apt/sources.list.d/debian.sources": debianSources})
	if _, err := AptSources(unread); err == nil || !strings.Contains(err.Error(), "/etc/apt/mirrors/debian.list") {
		t.Errorf("unreadable mirror list = %v, want it named", err)
	}
}

func TestParseAptEditRefusesOtherFiles(t *testing.T) {
	for _, s := range []string{
		"deb822 /etc/passwd 1",
		"deb822 /etc/apt/sources.list.d/../../shadow.sources 1",
		"deb822 /etc/apt/sources.list 1",
		"one-line /etc/apt/sources.list.d/ubuntu.sources 1",
		"one-line /etc/apt/sources.list 2,1",
		"one-line /etc/apt/sources.list 0",
		"deb822 /etc/apt/sources.list.d/ubuntu.sources",
	} {
		if e, err := ParseAptEdit(s); err == nil {
			t.Errorf("ParseAptEdit(%q) = %+v, want a refusal", s, e)
		}
	}
}

func TestAptEditRevertRefusesAChangedFile(t *testing.T) {
	root := writeTree(t, map[string]string{"/etc/apt/sources.list.d/ubuntu.sources": ubuntuResoluteSources})
	edits := disableAll(t, root)
	path := filepath.Join(root, "/etc/apt/sources.list.d/ubuntu.sources")
	b, _ := os.ReadFile(path)
	edited := strings.Replace(string(b), "Enabled: no\n", "Enabled: yes\n", 1)
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := edits[0].Revert(root); err == nil || !strings.Contains(err.Error(), "changed since doctor disabled it") {
		t.Errorf("revert of a hand-edited file = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != edited {
		t.Error("a refused revert wrote the file")
	}
}
