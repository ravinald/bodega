package aptsources

import (
	"strings"
	"testing"
)

// TestRenderMatrix walks the four dimensions an operator can be standing in:
// signed or not, public_url set or not, TLS terminated here or at a proxy, and
// the default suite or another one. Three of these sixteen shipped a wrong
// line, and each was wrong on a different axis, so the reported cell is not
// the unit of coverage.
func TestRenderMatrix(t *testing.T) {
	const proxied = "https://bodega.example.com"

	for _, signed := range []bool{true, false} {
		for _, publicURL := range []string{"", proxied} {
			// "https" is TLS terminating on this listener; "http" is a
			// loopback listener with a proxy in front.
			for _, local := range []string{"https", "http"} {
				for _, suite := range []string{"noble", "jammy"} {
					st := State{
						PublicURL:   publicURL,
						LocalScheme: local,
						Suites:      []string{suite},
						Signed:      signed,
					}
					got := Render(st)

					wantBase := publicURL
					if wantBase == "" {
						wantBase = local + "://" + PlaceholderHost
					}
					wantURI := wantBase + "/apt/"

					if got.URI != wantURI {
						t.Errorf("signed=%v public=%q local=%q: URI = %q, want %q",
							signed, publicURL, local, got.URI, wantURI)
					}
					if got.Suite != suite {
						t.Errorf("suite = %q, want %q", got.Suite, suite)
					}
					if !strings.Contains(got.Deb822, "Suites: "+suite) {
						t.Errorf("deb822 does not name suite %q:\n%s", suite, got.Deb822)
					}
					if !strings.Contains(got.OneLine, " "+suite+" "+Component) {
						t.Errorf("one-line does not name suite %q: %q", suite, got.OneLine)
					}

					// Signing decides the form, and only signing. A signed
					// instance handed [trusted=yes] is the defect that turned
					// verification off permanently for that source.
					switch {
					case signed:
						if !strings.Contains(got.Deb822, "Signed-By: "+ClientKeyringPath) {
							t.Errorf("signed instance emits no Signed-By:\n%s", got.Deb822)
						}
						if strings.Contains(got.Deb822, "trusted") || strings.Contains(got.OneLine, "trusted") {
							t.Errorf("signed instance emits trusted=yes:\n%s\n%s", got.Deb822, got.OneLine)
						}
						if !hasNote(got, SignedNote) {
							t.Errorf("signed instance carries no keyring note: %v", got.Notes)
						}
					default:
						if !strings.Contains(got.Deb822, "Trusted: yes") {
							t.Errorf("unsigned instance emits no Trusted: yes:\n%s", got.Deb822)
						}
						if !strings.Contains(got.OneLine, "[trusted=yes]") {
							t.Errorf("unsigned one-line has no [trusted=yes]: %q", got.OneLine)
						}
						if strings.Contains(got.Deb822, "Signed-By") {
							t.Errorf("unsigned instance emits Signed-By:\n%s", got.Deb822)
						}
						if !hasNote(got, UnsignedNote) {
							t.Errorf("unsigned instance carries no consequence beside the line: %v", got.Notes)
						}
					}

					// A placeholder that does not say it is one reads as an
					// address, which is how a proxied deployment's operator
					// copied http://<listener> out of the pane.
					if publicURL == "" && !hasNote(got, UnknownURLNote) {
						t.Errorf("placeholder host carries no note: %v", got.Notes)
					}
					if publicURL != "" && hasNote(got, UnknownURLNote) {
						t.Errorf("public_url is set but the placeholder note fired: %v", got.Notes)
					}
					// The trust-store note follows the scheme a client
					// speaks, not the one this listener answers on, so
					// a proxied http listener still carries it.
					if want := strings.HasPrefix(wantURI, "https://"); hasNote(got, TrustStoreNote) != want {
						t.Errorf("signed=%v public=%q local=%q: trust-store note = %v, want %v",
							signed, publicURL, local, !want, want)
					}

					if publicURL != "" && strings.Contains(got.OneLine, PlaceholderHost) {
						t.Errorf("public_url is set but the line names the placeholder: %q", got.OneLine)
					}
				}
			}
		}
	}
}

// A proxy in front is the case the TLS pair cannot describe: both keys are
// empty on bodega and every client still speaks https.
func TestPublicURLBeatsLocalScheme(t *testing.T) {
	got := Render(State{
		PublicURL:   "https://bodega.example.com/",
		LocalScheme: "http",
		Suites:      []string{"noble"},
	})
	if !strings.HasPrefix(got.URI, "https://bodega.example.com/apt/") {
		t.Fatalf("URI = %q, want the public URL, not the local listener", got.URI)
	}
	if strings.Contains(got.URI, "//apt") {
		t.Fatalf("URI = %q: trailing slash on public_url was not trimmed", got.URI)
	}
}

// Several suites go on one Suites: line; the one-line form carries one and
// takes the first.
func TestMultipleSuites(t *testing.T) {
	got := Render(State{PublicURL: "https://b.example.com", Suites: []string{"noble", "jammy", ""}})
	if !strings.Contains(got.Deb822, "Suites: noble jammy") {
		t.Errorf("deb822 = %q, want both suites on one line", got.Deb822)
	}
	if got.Suite != "noble" || !strings.Contains(got.OneLine, " noble main") {
		t.Errorf("one-line = %q, want the first suite", got.OneLine)
	}
}

// No suite served at all means apt_codename resolved to nothing. A placeholder
// is the only honest answer; a literal would be the web page's defect again.
func TestNoSuitesRendersPlaceholder(t *testing.T) {
	got := Render(State{PublicURL: "https://b.example.com"})
	if got.Suite != PlaceholderSuite {
		t.Fatalf("suite = %q, want %q", got.Suite, PlaceholderSuite)
	}
}

// A mirrored suite carries neither trust option. The upstream signature is
// intact and the client already holds the distro key, so [trusted=yes] would
// discard a working check and Signed-By: would point at a key that signed
// nothing here. Both are wrong in a way that survives into an Ansible
// template, which is why signing state does not reach this branch.
func TestMirroredSuiteCarriesNeitherTrustOption(t *testing.T) {
	for _, signed := range []bool{true, false} {
		got := Render(State{
			PublicURL: "https://bodega.example.com",
			Suites:    []string{"noble"},
			Signed:    signed,
			Mirrored:  true,
		})
		if strings.Contains(got.Deb822, "Trusted") || strings.Contains(got.OneLine, "trusted") {
			t.Errorf("signed=%v: mirrored suite emits a trust override:\n%s\n%s", signed, got.Deb822, got.OneLine)
		}
		if strings.Contains(got.Deb822, "Signed-By") || strings.Contains(got.OneLine, "signed-by") {
			t.Errorf("signed=%v: mirrored suite names bodega's keyring:\n%s\n%s", signed, got.Deb822, got.OneLine)
		}
		if !got.Mirrored || !got.Signed {
			t.Errorf("signed=%v: mirrored=%v signed=%v, want both true — upstream signs it", signed, got.Mirrored, got.Signed)
		}
		if !hasNote(got, MirroredNote) {
			t.Errorf("signed=%v: no note explaining what verifies a mirrored suite: %v", signed, got.Notes)
		}
		if got.OneLine != "deb https://bodega.example.com/apt/ noble main" {
			t.Errorf("one-line = %q, want a bare deb line", got.OneLine)
		}
	}
}

func hasNote(s Sources, want string) bool {
	for _, n := range s.Notes {
		if n == want {
			return true
		}
	}
	return false
}
