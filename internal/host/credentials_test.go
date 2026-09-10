package host

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scratchHome is a home directory with helm's two path overrides cleared, so
// a developer who exports HELM_REPOSITORY_CONFIG or XDG_CONFIG_HOME does not
// send a test write outside the scratch tree.
func scratchHome(t *testing.T) string {
	t.Helper()
	t.Setenv("HELM_REPOSITORY_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	return t.TempDir()
}

func testBase(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("https://bodega.internal")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	return u
}

// writeAll drives every target into a scratch home and returns what landed,
// keyed by path. The apt target is skipped: it reads /etc/apt/auth.conf.d and
// nowhere else, so a test that redirected it would assert about a path apt
// will never open.
func writeAll(t *testing.T, home, token string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, target := range CredentialTargets(home) {
		if !strings.HasPrefix(target.Path, home) {
			continue
		}
		if _, err := WriteCredential(target, testBase(t), token); err != nil {
			t.Fatalf("%s: %v", target.Client, err)
		}
		data, err := os.ReadFile(target.Path)
		if err != nil {
			t.Fatalf("%s: read back %s: %v", target.Client, target.Path, err)
		}
		got[target.Path] = string(data)
	}
	return got
}

// Requirement 6: every one of the eight clients has a file, and the credential
// reaches it. Eight clients, five files — pip, go, git and curl/wget all read
// ~/.netrc, and writing four copies of one secret would be four things to
// rotate.
func TestEveryClientHasACredentialTarget(t *testing.T) {
	home := scratchHome(t)
	targets := CredentialTargets(home)

	want := []string{"apt", "pip", "npm", "gomod", "cargo", "helm", "git", "binary"}
	if len(targets) != len(want) {
		t.Fatalf("%d credential targets, want %d (one per route bodega serves)", len(targets), len(want))
	}
	for i, name := range want {
		if targets[i].Client != name {
			t.Fatalf("target %d is %q, want %q", i, targets[i].Client, name)
		}
		if targets[i].Path == "" || targets[i].body == nil {
			t.Fatalf("%s has no file or nothing to write to it", name)
		}
		if targets[i].Mode != 0o600 {
			t.Fatalf("%s writes mode %v; every one of these holds a secret", name, targets[i].Mode)
		}
	}

	const tok = "bodega_ak_deadbeef"
	files := writeAll(t, home, tok)
	for path, body := range files {
		if !strings.Contains(body, tok) {
			t.Fatalf("%s does not carry the token", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is mode %v, want 0600", path, info.Mode().Perm())
		}
	}

	// apt's file is netrc with the machine line annotated by scheme. Bare, apt
	// matches the host and then declines to send the credential over plain
	// HTTP, so the entry is inert on every plaintext deployment.
	apt := targetFor(t, home, "apt").Render(testBase(t), tok)
	if !strings.Contains(apt, "machine https://bodega.internal") {
		t.Fatalf("apt's machine line is not scheme-annotated:\n%s", apt)
	}
	if !strings.Contains(apt, "password "+tok) {
		t.Fatalf("apt's entry carries no password:\n%s", apt)
	}

	// Each file in the format its client parses.
	netrc := files[filepath.Join(home, ".netrc")]
	if !strings.Contains(netrc, "machine bodega.internal") || !strings.Contains(netrc, "password "+tok) {
		t.Fatalf(".netrc is not netrc-shaped:\n%s", netrc)
	}
	if strings.Contains(netrc, "machine https://") {
		t.Fatalf("the shared .netrc carries apt's scheme annotation; libcurl, requests and the\n"+
			"go toolchain match a bare host and would find no entry:\n%s", netrc)
	}
	npmrc := files[filepath.Join(home, ".npmrc")]
	if !strings.Contains(npmrc, "//bodega.internal/npm/:_authToken="+tok) {
		t.Fatalf(".npmrc does not carry a path-scoped _authToken:\n%s", npmrc)
	}
	cargo := files[filepath.Join(home, ".cargo", "credentials.toml")]
	if !strings.Contains(cargo, "[registries.bodega]") || strings.Contains(cargo, "Bearer") {
		t.Fatalf("cargo credentials are not a bare registry token:\n%s", cargo)
	}
	helm := files[targetFor(t, home, "helm").Path]
	if !strings.Contains(helm, "username: bodega") || !strings.Contains(helm, "password: "+tok) {
		t.Fatalf("helm repositories.yaml carries no credential:\n%s", helm)
	}
}

// A second run is what config management does every hour. It must replace the
// block, not stack another one, and it must leave what the operator wrote
// alone.
func TestWriteCredentialIsIdempotentAndPreservesOperatorContent(t *testing.T) {
	home := scratchHome(t)
	const operator = "//registry.internal/:_authToken=someone-elses\n"
	npmrc := filepath.Join(home, ".npmrc")
	if err := os.WriteFile(npmrc, []byte(operator), 0o600); err != nil {
		t.Fatalf("seed .npmrc: %v", err)
	}

	target := targetFor(t, home, "npm")
	if changed, err := WriteCredential(target, testBase(t), "tok-1"); err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	if changed, err := WriteCredential(target, testBase(t), "tok-1"); err != nil || changed {
		t.Fatalf("second write with the same token: changed=%v err=%v; want no change", changed, err)
	}
	if changed, err := WriteCredential(target, testBase(t), "tok-2"); err != nil || !changed {
		t.Fatalf("rotation: changed=%v err=%v", changed, err)
	}

	data, err := os.ReadFile(npmrc)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, operator) {
		t.Fatalf("the operator's own line did not survive:\n%s", body)
	}
	if strings.Count(body, managedBegin) != 1 {
		t.Fatalf("%d managed blocks after three writes, want 1:\n%s", strings.Count(body, managedBegin), body)
	}
	if strings.Contains(body, "tok-1") {
		t.Fatalf("rotation left the old token behind:\n%s", body)
	}
}

// helm's file is the one where appending is not always legal. Refusing beats
// writing a repository entry into whatever key happened to follow.
func TestHelmRefusesAFileItWouldCorrupt(t *testing.T) {
	home := scratchHome(t)
	target := targetFor(t, home, "helm")
	path := target.Path
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	t.Run("repositories last", func(t *testing.T) {
		if err := os.WriteFile(path, []byte("apiVersion: \"\"\nrepositories:\n- name: other\n  url: https://x\n"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if changed, err := WriteCredential(target, testBase(t), "tok"); err != nil || !changed {
			t.Fatalf("append into a well-shaped file: changed=%v err=%v", changed, err)
		}
	})

	t.Run("another key follows", func(t *testing.T) {
		if err := os.WriteFile(path, []byte("repositories:\n- name: other\n  url: https://x\ngenerated: \"2026-01-01\"\n"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		before, _ := os.ReadFile(path)
		_, err := WriteCredential(target, testBase(t), "tok")
		if err == nil {
			t.Fatal("appended under a trailing top-level key; the entry would land inside it")
		}
		if !strings.Contains(err.Error(), "helm repo add") {
			t.Fatalf("refusal names no way forward:\n%v", err)
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Fatalf("a refused write still touched the file:\n%s", after)
		}
	})
}

func targetFor(t *testing.T, home, client string) CredentialTarget {
	t.Helper()
	for _, target := range CredentialTargets(home) {
		if target.Client == client {
			return target
		}
	}
	t.Fatalf("no credential target for %q", client)
	return CredentialTarget{}
}

// The fresh-host case --write-credentials exists for. helm unmarshals
// repositories.yaml into a struct, so a file that is a bare list is rejected
// whole and every later `helm repo add` fails with it until someone deletes
// the file. Creating the file means creating the document.
//
// helmAppendable is the assertion, not a grep for the credential: it already
// encodes the shape a repository entry can live in, and a bare sequence fails
// it for the same reason helm's parser does.
func TestHelmCreatesAParseableDocument(t *testing.T) {
	home := scratchHome(t)
	target := targetFor(t, home, "helm")
	if changed, err := WriteCredential(target, testBase(t), "tok"); err != nil || !changed {
		t.Fatalf("create: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(target.Path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	created := string(data)

	if err := helmAppendable(created); err != nil {
		t.Fatalf("the file doctor created is one it would refuse to append to: %v\n%s", err, created)
	}
	for _, line := range strings.Split(created, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "apiVersion:") {
			t.Fatalf("the document opens on %q; helm unmarshals a mapping and rejects a bare sequence:\n%s", line, created)
		}
		break
	}
	entry := strings.Index(created, "- name: bodega")
	repos := strings.Index(created, "\nrepositories:\n")
	if repos < 0 || entry < repos {
		t.Fatalf("the entry does not sit under a top-level repositories: key:\n%s", created)
	}

	// helm's own file is the shape the second run has to land in, and a
	// rotation must not stack a second document on top of the first.
	if changed, err := WriteCredential(target, testBase(t), "tok-2"); err != nil || !changed {
		t.Fatalf("rotation: changed=%v err=%v", changed, err)
	}
	data, _ = os.ReadFile(target.Path)
	rotated := string(data)
	if strings.Count(rotated, "apiVersion:") != 1 || strings.Count(rotated, managedBegin) != 1 {
		t.Fatalf("rotation did not replace in place:\n%s", rotated)
	}
	if err := helmAppendable(rotated); err != nil {
		t.Fatalf("rotation broke the shape: %v\n%s", err, rotated)
	}
}

// Requirement 6, on the file the client left rather than the one bodega left.
// cargo, helm and npm each rewrite their own configuration during ordinary use
// and drop comments doing it, so the fence is gone by the second run. Anchoring
// on the fence alone appended a second bodega entry holding the pre-rotation
// token: cargo then refuses to parse the file at all, helm resolves charts
// through the stale entry, npm accumulates dead credential lines.
//
// Each case starts from the shape that client's own serializer produces.
func TestRotationSurvivesTheClientsOwnRewrite(t *testing.T) {
	const old, fresh = "tok-old", "tok-fresh"

	cases := []struct {
		client string
		// seed is the file as the client re-serialized it: no markers, an
		// entry bodega owns holding the old token, operator content beside it.
		seed string
		// operator is content the rotation must not touch.
		operator string
		// entry counts what must appear exactly once afterwards.
		entry string
	}{
		{
			client: "cargo",
			seed: "[registries.bodega]\ntoken = \"" + old + "\"\n\n" +
				"[registry]\ntoken = \"crates-io-secret\"\n",
			operator: "crates-io-secret",
			entry:    "[registries.bodega]",
		},
		{
			client: "helm",
			seed: "apiVersion: \"\"\ngenerated: \"2026-01-01T00:00:00Z\"\nrepositories:\n" +
				"- name: bitnami\n  url: https://charts.bitnami.com/bitnami\n" +
				"- name: bodega\n  url: https://bodega.internal/helm\n  username: bodega\n  password: " + old + "\n",
			operator: "name: bitnami",
			entry:    "- name: bodega",
		},
		{
			client:   "npm",
			seed:     "//registry.internal/:_authToken=someone-elses\n//bodega.internal/npm/:_authToken=" + old + "\n",
			operator: "//registry.internal/:_authToken=someone-elses",
			entry:    "//bodega.internal/npm/:_authToken=",
		},
	}

	for _, tc := range cases {
		t.Run(tc.client, func(t *testing.T) {
			home := scratchHome(t)
			target := targetFor(t, home, tc.client)
			if err := os.MkdirAll(filepath.Dir(target.Path), 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(target.Path, []byte(tc.seed), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}

			if changed, err := WriteCredential(target, testBase(t), fresh); err != nil || !changed {
				t.Fatalf("rotation: changed=%v err=%v", changed, err)
			}
			data, err := os.ReadFile(target.Path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			body := string(data)

			if n := strings.Count(body, tc.entry); n != 1 {
				t.Fatalf("%d %q entries after the rotation, want 1:\n%s", n, tc.entry, body)
			}
			if strings.Contains(body, old) {
				t.Fatalf("the pre-rotation token is still in the file:\n%s", body)
			}
			if !strings.Contains(body, fresh) {
				t.Fatalf("the new token did not land:\n%s", body)
			}
			if !strings.Contains(body, tc.operator) {
				t.Fatalf("content bodega does not own did not survive:\n%s", body)
			}
			// A third run has a fence again and must still not stack.
			if changed, err := WriteCredential(target, testBase(t), fresh); err != nil || changed {
				t.Fatalf("third write with the same token: changed=%v err=%v; want no change", changed, err)
			}
		})
	}

	t.Run("helm still parses", func(t *testing.T) {
		home := scratchHome(t)
		target := targetFor(t, home, "helm")
		if err := os.MkdirAll(filepath.Dir(target.Path), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(target.Path, []byte(cases[1].seed), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := WriteCredential(target, testBase(t), fresh); err != nil {
			t.Fatalf("rotation: %v", err)
		}
		data, _ := os.ReadFile(target.Path)
		body := string(data)
		if err := helmAppendable(body); err != nil {
			t.Fatalf("the rotated file is one helm's parser would reject: %v\n%s", err, body)
		}
		if strings.Count(body, "apiVersion:") != 1 || strings.Count(body, "\nrepositories:\n") != 1 {
			t.Fatalf("the rotation duplicated the document keys:\n%s", body)
		}
	})
}

// helm is the one target whose path is not the same on every platform, and
// getting it wrong is silent: the credential lands in a file helm never opens
// and doctor prints "written" over it.
func TestHelmConfigPathFollowsHelm(t *testing.T) {
	const home = "/home/op"
	none := func(string) string { return "" }

	cases := []struct {
		name string
		goos string
		env  map[string]string
		want string
	}{
		{name: "linux default", goos: "linux", want: "/home/op/.config/helm/repositories.yaml"},
		{name: "darwin default", goos: "darwin", want: "/home/op/Library/Preferences/helm/repositories.yaml"},
		{
			name: "XDG beats the platform default",
			goos: "darwin",
			env:  map[string]string{"XDG_CONFIG_HOME": "/xdg"},
			want: "/xdg/helm/repositories.yaml",
		},
		{
			name: "HELM_REPOSITORY_CONFIG beats XDG",
			goos: "linux",
			env:  map[string]string{"XDG_CONFIG_HOME": "/xdg", "HELM_REPOSITORY_CONFIG": "/etc/helm/repos.yaml"},
			want: "/etc/helm/repos.yaml",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := none
			if tc.env != nil {
				env = func(k string) string { return tc.env[k] }
			}
			if got := helmConfigPath(home, tc.goos, env); got != tc.want {
				t.Fatalf("helmConfigPath(%s) = %q, want %q", tc.goos, got, tc.want)
			}
		})
	}
}
