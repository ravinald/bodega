package builder

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ravinald/bodega/internal/manifest"
)

// pypiUTF16LE encodes text the way a file saved as UTF-16 carries it, mark
// included. pip decodes the whole file by that mark; a reader working on raw
// bytes does not, and the UTF-16 spelling of `://` never appears in them, so
// no token match finds the index this hides.
func pypiUTF16LE(text string) string {
	var b strings.Builder
	b.WriteString("\xff\xfe")
	for _, u := range utf16.Encode([]rune(text)) {
		b.WriteByte(byte(u & 0xff))
		b.WriteByte(byte(u >> 8 & 0xff))
	}
	return b.String()
}

// pypiFetchFailure runs a fetch that must fail and returns the message.
func pypiFetchFailure(t *testing.T, cfg *Config, store *manifest.Store, why string) string {
	t.Helper()
	summary := FetchPypi(cfg, store)
	if !summary.HasFailures() {
		t.Fatalf("%s: %+v", why, summary.Results)
	}
	var msg string
	for _, r := range summary.Results {
		if r.Err != nil {
			msg = r.Err.Error()
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")); !os.IsNotExist(err) {
		t.Error("a fetch that could not settle the origin still wrote a requirements file")
	}
	return msg
}

// pip decodes a requirements file before it reads a line of it, and splits the
// result with str.splitlines. Both stages happen above tokenization, so an
// option either of them produces is one no tokenizer can be taught to see.
// Each input here is refused rather than reproduced: matching Python's
// decoding and line-breaking tables is a standing obligation, not a fix.
func TestFetchPypiRefusesPreprocessingItCannotReproduce(t *testing.T) {
	for _, tc := range []struct {
		name, body, names string
		encode            func(string) string
	}{
		{name: "a UTF-16 byte-order mark", body: "--index-url OTHER/simple/\nsix\n", names: "byte-order mark", encode: pypiUTF16LE},
		{name: "a UTF-8 byte-order mark", body: "\xef\xbb\xbf--index-url OTHER/simple/\nsix\n", names: "byte-order mark"},
		{name: "a PEP 263 coding declaration", body: "# -*- coding: utf-16 -*-\nsix\n", names: "coding utf-16"},
		{name: "bytes that are not UTF-8", body: "six\n\xfe\xff\xfe\n", names: "not UTF-8"},
		{name: "an environment variable", body: "${B57_AUDIT_OPTIONS}\nsix\n", names: "${B57_AUDIT_OPTIONS}"},
		{name: "a carriage return mid-line", body: "# app\r--index-url OTHER/simple/\rsix\r", names: "carriage return"},
		{name: "a vertical tab", body: "# app\v--index-url OTHER/simple/\vsix\n", names: `\v`},
		{name: "a form feed", body: "# app\f--index-url OTHER/simple/\fsix\n", names: `\f`},
		{name: "a file separator", body: "# app\x1c--index-url OTHER/simple/\x1csix\n", names: `\x1c`},
		{name: "a group separator", body: "# app\x1d--index-url OTHER/simple/\x1dsix\n", names: `\x1d`},
		{name: "a record separator", body: "# app\x1e--index-url OTHER/simple/\x1esix\n", names: `\x1e`},
		{name: "a next line", body: "# app\u0085--index-url OTHER/simple/\u0085six\n", names: `\u0085`},
		{name: "a line separator", body: "# app\u2028--index-url OTHER/simple/\u2028six\n", names: `\u2028`},
		{name: "a paragraph separator", body: "# app\u2029--index-url OTHER/simple/\u2029six\n", names: `\u2029`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := pypiIndex(t, "six", "1.16.0")
			other := pypiWheelIndex(t, "six", "1.16.0")
			body := strings.ReplaceAll(tc.body, "OTHER", other.URL)
			if tc.encode != nil {
				body = tc.encode(body)
			}

			cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{"requirements.txt": body})
			msg := pypiFetchFailure(t, cfg, store, "preprocessing pip performs and this does not passed the fetch")

			for _, want := range []string{"requirements.txt", tc.names} {
				if !strings.Contains(msg, want) {
					t.Errorf("the failure does not name %q: %s", want, msg)
				}
			}
			// A rejection has to say where, or it sends nobody anywhere.
			// An encoding is a property of the whole file, so it has no line.
			if tc.names == "not UTF-8" {
				return
			}
			if !strings.Contains(msg, "line ") {
				t.Errorf("the failure names no line: %s", msg)
			}
		})
	}
}

// Refusing a construct pip ignores would prove nothing. The selected index
// serves release JSON and no wheel bytes, so a wheel stored from the file as
// written is proof that the construct does move acquisition.
func TestPipAcquiresElsewhereFromPreprocessingThisRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		encode     func(string) string
	}{
		{name: "a UTF-16 byte-order mark", body: "--index-url OTHER/simple/\nsix\n", encode: pypiUTF16LE},
		{name: "a carriage return mid-line", body: "# app\r--index-url OTHER/simple/\rsix\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := pypiIndex(t, "six", "1.16.0")
			other := pypiWheelIndex(t, "six", "1.16.0")
			body := strings.ReplaceAll(tc.body, "OTHER", other.URL)
			if tc.encode != nil {
				body = tc.encode(body)
			}

			stored, out := pypiPipHonors(t, selected.URL, map[string]string{"requirements.txt": body})
			if len(stored) == 0 {
				t.Fatalf("pip stored nothing from %s, so this spelling proves nothing here:\n%s", other.URL, out)
			}
			if !strings.Contains(out, other.URL) {
				t.Errorf("pip stored %v without reading %s:\n%s", stored, other.URL, out)
			}
		})
	}
}

// The generated file is what pip reads, and it is written here in full. An
// application's requirements arrive inlined, so no path in it reaches back out
// to a file this checked at fetch and pip would re-read at build with a parser
// of its own.
func TestFetchPypiInlinesTheApplicationRequirements(t *testing.T) {
	selected := pypiIndex(t, "six", "1.16.0")
	cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
		"requirements.txt": "# app\nattrs>=24.1\n-r nested/extra.txt\nrequests ; python_version >= \"3.9\"\n",
		"nested/extra.txt": "click==8.1.7\n",
	})

	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("fetch reported failures: %+v", summary.Results)
	}
	root := cfg.rootFor(manifest.TypePypi)
	body, err := os.ReadFile(filepath.Join(root, "combined-requirements.txt"))
	if err != nil {
		t.Fatalf("read generated requirements: %v", err)
	}
	got := string(body)

	for _, want := range []string{"attrs>=24.1", "click==8.1.7", `requests ; python_version >= "3.9"`, "six===1.16.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("the generated file drops %q:\n%s", want, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-r") && !strings.HasPrefix(line, "--requirement") {
			continue
		}
		t.Errorf("the generated file still hands pip a file of its own to parse: %q", line)
	}
	if strings.Contains(got, "nested/extra.txt") {
		t.Errorf("an include survived into the generated file:\n%s", got)
	}
}

// A constraint restricts a version without requesting the package. Flattening
// one into the requirements installs what an application only meant to bound,
// so constraints land in a generated file of their own and reach pip as -c.
func TestFetchPypiKeepsConstraintsApartFromRequirements(t *testing.T) {
	selected := pypiIndex(t, "six", "1.16.0")
	cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
		"requirements.txt": "attrs\n-c constraints.txt\n",
		"constraints.txt":  "urllib3<2\n",
	})

	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("fetch reported failures: %+v", summary.Results)
	}
	root := cfg.rootFor(manifest.TypePypi)
	req, err := os.ReadFile(filepath.Join(root, "combined-requirements.txt"))
	if err != nil {
		t.Fatalf("read generated requirements: %v", err)
	}
	con, err := os.ReadFile(filepath.Join(root, "combined-constraints.txt"))
	if err != nil {
		t.Fatalf("read generated constraints: %v", err)
	}
	if strings.Contains(string(req), "urllib3") {
		t.Errorf("a constraint became a requirement, so the build installs it:\n%s", req)
	}
	if !strings.Contains(string(con), "urllib3<2") {
		t.Errorf("the constraint did not reach the generated constraint file:\n%s", con)
	}
	if want := "-c " + filepath.Join(root, "combined-constraints.txt"); !strings.Contains(string(req), want) {
		t.Errorf("the generated requirements do not name %q:\n%s", want, req)
	}
}

// A failed re-resolve discards the constraint file with the requirements file.
// Leaving it would outlive the pins it was read alongside.
func TestFetchPypiDiscardsConstraintsWhenARefetchFails(t *testing.T) {
	selected := pypiIndex(t, "six", "1.16.0")
	cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
		"requirements.txt": "attrs\n-c constraints.txt\n",
		"constraints.txt":  "urllib3<2\n",
	})
	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("first fetch reported failures: %+v", summary.Results)
	}

	root := cfg.rootFor(manifest.TypePypi)
	work := gitReleaseDir(buildDirs(cfg.rootFor(manifest.TypeGit)), "app", manifest.VersionEntry{Ref: "v1.0.0"})
	if err := os.WriteFile(filepath.Join(work, "requirements.txt"), []byte("${SOMETHING}\n"), 0o600); err != nil {
		t.Fatalf("rewrite requirements: %v", err)
	}
	if summary := FetchPypi(cfg, store); !summary.HasFailures() {
		t.Fatal("a fetch that could not read the application's file reported success")
	}
	for _, name := range []string{"combined-requirements.txt", "combined-constraints.txt"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Errorf("%s outlived the fetch that stopped describing the manifest", name)
		}
	}
}

// pypiWheelRunAs runs real pip over a requirements file with an explicit
// environment and extra arguments, and returns the wheels it stored.
func pypiWheelRunAs(t *testing.T, requirements string, env []string, args ...string) ([]string, string) {
	t.Helper()
	if err := exec.Command("python3", "-m", "pip", "--version").Run(); err != nil {
		t.Skipf("no python3 -m pip on this host: %v", err)
	}
	dir := t.TempDir()
	reqPath := filepath.Join(dir, "combined-requirements.txt")
	if err := os.WriteFile(reqPath, []byte(requirements), 0o600); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	cmd := exec.Command("python3", append(append([]string{"-m", "pip", "wheel"}, args...),
		"--no-deps", "--no-cache-dir", "--disable-pip-version-check",
		"--wheel-dir", dir, "-r", reqPath)...)
	cmd.Env = env
	out, _ := cmd.CombinedOutput()

	stored, _ := filepath.Glob(filepath.Join(dir, "*.whl"))
	for i, whl := range stored {
		stored[i] = filepath.Base(whl)
	}
	return stored, string(out)
}

// pip reads PIP_* and a pip.conf as configuration, above the requirements file
// in its own precedence, so an index named there moves acquisition without
// appearing in any file a requirements reader could examine. No amount of
// reading the file finds it. The build drops that configuration and names the
// index on the command line instead.
//
// The requirements here carry no index of their own, which is the shape the
// generated file had whenever the manifest resolved against the default index.
func TestPypiBuildIgnoresAnIndexFromTheEnvironment(t *testing.T) {
	selected := pypiWheelIndex(t, "six", "1.16.0")
	other := pypiWheelIndex(t, "six", "1.17.0")
	t.Setenv("PIP_INDEX_URL", pypiIndexURL(other.URL))

	// The bypass is real: pip run the way the build used to run it takes the
	// index out of the environment and stores a version nobody approved.
	stored, out := pypiWheelRunAs(t, "six\n", os.Environ())
	if len(stored) == 0 {
		t.Fatalf("pip stored nothing, so this proves nothing here:\n%s", out)
	}
	if !strings.Contains(out, other.URL) {
		t.Fatalf("PIP_INDEX_URL did not move acquisition, so the control under test is untested:\n%s", out)
	}

	// The build's own environment and arguments hold against it.
	stored, out = pypiWheelRunAs(t, "six\n", pypiPipEnv(),
		"--isolated", "--index-url", pypiIndexURL(selected.URL))
	if len(stored) == 0 {
		t.Fatalf("the build's invocation stored nothing:\n%s", out)
	}
	if strings.Contains(out, other.URL) {
		t.Errorf("pip read %s out of the environment past the selected index:\n%s", other.URL, out)
	}
	if !slices.Contains(stored, "six-1.16.0-py3-none-any.whl") {
		t.Errorf("the build stored %v rather than the version the selected index serves:\n%s", stored, out)
	}
}
