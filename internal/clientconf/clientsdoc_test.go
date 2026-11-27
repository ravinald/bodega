package clientconf

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// clientsDocBase is the public_url every by-hand file in docs/clients.md is
// rendered for.
const clientsDocBase = "https://bodega.example"

// clientsDocPath is the page an operator reads to put bodega in front of one
// client.
var clientsDocPath = filepath.Join("..", "..", "docs", "clients.md")

// clientsDocInputs is a server serving every type: one namespace per
// upstream map, Ubuntu's noble with its pockets and a tailscale vendor
// archive, FreeBSD's latest, a Rocky 9 host with its three repositories
// configured, three oci_upstreams registries, a binary link and an osquery
// server-mode source that sets origins. Each input is the smallest one that
// makes ForType render the file the page shows.
func clientsDocInputs(t *testing.T) Inputs {
	t.Helper()
	repo, err := pkgrepos.Render(pkgrepos.State{
		PublicURL: clientsDocBase,
		ABI:       "FreeBSD:15:amd64",
		Repo:      "latest",
		Upstream:  "https://pkg.freebsd.org/FreeBSD:15:amd64/latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	rocky, ok := RpmDistroFor("rocky", "9")
	if !ok {
		t.Fatal("the rpm table has no rocky 9 row")
	}
	return Inputs{
		Base:            clientsDocBase,
		GitUpstreams:    map[string]config.GitUpstream{"github": {URL: "https://github.com/"}},
		BinaryUpstreams: map[string]config.BinaryUpstream{"nodejs": {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen}},
		Apt: []aptsources.Sources{aptsources.Render(aptsources.State{
			PublicURL: clientsDocBase,
			Suites:    []string{"noble", "noble-updates", "noble-security"},
			Mirrored:  true,
		})},
		FreeBSD:     []pkgrepos.Repo{repo},
		Binary:      []BinaryLink{{Filename: "kubectl", Path: "kubernetes/release/v1.34.2/bin/linux/amd64/kubectl"}},
		Osquery:     &OsqueryPlan{Instance: "osq", Mode: "server", Endpoint: clientsDocBase + "/api/v1/inventory/sources/osq", Interval: 3600, Origins: true},
		RpmRepos:    []string{"rocky-appstream", "rocky-baseos", "epel"},
		AptArchives: []AptArchiveRef{{Archive: "tailscale", Key: "tailscale/noble", Components: []string{"main"}}},
		RpmDistro:   &rocky,
		OCIUpstreams: map[string]string{
			"docker.io": "https://registry-1.docker.io",
			"ghcr.io":   "https://ghcr.io",
			"quay.io":   "https://quay.io",
		},
	}
}

func readClientsDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(clientsDocPath)
	if err != nil {
		t.Fatalf("docs/clients.md: %v", err)
	}
	return string(b)
}

// clientsDocSections splits the page at its ## headings, keyed by heading.
func clientsDocSections(doc string) (map[string]string, []string) {
	sections := map[string]string{}
	var order []string
	cur := ""
	inFence := false
	for _, line := range strings.SplitAfter(doc, "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
		}
		if !inFence && strings.HasPrefix(line, "## ") {
			cur = strings.TrimSpace(strings.TrimPrefix(line, "## "))
			order = append(order, cur)
			continue
		}
		if cur != "" {
			sections[cur] += line
		}
	}
	return sections, order
}

var clientsDocMarker = regexp.MustCompile(`^<!-- clientconf: (\S+) (.+?) -->$`)

type clientsDocBlock struct {
	system, label, body string
	line                int
}

// clientsDocBlocks returns each marked block: the fenced block that follows a
// marker line, with only blank lines between them.
func clientsDocBlocks(t *testing.T, doc string) []clientsDocBlock {
	t.Helper()
	lines := strings.Split(doc, "\n")
	var out []clientsDocBlock
	for i := 0; i < len(lines); i++ {
		m := clientsDocMarker.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			continue
		}
		j := i + 1
		for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
			j++
		}
		if j == len(lines) || !strings.HasPrefix(lines[j], "```") {
			t.Errorf("docs/clients.md:%d: marker %q is not followed by a fenced block", i+1, lines[i])
			continue
		}
		k := j + 1
		for k < len(lines) && !strings.HasPrefix(lines[k], "```") {
			k++
		}
		if k == len(lines) {
			t.Fatalf("docs/clients.md:%d: fenced block never closes", j+1)
		}
		out = append(out, clientsDocBlock{system: m[1], label: m[2], body: strings.Join(lines[j+1:k], "\n"), line: j + 1})
		i = k
	}
	return out
}

// A type that ForType renders a file for has a section on the page naming
// it, so a new type cannot ship without telling an operator how to connect
// its client.
func TestClientsDocNamesEveryRenderedType(t *testing.T) {
	sections, _ := clientsDocSections(readClientsDoc(t))
	in := clientsDocInputs(t)
	for _, typ := range append(slices.Clone(manifest.AllTypes), SystemOsquery) {
		if len(ForType(typ, in)) == 0 {
			t.Errorf("ForType(%q) renders nothing from clientsDocInputs: give it the input that makes it render a file, so this test checks the page names it", typ)
			continue
		}
		named := false
		for _, body := range sections {
			if strings.Contains(body, "bodega doctor --configure "+typ+" ") {
				named = true
				break
			}
		}
		if !named {
			t.Errorf("docs/clients.md has no ## section naming %q: write one giving `bodega doctor --configure %s --apply`, the files it writes, the audit command and the traps", typ, typ)
		}
	}
}

// Every marked block on the page is the file its renderer writes for
// https://bodega.example, so the by-hand form cannot drift from what doctor
// installs. A marker names a file by its label, or by "label (scope)" where
// two files share a label.
func TestClientsDocFilesMatchRenderer(t *testing.T) {
	doc := readClientsDoc(t)
	blocks := clientsDocBlocks(t, doc)
	if len(blocks) == 0 {
		t.Fatal("docs/clients.md carries no <!-- clientconf: {system} {label} --> marker")
	}
	in := clientsDocInputs(t)
	for _, b := range blocks {
		files := ForType(b.system, in)
		var match []File
		var labels []string
		for _, f := range files {
			scoped := f.Label + " (" + f.Scope + ")"
			labels = append(labels, scoped)
			if f.Label == b.label || scoped == b.label {
				match = append(match, f)
			}
		}
		switch {
		case len(match) == 0:
			t.Errorf("docs/clients.md:%d: %s renders no file labeled %q; its labels are %q", b.line, b.system, b.label, labels)
		case len(match) > 1:
			t.Errorf("docs/clients.md:%d: %s renders %d files labeled %q, so the marker names none of them", b.line, b.system, len(match), b.label)
		case strings.TrimRight(match[0].Content, "\n") != strings.TrimRight(b.body, "\n"):
			t.Errorf("docs/clients.md:%d: the %s %q block differs from what the renderer writes.\n--- page\n%s\n--- renderer\n%s", b.line, b.system, b.label, b.body, match[0].Content)
		}
	}
}

// clientsDocClients are the ## sections an operator moving a host looks for,
// one per client the host runs.
var clientsDocClients = []string{
	"apt", "dnf and yum", "FreeBSD pkg", "FreeBSD ports distfiles", "pip", "npm", "Go modules", "Cargo",
	"Maven", "Gradle", "RubyGems and Bundler", "Composer", "Helm", "Docker Engine", "containerd", "podman",
	"git", "osquery", "Binary downloads",
}

// Each client section gives, in order, the doctor command, the files it
// writes, the audit command that shows a fetch went through bodega, and the
// traps with what the operator sees when one bites.
func TestClientsDocSectionsFollowTheOrder(t *testing.T) {
	sections, order := clientsDocSections(readClientsDoc(t))
	for _, name := range clientsDocClients {
		body, ok := sections[name]
		if !ok {
			t.Errorf("docs/clients.md has no `## %s` section; it has %q", name, order)
			continue
		}
		steps := []struct{ what, needle string }{
			{"the doctor command", "bodega doctor --configure "},
			{"the files", "### Files"},
			{"the audit command", "bodega audit events"},
			{"the traps", "### Traps"},
		}
		at := -1
		for _, s := range steps {
			i := strings.Index(body, s.needle)
			if i < 0 {
				t.Errorf("## %s lacks %s (%q)", name, s.what, s.needle)
				break
			}
			if i < at {
				t.Errorf("## %s gives %s before the step ahead of it", name, s.what)
			}
			at = i
		}
		traps := body[strings.Index(body, "### Traps")+1:]
		if !strings.Contains(traps, "You see") {
			t.Errorf("## %s lists traps without saying what the operator sees when one bites (\"You see ...\")", name)
		}
	}
	if i, j := slices.Index(order, "Binary downloads"), slices.Index(order, "Applications that fetch on their own"); j < 0 || j < i {
		t.Errorf("docs/clients.md has no `## Applications that fetch on their own` after the client sections; it has %q", order)
	}
}

func wantInSection(t *testing.T, section, body string, wants map[string]string) {
	t.Helper()
	for what, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("## %s does not say %s: no %q", section, what, want)
		}
	}
}

func TestClientsDocDockerEngineStores(t *testing.T) {
	sections, _ := clientsDocSections(readClientsDoc(t))
	wantInSection(t, "Docker Engine", sections["Docker Engine"], map[string]string{
		"Docker Hub goes through registry-mirrors under either store": "Docker Hub through `registry-mirrors` under either image store",
		"other registries go through certs.d only on containerd":      "every other registry through `/etc/docker/certs.d/{registry}/hosts.toml` only under the containerd image store",
		"how to read the store":                     "docker info",
		"the containerd store's driver-type":        "driver-type",
		"registry-mirrors applies on SIGHUP":        "SIGHUP",
		"a reload leaves containers running":        "systemctl reload docker",
		"the snapshotter switch needs a restart":    "systemctl restart docker",
		"the switch hides images and containers":    "hides every image and container",
		"compose projects are pulled and recreated": "docker compose up -d --force-recreate",
		"how to switch back":                        `"containerd-snapshotter": false`,
	})
}

func TestClientsDocApplicationsThatFetchOnTheirOwn(t *testing.T) {
	sections, _ := clientsDocSections(readClientsDoc(t))
	body := sections["Applications that fetch on their own"]
	wantInSection(t, "Applications that fetch on their own", body, map[string]string{
		"the system gitconfig":                   "/etc/gitconfig",
		"a rewrite naming one repository":        `[url "https://bodega.example/git/github/acme/updater.git"]`,
		"the upstream it replaces":               "insteadOf = https://github.com/acme/updater.git",
		"why the repository and not the forge":   "rather than the forge",
		"cataloging with pkg import":             "bodega pkg import",
		"catalog mode's bare 404":                "404",
		"no audit event for the 404":             "no audit event",
		"opening the namespace instead":          `"mode": "open"`,
		"snapd":                                  "snapd",
		"the Ubuntu Pro apt hook":                "20apt-esm-hook.conf",
		"ubuntu-release-upgrader":                "ubuntu-release-upgrader",
		"the doctor flag that quiets OS callers": "--quiet-os-callers",
	})
}

func TestClientsDocAptVendorArchives(t *testing.T) {
	sections, _ := clientsDocSections(readClientsDoc(t))
	wantInSection(t, "apt", sections["apt"], map[string]string{
		"the qualified apt_upstreams key":     `"tailscale/noble"`,
		"the --archive flag":                  "--archive tailscale/noble",
		"the default archive's spelling":      "--suite /noble",
		"the refusal a bare codename gets":    `apt codename "noble" is mirrored in 2 archives`,
		"the vendor stanza's file":            "/etc/apt/sources.list.d/bodega-tailscale_noble.sources",
		"the vendor key's file":               "/etc/apt/keyrings/bodega-tailscale_noble.asc",
		"a vendor archive under its own name": "--archive stable",
	})
}

// The page sends flags, the doctor reference and the server side to
// docs/usage.md rather than restating them, and README lists it.
func TestClientsDocLinksUsageAndIsListed(t *testing.T) {
	doc := readClientsDoc(t)
	for what, want := range map[string]string{
		"the doctor reference":               "(usage.md#bodega-doctor-",
		"the client plan":                    "(usage.md#client-plan-and-per-system-files)",
		"the audit command":                  "(usage.md#bodega-audit-events-flags)",
		"the server side of git":             "(usage.md#git-smart-http)",
		"the server side of vendor archives": "(usage.md#vendor-archives)",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/clients.md does not link %s: no %q", what, want)
		}
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, docs, ok := strings.Cut(string(readme), "## Documentation")
	if !ok {
		t.Fatal("README.md has no Documentation section")
	}
	if !strings.Contains(docs, "(docs/clients.md)") {
		t.Error("README.md's Documentation section does not list docs/clients.md")
	}
}

func TestReviewF124NpmCommandTargetsInstallingUser(t *testing.T) {
	sections, _ := clientsDocSections(readClientsDoc(t))
	command := regexp.MustCompile(`(?m)^(?:sudo )?bodega doctor --configure npm[^\n]*`).FindString(sections["npm"])
	if command == "" {
		t.Fatal("npm section has no doctor command")
	}
	home := "/home/operator"
	if strings.HasPrefix(command, "sudo ") {
		home = "/root"
	}
	target, err := TargetPath(Npm(clientsDocBase, nil).Path(OSLinux), home)
	if err != nil {
		t.Fatal(err)
	}
	if target != "/home/operator/.npmrc" {
		t.Fatalf("documented command %q configures %s, leaving /home/operator/.npmrc unchanged", command, target)
	}
}

func TestReviewF124OsqueryListsDoctorFiles(t *testing.T) {
	sections, _ := clientsDocSections(readClientsDoc(t))
	body := sections["osquery"]
	for _, goos := range []string{OSLinux, OSFreeBSD} {
		for _, path := range []string{OsqueryExtensionPaths[goos], OsqueryAutoloadPaths[goos]} {
			if !strings.Contains(body, path) {
				t.Errorf("osquery section omits doctor's %s file %s", goos, path)
			}
		}
	}
	if !strings.Contains(body, "--extensions_autoload=") {
		t.Error("osquery section omits the flag that makes osqueryd load the extension")
	}
}

func TestReviewF124EveryMarkerNamesForTypeFile(t *testing.T) {
	in := clientsDocInputs(t)
	for _, block := range clientsDocBlocks(t, readClientsDoc(t)) {
		found := false
		for _, file := range ForType(block.system, in) {
			if file.Label == block.label || file.Label+" ("+file.Scope+")" == block.label {
				found = strings.TrimRight(file.Content, "\n") == strings.TrimRight(block.body, "\n")
			}
		}
		if !found {
			t.Errorf("docs/clients.md:%d: ForType(%q) has no matching file %q", block.line, block.system, block.label)
		}
	}
}
