package clientconf

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func distroFromFixture(t *testing.T, name string) (RpmDistro, bool, string, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rpm", name))
	if err != nil {
		t.Fatal(err)
	}
	id, ver := OSReleaseIDs(data)
	d, ok := RpmDistroFor(id, ver)
	return d, ok, id, ver
}

func configuredSet(names ...string) func(string) bool {
	return func(up string) bool { return slices.Contains(names, up) }
}

// F103 R1: Rocky 9.4 maps to Rocky 9's BaseOS, AppStream and EPEL, each
// section reading bodega's /rpm/ route with both checks on and bodega's key
// named before the vendor's.
func TestRpmHostRocky9(t *testing.T) {
	d, ok, _, _ := distroFromFixture(t, "os-release-rocky-9")
	if !ok || d.Name() != "rocky 9" {
		t.Fatalf("rocky 9.4 maps to %+v, %v; want rocky 9", d, ok)
	}
	f, kept := RpmHost(testBase+"/", d, configuredSet("rocky-baseos", "rocky-appstream", "epel"))
	want := `[bodega-rocky-baseos]
name=bodega rocky-baseos
baseurl=https://bodega.example.com/rpm/rocky-baseos/$releasever/$basearch/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bodega file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9

[bodega-rocky-appstream]
name=bodega rocky-appstream
baseurl=https://bodega.example.com/rpm/rocky-appstream/$releasever/$basearch/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bodega file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9

[bodega-epel]
name=bodega epel
baseurl=https://bodega.example.com/rpm/epel/$releasever/$basearch/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bodega file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9
`
	if f.Content != want {
		t.Errorf("bodega.repo =\n%s\nwant\n%s", f.Content, want)
	}
	if f.Path(OSLinux) != RpmRepoPath || len(f.Notes) != 0 || len(kept) != 3 {
		t.Errorf("path %q, notes %v, kept %d; want %s, none, 3", f.Path(OSLinux), f.Notes, len(kept), RpmRepoPath)
	}
	if got := RpmHostUpstreams([]byte(f.Content)); !slices.Equal(got, []string{"rocky-baseos", "rocky-appstream", "epel"}) {
		t.Errorf("upstreams read back = %v", got)
	}
}

// F103 R1: Alma 10 with EPEL missing from rpm_upstreams gets BaseOS and
// AppStream only, and a note naming what was left out.
func TestRpmHostAlma10WithoutEPEL(t *testing.T) {
	d, ok, _, _ := distroFromFixture(t, "os-release-alma-10")
	if !ok || d.Name() != "almalinux 10" {
		t.Fatalf("alma 10.0 maps to %+v, %v; want almalinux 10", d, ok)
	}
	f, kept := RpmHost(testBase, d, configuredSet("alma-baseos", "alma-appstream", "rocky-baseos"))
	if strings.Contains(f.Content, "epel") || strings.Contains(f.Content, "rocky") {
		t.Errorf("bodega.repo names a repository it should not:\n%s", f.Content)
	}
	for _, s := range []string{"[bodega-alma-baseos]", "[bodega-alma-appstream]", "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10"} {
		if !strings.Contains(f.Content, s) {
			t.Errorf("bodega.repo lacks %s:\n%s", s, f.Content)
		}
	}
	if len(kept) != 2 || len(f.Notes) != 1 || !strings.Contains(f.Notes[0], "epel is left out") || !strings.Contains(f.Notes[0], "almalinux 10") {
		t.Errorf("kept %d, notes %v; want 2 and one naming epel", len(kept), f.Notes)
	}
}

// F103 R2: an OS the table does not name maps to nothing, and RHEL's ids
// carry the host's architecture.
func TestRpmDistroTable(t *testing.T) {
	if d, ok, id, ver := distroFromFixture(t, "os-release-ubuntu"); ok || id != "ubuntu" || ver != "24.04" {
		t.Errorf("ubuntu 24.04 = %+v, %v (read %s %s); want no row", d, ok, id, ver)
	}
	for _, c := range [][2]string{{"rocky", "9"}, {"rocky", "10.1"}, {"almalinux", "9.6"}, {"almalinux", "10"}, {"rhel", "9.4"}, {"rhel", "10.0"}} {
		if _, ok := RpmDistroFor(c[0], c[1]); !ok {
			t.Errorf("%s %s maps to no row", c[0], c[1])
		}
	}
	if _, ok := RpmDistroFor("rocky", "8.10"); ok {
		t.Error("rocky 8 maps to a row; the table covers 9 and 10")
	}
	rhel, _ := RpmDistroFor("rhel", "9.4")
	if got := rhel.Repos[0].VendorID(RpmBasearch("arm64")); got != "rhel-9-for-aarch64-baseos-rpms" {
		t.Errorf("rhel 9 baseos on arm64 = %q", got)
	}
}

func repoIDs(repos []YumRepo) []string {
	var ids []string
	for _, r := range repos {
		ids = append(ids, r.ID)
	}
	return ids
}

// F103 R3: every enabled repository that can fetch around bodega is
// reported, mirrorlist, metalink and a second baseurl alike; disabled ones
// and bodega's own are not, and a file not ending .repo is not read. With
// no base, a bodega- id proves nothing: a section whose URL cannot be
// bodega's route is around, and one whose URLs might be is unverified.
func TestRpmBypassesOverAFixtureReposDir(t *testing.T) {
	conf, err := ReadDnfConfig("", []string{filepath.Join("testdata", "rpm", "yum.repos.d"), filepath.Join("testdata", "rpm", "absent")})
	if err != nil {
		t.Fatal(err)
	}
	repos := conf.Repos
	around, unverified := RpmBypasses(repos, testBase)
	if want := []string{"bodega-split", "epel", "baseos"}; !slices.Equal(repoIDs(around), want) || len(unverified) != 0 {
		t.Errorf("bypasses = %v, unverified %v, want %v", repoIDs(around), repoIDs(unverified), want)
	}
	around, unverified = RpmBypasses(repos, "")
	if want := []string{"bodega-split", "epel", "baseos"}; !slices.Equal(repoIDs(around), want) {
		t.Errorf("bypasses with no base = %v, want %v", repoIDs(around), want)
	}
	if want := []string{"bodega-rocky-baseos"}; !slices.Equal(repoIDs(unverified), want) {
		t.Errorf("unverified with no base = %v, want %v", repoIDs(unverified), want)
	}

	d, _ := RpmDistroFor("rocky", "9.4")
	got := RpmDisableIDs(d, []string{"rocky-baseos", "rocky-appstream", "epel"}, repos, "x86_64")
	if want := []string{"baseos", "epel"}; !slices.Equal(got, want) {
		t.Errorf("disable = %v, want %v: appstream is already off", got, want)
	}
	if got := RpmDisableIDs(d, []string{"rocky-baseos"}, repos, "x86_64"); !slices.Equal(got, []string{"baseos"}) {
		t.Errorf("disable with only baseos served = %v; epel has no bodega section to replace it", got)
	}
}

// F103 R3: a bodega-named section pointing at the vendor is never passed on
// its name, with or without a base to compare.
func TestRpmBypassesIgnoresTheID(t *testing.T) {
	r := []YumRepo{{ID: "bodega-rocky-baseos", Enabled: true, URLs: []string{"https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"}}}
	for _, base := range []string{"", testBase} {
		if around, _ := RpmBypasses(r, base); len(around) != 1 {
			t.Errorf("base %q: a bodega- id pointing upstream was passed", base)
		}
	}
	empty := []YumRepo{{ID: "bodega-rocky-baseos", Enabled: true}}
	if around, _ := RpmBypasses(empty, testBase); len(around) != 1 {
		t.Error("a bodega- id with no URL was passed")
	}
}

// F103 R2, R3: values read as dnf reads them. libdnf's IniParser strips one
// pair of matching quotes, joins indented and whitespace-only lines onto the
// value above (an empty line ends it), and
// dnf keeps enabled's default (on) for a value it cannot parse, so only an
// unquoted false word turns a repository off.
func TestParseDnfIniValueForms(t *testing.T) {
	for _, c := range []struct {
		enabled string
		want    bool
	}{
		{`"1"`, true}, {`'1'`, true}, {`"0"`, false}, {`'no'`, false}, {`Off`, false},
		{``, true}, {`""`, true}, {`maybe`, true}, {`"1`, true}, {`"0'`, true},
	} {
		secs := parseDnfIni([]byte("[baseos]\nenabled=" + c.enabled + "\n"))
		if got := secs[0].repo("x.repo").Enabled; got != c.want {
			t.Errorf("enabled=%s read as %v, want %v", c.enabled, got, c.want)
		}
	}
	// A key dnf does not know (dnf matches option names exactly) changes nothing.
	if !parseDnfIni([]byte("[baseos]\nEnabled=0\n"))[0].repo("x.repo").Enabled {
		t.Error("Enabled=0 turned the repository off; dnf does not read that key")
	}

	data := "\uFEFF[baseos]\nbaseurl = \"https://a.example/rpm/x/,\n\thttps://b.example/os/\"\n  \n  https://c.example/os/\n# comment\n  enabled=0\nmirrorlist=None\n[appstream] # trailing comment\nenabled = 0\n"
	secs := parseDnfIni([]byte(data))
	if len(secs) != 2 {
		t.Fatalf("sections = %+v", secs)
	}
	base := secs[0].repo("x.repo")
	if want := []string{`"https://a.example/rpm/x/`, `https://b.example/os/"`, "https://c.example/os/"}; !slices.Equal(base.URLs, want) {
		t.Errorf("baseurl = %q, want %q: the quotes do not match end to end once the continuation joins", base.URLs, want)
	}
	if !base.Enabled {
		t.Error("an indented enabled=0 after a comment ended the value was read as a key")
	}
	if secs[1].repo("x.repo").Enabled {
		t.Error("[appstream] with a trailing comment was not read as a section")
	}
	quoted := parseDnfIni([]byte("[epel]\nbaseurl=\"https://a.example/1/\n https://b.example/2/\"\n"))[0].repo("x.repo")
	if want := []string{"https://a.example/1/", "https://b.example/2/"}; !slices.Equal(quoted.URLs, want) {
		t.Errorf("quoted continued baseurl = %q, want %q", quoted.URLs, want)
	}
}

// F103 R2, R3: repositories come from dnf.conf's own sections and from the
// reposdir it sets, and only from there: a default directory reposdir
// leaves out is not read, a quoted enabled is enabled, and the first
// definition of an id is the one kept.
func TestReadDnfConfigFollowsMainConf(t *testing.T) {
	root := t.TempDir()
	custom, skipped := filepath.Join(root, "custom.repos.d"), filepath.Join(root, "yum.repos.d")
	for _, dir := range []string{custom, skipped} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mainConf := filepath.Join(root, "dnf.conf")
	write(mainConf, "[main]\ngpgcheck=1\nreposdir=\""+custom+"\"\n\n[baseos]\nbaseurl=https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/\nenabled=\"1\"\n")
	write(filepath.Join(custom, "ext.repo"), "[ext]\nmirrorlist=https://mirror.example/list\n\n[baseos]\nbaseurl="+testBase+"/rpm/rocky-baseos/9/x86_64/\n")
	write(filepath.Join(skipped, "stray.repo"), "[stray]\nbaseurl=https://stray.example/\n")

	conf, err := ReadDnfConfig(mainConf, []string{skipped})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"baseos", "ext"}; !slices.Equal(repoIDs(conf.Repos), want) {
		t.Errorf("repos = %v, want %v", repoIDs(conf.Repos), want)
	}
	if conf.Repos[0].File != mainConf || !conf.Repos[0].Enabled {
		t.Errorf("baseos = %+v, want enabled from %s", conf.Repos[0], mainConf)
	}
	if !conf.ReadsDir(custom+"/") || conf.ReadsDir(skipped) {
		t.Errorf("reposdir = %v", conf.ReposDirs)
	}
	around, _ := RpmBypasses(conf.Repos, testBase)
	if want := []string{"baseos", "ext"}; !slices.Equal(repoIDs(around), want) {
		t.Errorf("bypasses = %v, want %v", repoIDs(around), want)
	}
	d, _ := RpmDistroFor("rocky", "9")
	if got := RpmDisableIDs(d, []string{"rocky-baseos"}, conf.Repos, "x86_64"); !slices.Equal(got, []string{"baseos"}) {
		t.Errorf("disable = %v, want [baseos] from dnf.conf", got)
	}

	write(mainConf, "[main]\nreposdir=\n")
	if conf, err := ReadDnfConfig(mainConf, []string{skipped}); err != nil || len(conf.Repos) != 0 || conf.ReadsDir(skipped) {
		t.Errorf("an empty reposdir = %+v, %v; dnf reads no directory", conf, err)
	}
	if conf, err := ReadDnfConfig(filepath.Join(root, "absent.conf"), []string{skipped}); err != nil || !slices.Equal(repoIDs(conf.Repos), []string{"stray"}) {
		t.Errorf("no dnf.conf = %+v, %v; the default directories apply", conf, err)
	}
}
