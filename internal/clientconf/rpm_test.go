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

// F103 R3: every enabled repository that can fetch around bodega is
// reported, mirrorlist, metalink and a second baseurl alike; disabled ones
// and bodega's own are not, and a file not ending .repo is not read.
func TestRpmBypassesOverAFixtureReposDir(t *testing.T) {
	repos, err := ReadYumRepos(filepath.Join("testdata", "rpm", "yum.repos.d"), filepath.Join("testdata", "rpm", "absent"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range RpmBypasses(repos, testBase) {
		ids = append(ids, r.ID)
	}
	if want := []string{"bodega-split", "epel", "baseos"}; !slices.Equal(ids, want) {
		t.Errorf("bypasses = %v, want %v", ids, want)
	}
	var none []string
	for _, r := range RpmBypasses(repos, "") {
		none = append(none, r.ID)
	}
	if want := []string{"epel", "baseos"}; !slices.Equal(none, want) {
		t.Errorf("bypasses with no base = %v, want %v", none, want)
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
