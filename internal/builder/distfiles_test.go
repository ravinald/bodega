package builder

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

const distfileBody = "pcpustat source bytes"

// distfilesRun is a ports tree pinning two distfiles, one of them restricted,
// an https upstream serving body for both, and a store holding an entry for
// each. It returns the builder config and the upstream's request counter.
func distfilesRun(t *testing.T, body string) (*Config, *manifest.Store, *atomic.Int32) {
	t.Helper()
	tree := t.TempDir()
	put := func(root, rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(distfileBody))
	put(tree, "Mk/bsd.licenses.db.mk", "")
	put(tree, "sysutils/pcpustat/Makefile", "DIST_SUBDIR=\tpcpustat\n")
	put(tree, "sysutils/pcpustat/distinfo", fmt.Sprintf("SHA256 (pcpustat/1.6.tar.bz2) = %x\nSIZE (pcpustat/1.6.tar.bz2) = %d\n", sum, len(distfileBody)))
	put(tree, "games/adom/Makefile", "RESTRICTED=\tno redistribution\n")
	put(tree, "games/adom/distinfo", fmt.Sprintf("SHA256 (adom.tar.gz) = %x\nSIZE (adom.tar.gz) = %d\n", sum, len(distfileBody)))

	var hits atomic.Int32
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	saved := distfilesClient
	distfilesClient = up.Client()
	t.Cleanup(func() { distfilesClient = saved })

	store := manifest.NewLocalStore(t.TempDir())
	for _, name := range []string{"pcpustat/1.6.tar.bz2", "adom.tar.gz"} {
		if err := store.AddVersion(t.Context(), manifest.TypeDistfiles, name, manifest.VersionEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{
		BuildRoot:          t.TempDir(),
		Stdout:             io.Discard,
		DistfilesPortsTree: tree,
		DistfilesUpstream:  up.URL + "/",
	}
	return cfg, store, &hits
}

func distdirFiles(t *testing.T, cfg *Config) []string {
	t.Helper()
	root := ArtifactDir(cfg, manifest.TypeDistfiles)
	var out []string
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

// A matching file lands in DISTDIR under its DIST_SUBDIR, readable by a build
// running as another user, and a restricted one is refused with the reason.
func TestFetchDistfilesWritesADistdir(t *testing.T) {
	cfg, store, _ := distfilesRun(t, distfileBody)
	s := FetchDistfiles(cfg, store, "")

	if s.Failures != 1 || len(s.Results) != 2 {
		t.Fatalf("summary: %d failures in %d results, want the restricted one alone to fail", s.Failures, len(s.Results))
	}
	for _, r := range s.Results {
		if r.Name == "adom.tar.gz" && (r.Err == nil || !strings.Contains(r.Err.Error(), "RESTRICTED")) {
			t.Errorf("adom.tar.gz: %v, want a refusal naming RESTRICTED", r.Err)
		}
	}
	if got := distdirFiles(t, cfg); strings.Join(got, ",") != "pcpustat/1.6.tar.bz2" {
		t.Fatalf("DISTDIR holds %v, want pcpustat/1.6.tar.bz2 alone", got)
	}
	dest := filepath.Join(ArtifactDir(cfg, manifest.TypeDistfiles), "pcpustat", "1.6.tar.bz2")
	fi, err := os.Stat(dest)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("%s: %v mode %v, want 0644", dest, err, fi.Mode().Perm())
	}
}

// makeOnlyRestrictions are pcpustat Makefiles that set NO_CDROM only through
// a make construct a lexical read gets wrong: a := taken before the variable
// it reads is reassigned, one file included twice under two values, a ?= after
// an .undef that may run, a .for variable shadowing a global one, and an
// assignment whose name is computed. Base make on FreeBSD prints "No resale"
// for `make -V NO_CDROM` in each.
var makeOnlyRestrictions = map[string]map[string]string{
	"conditional undef": {
		"Makefile": "D=\tfiles/allowed.mk\n.if 1\n.undef D\n.endif\nD?=\tfiles/restricted.mk\n.include \"${D}\"\n",
	},
	"loop shadow": {
		"Makefile": "D=\tfiles/allowed.mk\n.for D in files/restricted.mk\n.include \"${D}\"\n.endfor\n",
	},
	"computed restriction": {
		"Makefile": "N=\tNO_CDROM\n${N}=\tNo resale\n",
	},
	"immediate assignment": {
		"Makefile": "D=\tfiles/restricted.mk\nP:=\t${D}\nD=\tfiles/allowed.mk\n.include \"${P}\"\n",
	},
	"repeated include": {
		"Makefile":          "D=\tfiles/allowed.mk\n.include \"files/dispatch.mk\"\nD=\tfiles/restricted.mk\n.include \"files/dispatch.mk\"\n",
		"files/dispatch.mk": ".include \"${.CURDIR}/${D}\"\n",
	},
}

func writeMakeOnlyRestriction(t *testing.T, tree string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(tree, "sysutils", "pcpustat")
	all := map[string]string{"files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "PORTNAME=\tpcpustat\n"}
	for rel, body := range files {
		all[rel] = body
	}
	for rel, body := range all {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A restriction only make's own reading of the Makefiles reaches fails the
// entry before any upstream is contacted.
func TestFetchDistfilesRefusesARestrictionMakeReaches(t *testing.T) {
	for name, files := range makeOnlyRestrictions {
		t.Run(name, func(t *testing.T) {
			cfg, store, hits := distfilesRun(t, distfileBody)
			writeMakeOnlyRestriction(t, cfg.DistfilesPortsTree, files)
			s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2")
			if s.Failures != 1 || hits.Load() != 0 || !strings.Contains(s.Results[0].Err.Error(), "NO_CDROM") {
				t.Fatalf("results %+v after %d upstream fetches, want one refusal naming NO_CDROM after none", s.Results, hits.Load())
			}
		})
	}
}

// A file already in DISTDIR whose port make restricts is not uploaded, and
// the whole upload is refused.
func TestDistfilesArtifactPathsRefusesARestrictionMakeReaches(t *testing.T) {
	for name, files := range makeOnlyRestrictions {
		t.Run(name, func(t *testing.T) {
			cfg, store, _ := distfilesRun(t, distfileBody)
			if s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2"); s.HasFailures() {
				t.Fatalf("fetch: %+v", s.Results)
			}
			writeMakeOnlyRestriction(t, cfg.DistfilesPortsTree, files)
			paths, _, err := DistfilesArtifactPaths(cfg, store, "")
			if err == nil || !strings.Contains(err.Error(), "NO_CDROM") {
				t.Fatalf("paths=%v err=%v, want a refusal naming NO_CDROM", paths, err)
			}
		})
	}
}

// Bytes distinfo did not pin never reach DISTDIR, under their own name or a
// temporary one. do-fetch.sh skips any file already present, so a wrong file
// left there is one the client would never re-fetch.
func TestFetchDistfilesWritesNothingOnAMismatch(t *testing.T) {
	cfg, store, _ := distfilesRun(t, "PCPUSTAT SOURCE BYTES")
	s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2")
	if s.Failures != 1 || !strings.Contains(s.Results[0].Err.Error(), "does not match distinfo") {
		t.Fatalf("summary: %+v, want one failure naming the distinfo mismatch", s.Results)
	}
	if got := distdirFiles(t, cfg); len(got) != 0 {
		t.Errorf("DISTDIR holds %v after a refused fetch, want nothing", got)
	}
}

// A file already present is re-hashed: a match skips the fetch, anything else
// is replaced.
func TestFetchDistfilesChecksWhatIsAlreadyThere(t *testing.T) {
	cfg, store, hits := distfilesRun(t, distfileBody)
	dest := filepath.Join(ArtifactDir(cfg, manifest.TypeDistfiles), "pcpustat", "1.6.tar.bz2")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(dest, []byte("PCPUSTAT SOURCE BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2"); s.Failures != 0 || hits.Load() != 1 {
		t.Fatalf("a wrong file in place: %d failures after %d fetches, want it replaced by one", s.Failures, hits.Load())
	}
	if got, _ := os.ReadFile(dest); string(got) != distfileBody {
		t.Fatalf("DISTDIR holds %q, want the pinned bytes", got)
	}

	if s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2"); s.Failures != 0 || hits.Load() != 1 {
		t.Errorf("a matching file in place: %d failures after %d fetches, want it skipped", s.Failures, hits.Load())
	}
}

// With no ports tree there is nothing to admit against, and every entry says
// so rather than falling back to pinning whatever arrives.
func TestFetchDistfilesRefusesWithoutAPortsTree(t *testing.T) {
	cfg, store, hits := distfilesRun(t, distfileBody)
	cfg.DistfilesPortsTree = ""
	s := FetchDistfiles(cfg, store, "")
	if s.Failures != 2 || hits.Load() != 0 {
		t.Fatalf("%d failures after %d fetches, want both refused before any fetch", s.Failures, hits.Load())
	}
	if !strings.Contains(s.Results[0].Err.Error(), "distfiles_ports_tree") {
		t.Errorf("error %q does not name the setting to fix", s.Results[0].Err)
	}
}

// A DISTDIR that cannot be created fails every selected entry, naming the path
// and the filesystem error, rather than returning an empty summary.
func TestFetchDistfilesFailsWhenTheDistdirCannotBeCreated(t *testing.T) {
	cfg, store, hits := distfilesRun(t, distfileBody)
	if err := os.WriteFile(filepath.Join(cfg.BuildRoot, "distfiles"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2")
	if !s.HasFailures() || s.Total != 1 || hits.Load() != 0 {
		t.Fatalf("total=%d failures=%d fetches=%d, want the entry failed before any fetch", s.Total, s.Failures, hits.Load())
	}
	if msg := s.Results[0].Err.Error(); !strings.Contains(msg, filepath.Join(cfg.BuildRoot, "distfiles")) {
		t.Errorf("error %q does not name the DISTDIR", msg)
	}
}

// The upstream allow-list applies before a fetch: a denied host is never
// contacted, and an allowed one is.
func TestFetchDistfilesHonorsTheUpstreamAllowList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		denied  bool
	}{
		{"matching host", "127.0.0.1", false},
		{"other host", "allowed.example", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, hits := distfilesRun(t, distfileBody)
			db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "p", RegistryType: manifest.TypeDistfiles, RuleKind: policy.KindHost, Pattern: tc.pattern}); err != nil {
				t.Fatal(err)
			}
			cfg.policyChecker = policy.NewChecker(db)
			cfg.AuditDB = db
			s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2")
			if tc.denied {
				if !s.HasFailures() || hits.Load() != 0 || !policy.IsViolation(s.Results[0].Err) {
					t.Fatalf("failures=%d fetches=%d err=%v, want a policy refusal before any fetch", s.Failures, hits.Load(), s.Results)
				}
				rows, err := db.Query(t.Context(), audit.Filter{EventType: audit.EventFetch})
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rows {
					if r.Status == "policy_violation" && r.PkgType == manifest.TypeDistfiles {
						return
					}
				}
				t.Errorf("no policy_violation row: %+v", rows)
				return
			}
			if s.HasFailures() || hits.Load() != 1 {
				t.Fatalf("failures=%d fetches=%d, want the allowed host fetched once", s.Failures, hits.Load())
			}
		})
	}
}

// Enumerating for upload holds every file to the current distinfo, uploads
// from a pinned copy, and refuses the lot when any one is not admitted.
func TestDistfilesArtifactPathsAdmitsOnlyWhatDistinfoPins(t *testing.T) {
	cfg, store, _ := distfilesRun(t, distfileBody)
	if s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2"); s.HasFailures() {
		t.Fatalf("fetch: %+v", s.Results)
	}
	paths, release, err := DistfilesArtifactPaths(cfg, store, "pcpustat/1.6.tar.bz2")
	if err != nil || len(paths) != 1 {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	if b, _ := os.ReadFile(paths[0].Local); string(b) != distfileBody || paths[0].ObjectKey != "distfiles/pcpustat/1.6.tar.bz2" {
		t.Errorf("pinned %q at key %q", b, paths[0].ObjectKey)
	}
	// Rewriting the DISTDIR file in place, or replacing it, after enumeration
	// does not change what is uploaded.
	dest := filepath.Join(cfg.BuildRoot, "distfiles", "pcpustat", "1.6.tar.bz2")
	if err := os.WriteFile(dest, []byte("PCPUSTAT SOURCE BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(paths[0].Local); string(b) != distfileBody {
		t.Errorf("pinned copy changed to %q when the DISTDIR file was rewritten in place", b)
	}
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, []byte("PCPUSTAT SOURCE BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(paths[0].Local); string(b) != distfileBody {
		t.Errorf("pinned copy changed to %q when the DISTDIR file was replaced", b)
	}
	release()
	if _, err := os.Stat(paths[0].Local); !os.IsNotExist(err) {
		t.Errorf("release left the pinned copy: %v", err)
	}

	// The DISTDIR now holds bytes distinfo does not pin: refused, by name.
	if _, _, err := DistfilesArtifactPaths(cfg, store, ""); err == nil || !strings.Contains(err.Error(), "pcpustat/1.6.tar.bz2") {
		t.Fatalf("err=%v, want a refusal naming the file", err)
	}
	tree := cfg.DistfilesPortsTree
	cfg.DistfilesPortsTree = ""
	if _, _, err := DistfilesArtifactPaths(cfg, store, ""); err == nil || !strings.Contains(err.Error(), "distfiles_ports_tree") {
		t.Fatalf("err=%v, want a refusal naming the missing setting", err)
	}
	cfg.DistfilesPortsTree = tree
	// A symlink in the DISTDIR is not followed, even to the pinned bytes.
	good := filepath.Join(t.TempDir(), "good")
	if err := os.WriteFile(good, []byte(distfileBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, dest); err != nil {
		t.Fatal(err)
	}
	if paths, _, err := DistfilesArtifactPaths(cfg, store, ""); err != nil || len(paths) != 0 {
		t.Fatalf("paths=%v err=%v, want the symlink skipped as not present", paths, err)
	}
	if left, _ := filepath.Glob(filepath.Join(cfg.BuildRoot, ".bodega-distfiles-upload-*")); len(left) != 0 {
		t.Errorf("refusals left pin directories: %v", left)
	}
}
