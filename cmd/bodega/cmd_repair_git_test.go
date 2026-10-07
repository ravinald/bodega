package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
)

// TestRepairGitDepLinksHonorsDepPolicy seeds a git entry whose source is on
// disk with a requirements.txt and whose graph has no edges, the state a fetch
// under the default dep_policy leaves, and runs repair's dependency phase
// under each policy value.
func TestRepairGitDepLinksHonorsDepPolicy(t *testing.T) {
	tests := []struct {
		policy     string
		dryRun     bool
		wantIssues int
		wantImport bool
		wantLine   string
	}{
		{policy: "", wantLine: "SKIP: git/demo imports no dependencies"},
		{policy: "none", wantLine: "SKIP: git/demo imports no dependencies"},
		{policy: "direct", wantIssues: 1, wantImport: true, wantLine: "UNLINKED: git/demo@v1.0.0"},
		{policy: "transitive", wantIssues: 1, wantImport: true, wantLine: "UNLINKED: git/demo@v1.0.0"},
		{policy: "direct", dryRun: true, wantIssues: 1, wantLine: "UNLINKED: git/demo@v1.0.0"},
		{policy: "drect", wantIssues: 1, wantLine: `ERROR: git/demo: unknown dep_policy "drect"`},
	}
	for _, tt := range tests {
		name := "policy=" + tt.policy
		if tt.dryRun {
			name += "/check"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			root := t.TempDir()
			src := filepath.Join(root, "sources", "demo", "demo-v1.0.0")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			store := manifest.NewLocalStore(t.TempDir())
			if err := store.AddVersion(ctx, manifest.TypeGit, "demo", manifest.VersionEntry{Ref: "v1.0.0"}); err != nil {
				t.Fatal(err)
			}
			pm, err := store.GetPackage(ctx, manifest.TypeGit, "demo")
			if err != nil || pm == nil {
				t.Fatalf("GetPackage: %v", err)
			}
			pm.DepPolicy = tt.policy
			if err := store.SavePackage(ctx, pm); err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			noDescribe := func(*manifest.Store, io.Writer) {}
			issues := repairGitDepLinks(ctx, &builder.Config{BuildRoot: root}, store, tt.dryRun, noDescribe, &out)

			if issues != tt.wantIssues {
				t.Errorf("issues = %d, want %d\n%s", issues, tt.wantIssues, out.String())
			}
			if !strings.Contains(out.String(), tt.wantLine) {
				t.Errorf("output lacks %q:\n%s", tt.wantLine, out.String())
			}
			if !strings.HasPrefix(tt.wantLine, "UNLINKED") && strings.Contains(out.String(), "UNLINKED") {
				t.Errorf("repair flagged an entry its dep_policy told not to link:\n%s", out.String())
			}
			got, err := store.GetPackage(ctx, manifest.TypePypi, "requests")
			if err != nil {
				t.Fatalf("GetPackage pypi/requests: %v", err)
			}
			if (got != nil) != tt.wantImport {
				t.Errorf("pypi/requests in store = %v, want %v\n%s", got != nil, tt.wantImport, out.String())
			}
			if edges := len(store.ChildrenOf("git/demo@v1.0.0")); (edges > 0) != tt.wantImport {
				t.Errorf("git/demo@v1.0.0 has %d edges after repair, want edges=%v", edges, tt.wantImport)
			}
		})
	}
}

// TestRepairGitDepLinksFindsSourceUnderGitRoot puts the fetched source where
// the fetch writes it, under git_root when that is set, and leaves build_root
// empty, so a repair that resolves the tree from build_root reports the
// source missing and rebuilds no edges.
func TestRepairGitDepLinksFindsSourceUnderGitRoot(t *testing.T) {
	for _, gitRootSet := range []bool{true, false} {
		t.Run(fmt.Sprintf("git_root=%v", gitRootSet), func(t *testing.T) {
			ctx := t.Context()
			bcfg := &builder.Config{BuildRoot: t.TempDir()}
			srcRoot := bcfg.BuildRoot
			if gitRootSet {
				bcfg.GitRoot = t.TempDir()
				srcRoot = bcfg.GitRoot
			}
			src := filepath.Join(srcRoot, "sources", "demo", "demo-v1.0.0")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			store := manifest.NewLocalStore(t.TempDir())
			if err := store.AddVersion(ctx, manifest.TypeGit, "demo", manifest.VersionEntry{Ref: "v1.0.0"}); err != nil {
				t.Fatal(err)
			}
			pm, err := store.GetPackage(ctx, manifest.TypeGit, "demo")
			if err != nil || pm == nil {
				t.Fatalf("GetPackage: %v", err)
			}
			pm.DepPolicy = "direct"
			if err := store.SavePackage(ctx, pm); err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			issues := repairGitDepLinks(ctx, bcfg, store, false, func(*manifest.Store, io.Writer) {}, &out)

			if issues != 1 || !strings.Contains(out.String(), "UNLINKED: git/demo@v1.0.0") {
				t.Errorf("issues = %d, want 1 UNLINKED entry:\n%s", issues, out.String())
			}
			if edges := len(store.ChildrenOf("git/demo@v1.0.0")); edges == 0 {
				t.Errorf("git/demo@v1.0.0 has no edges after repair:\n%s", out.String())
			}
		})
	}
}
