package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/host"
)

type retainedAnchorFixture struct {
	root, bundle, managed, retained, release, envFile string
	old, replacement                                  clientconf.CA
}

func TestReviewRootReplacementRetainsIndependentAnchor(t *testing.T) {
	for _, retain := range []bool{false, true} {
		name := "last_anchor_removed"
		if retain {
			name = "independent_anchor_retained"
		}
		t.Run(name, func(t *testing.T) {
			old := review42PlanServer(t, "pypi")
			next := review42PlanServer(t, "pypi")
			oldCA, err := clientconf.ParseCA(old.pem)
			if err != nil {
				t.Fatal(err)
			}
			nextCA, err := clientconf.ParseCA(next.pem)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			f := retainedAnchorFixture{
				root:     root,
				bundle:   filepath.Join(root, "etc/ssl/certs/ca-certificates.crt"),
				managed:  filepath.Join(root, "usr/local/share/ca-certificates/bodega-ca.crt"),
				retained: filepath.Join(root, "usr/local/share/ca-certificates/corporate/issuer.crt"),
				release:  filepath.Join(root, "os-release"),
				envFile:  filepath.Join(root, ".config/go/env"),
				old:      oldCA, replacement: nextCA,
			}
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(f.bundle, f.old.PEM)
			write(f.managed, f.old.PEM)
			write(f.release, []byte("ID=ubuntu\n"))
			if retain {
				write(f.retained, f.old.PEM)
			}
			body := []byte("GOPROXY=" + old.base + "/go\n")
			write(f.envFile, body)
			getenv := func(key string) string {
				if key == "GOENV" {
					return f.envFile
				}
				return ""
			}
			sum := sha256.Sum256(body)
			rec := clientconf.PlanRecord{System: "gomod", Path: f.envFile, Action: clientconf.PlanInstall, SHA256: hex.EncodeToString(sum[:])}
			change, err := clientconf.NewChange(rec, body, root)
			if err != nil {
				t.Fatal(err)
			}
			h := clientconf.CAHost{Root: root, Home: root, GOOS: clientconf.OSLinux, Base: old.base, OSRelease: []byte("ID=ubuntu\n"), Getenv: getenv}
			install, err := clientconf.AddCA([]clientconf.Change{change}, f.replacement, h)
			if err != nil {
				t.Fatalf("rotation plan: %v", err)
			}
			savedProbe, savedRoot, savedOS, savedRelease := doctorTrustProbe, doctorOCIRoot, doctorCAGOOS, doctorOSRelease
			doctorOCIRoot, doctorCAGOOS, doctorOSRelease = root, clientconf.OSLinux, f.release
			doctorTrustProbe = func() host.TrustProbe {
				return host.TrustProbe{Root: root, Home: root, GOOS: clientconf.OSLinux, Getenv: getenv,
					Chain:  func(string) ([]*x509.Certificate, error) { return old.chain, nil },
					System: func(chain []*x509.Certificate, name string) error { return host.VerifyServed(chain, name, f.old.Certs) },
				}
			}
			t.Cleanup(func() {
				doctorTrustProbe, doctorOCIRoot, doctorCAGOOS, doctorOSRelease = savedProbe, savedRoot, savedOS, savedRelease
			})
			owed := owedTrustChecks([]clientconf.PlanRecord{rec})
			previewErr := plannedCA(install.Changes, owed, install.System, old.base)
			t.Logf("retained=%t proposed verdict: %v", retain, previewErr)
			if retain && previewErr != nil {
				t.Errorf("the independent corporate anchor survives the rebuild; preview must allow the rotation: %v", previewErr)
			}
			if !retain && previewErr == nil {
				t.Error("control: removing the last anchor must refuse before writing")
			}
			if got, err := os.ReadFile(f.managed); err != nil || string(got) != string(f.old.PEM) {
				t.Fatalf("preview changed managed anchor: %v", err)
			}
			if _, err := clientconf.Apply(install.Changes, ".review-retention"); err != nil {
				t.Fatal(err)
			}
			// Debian includes each remaining *.crt below the local anchor directory.
			var rebuilt []byte
			err = filepath.WalkDir(filepath.Join(root, "usr/local/share/ca-certificates"), func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() && filepath.Ext(path) == ".crt" {
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					rebuilt = append(rebuilt, data...)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			write(f.bundle, rebuilt)
			liveErr := unreadCA(owed, install.System, old.base)
			t.Logf("retained=%t fresh rebuilt-store verdict: %v", retain, liveErr)
			if retain && liveErr != nil {
				t.Fatalf("retained-anchor live control: %v", liveErr)
			}
			if !retain && liveErr == nil {
				t.Fatal("removed-anchor live control accepted old issuer")
			}
		})
	}
}
