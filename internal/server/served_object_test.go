package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

func assertServed(t *testing.T, ev audit.StoredEvent, wantKey, wantDigest string) {
	t.Helper()
	if ev.ObjectKey != wantKey {
		t.Errorf("%s/%s object_key = %q, want %q", ev.PkgType, ev.PkgName, ev.ObjectKey, wantKey)
	}
	if ev.Digest != wantDigest {
		t.Errorf("%s/%s digest = %q, want %q", ev.PkgType, ev.PkgName, ev.Digest, wantDigest)
	}
}

// A mirrored .deb is served twice: the miss hands over the digest the fill
// computed, and the hit reads the checksums row that fill pinned. Both rows
// have to name the same bytes, or a host's report matches one fetch and not
// the other.
func TestServeFetchRecordsAptPoolObject(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	objects := fixtureDists(t, kr, fixturePackages(fixtureDeb, fixtureDebBody))
	objects[fixtureDeb] = fixtureDebBody
	s := mirrorServer(t, newFixtureArchive(t, objects))

	key := manifest.AptKey(fixtureDeb)
	want := sha256Hex(fixtureDebBody)
	for i := 1; i <= 2; i++ {
		if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
			t.Fatalf("pool fetch %d = %d, want 200", i, code)
		}
		events := waitForServeFetch(t, s, i)
		assertServed(t, events[0], key, want)
	}
}

// A hosted pool object is served by serveArtifact rather than the cache, and
// takes its digest from the checksums row alone.
func TestServeFetchRecordsHostedAptPoolObject(t *testing.T) {
	s := newDiscoveryServer(t)
	const pool = "pool/main/h/hello/hello_2.10_amd64.deb"
	key := manifest.AptKey(pool)
	seed(t, s, manifest.TypeApt, map[string]string{key: "hosted deb"})
	if err := s.auditDB.StoreChecksum(t.Context(), key, manifest.TypeApt, "hello", "2.10", "sha256",
		strings.ToUpper(sha256Hex("hosted deb")), "build"); err != nil {
		t.Fatalf("store checksum: %v", err)
	}

	if status, body := getStatusAndBody(t, s, "/apt/"+pool); status != http.StatusOK {
		t.Fatalf("GET hosted pool = %d: %s", status, body)
	}
	assertServed(t, waitForServeFetch(t, s, 1)[0], key, sha256Hex("hosted deb"))
}

// InRelease and a by-hash index are metadata. by-hash is immutable and cached
// exactly like a .deb, so it is the case an "immutable means artifact" rule
// gets wrong.
func TestServeFetchRecordsNoKeyForAptIndexes(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	packages := fixturePackages(fixtureDeb, fixtureDebBody)
	s := mirrorServer(t, newFixtureArchive(t, fixtureDists(t, kr, packages)))

	paths := []string{
		"/apt/dists/" + mirroredCodename + "/InRelease",
		"/apt/dists/" + mirroredCodename + "/main/binary-amd64/by-hash/SHA256/" + sha256Hex(packages),
	}
	for _, p := range paths {
		if code, _ := mirrorGet(t, s, p); code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", p, code)
		}
	}
	for _, ev := range waitForServeFetch(t, s, len(paths)) {
		assertServed(t, ev, "", "")
	}
}

// A hosted npm tarball takes its digest from the version entry's
// ArtifactDigest, which the fetch stage recorded and no checksums row holds.
// The packument for the same package is metadata and names no object.
func TestServeFetchRecordsNpmTarballAndNotPackument(t *testing.T) {
	s := newDiscoveryServer(t)
	const tarball = "widget tarball bytes"
	addVersion(t, s, manifest.TypeNpm, "widget", manifest.VersionEntry{
		Version:        "1.0.0",
		ArtifactDigest: sha256Hex(tarball),
	})
	key := manifest.NpmTarballKey("widget", "1.0.0")
	seed(t, s, manifest.TypeNpm, map[string]string{key: tarball})

	if status, body := getStatusAndBody(t, s, "/npm/widget/-/widget-1.0.0.tgz"); status != http.StatusOK {
		t.Fatalf("GET tarball = %d: %s", status, body)
	}
	tgz := waitForServeFetch(t, s, 1)[0]
	if tgz.PkgVersion != "1.0.0" {
		t.Fatalf("first row is %s/%s@%s, want the tarball", tgz.PkgType, tgz.PkgName, tgz.PkgVersion)
	}
	assertServed(t, tgz, key, sha256Hex(tarball))

	if status, body := getStatusAndBody(t, s, "/npm/widget"); status != http.StatusOK {
		t.Fatalf("GET packument = %d: %s", status, body)
	}
	packument := waitForServeFetch(t, s, 2)[0]
	if packument.PkgVersion != "" {
		t.Fatalf("newest row is %s/%s@%s, want the packument", packument.PkgType, packument.PkgName, packument.PkgVersion)
	}
	assertServed(t, packument, "", "")
}

// A proxied wheel's miss records the digest computed while spooling, and the
// cache hit after it reads the same digest back from the checksums row.
func TestServeFetchRecordsProxiedPypiWheel(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/six/", fmt.Sprintf(
		`<!DOCTYPE html><html><body><a href="%s%s">%s</a><br/></body></html>`,
		up.ts.URL, testWheelRel, testWheel))
	up.route(testWheelRel, wheelBytes)
	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	key := manifest.PypiWheelKey(testWheel)
	for i := 1; i <= 2; i++ {
		if status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel); status != http.StatusOK {
			t.Fatalf("GET wheel %d = %d: %s", i, status, body)
		}
		assertServed(t, waitForServeFetch(t, s, i)[0], key, sha256Hex(wheelBytes))
	}
}

// A mirrored FreeBSD package is a cache hit on an object the mirror stored,
// with its digest in the checksums row. meta.conf beside it is metadata.
func TestServeFetchRecordsFreeBSDPackage(t *testing.T) {
	s := newDiscoveryServer(t)
	const pkgBody = "a mirrored package"
	mirrored(t, s, "latest", map[string]string{
		manifest.FreeBSDCatalogFile: freeBSDCatalogBytes,
		manifest.FreeBSDMetaFile:    freeBSDMetaBytes,
		freeBSDHashedPath:           pkgBody,
	})
	key := manifest.FreeBSDKey(freeBSDABI, "latest", freeBSDHashedPath)
	if err := s.auditDB.StoreChecksum(t.Context(), key, manifest.TypeFreeBSD, "latest", freeBSDABI, "sha256",
		sha256Hex(pkgBody), "computed"); err != nil {
		t.Fatalf("store checksum: %v", err)
	}

	if status, body := getStatusAndBody(t, s, freeBSDURL("latest", freeBSDHashedPath)); status != http.StatusOK {
		t.Fatalf("GET package = %d: %s", status, body)
	}
	assertServed(t, waitForServeFetch(t, s, 1)[0], key, sha256Hex(pkgBody))

	if status, body := getStatusAndBody(t, s, freeBSDURL("latest", manifest.FreeBSDMetaFile)); status != http.StatusOK {
		t.Fatalf("GET meta.conf = %d: %s", status, body)
	}
	assertServed(t, waitForServeFetch(t, s, 2)[0], "", "")
}

// A key with no recorded sha256 is served with its key and no digest; the
// request does not hash the object to fill the gap.
func TestServeFetchLeavesDigestEmptyWhenNoneRecorded(t *testing.T) {
	s := newDiscoveryServer(t)
	const pool = "pool/main/u/unpinned/unpinned_1.0_amd64.deb"
	key := manifest.AptKey(pool)
	seed(t, s, manifest.TypeApt, map[string]string{key: "unpinned deb"})

	if status, body := getStatusAndBody(t, s, "/apt/"+pool); status != http.StatusOK {
		t.Fatalf("GET = %d: %s", status, body)
	}
	assertServed(t, waitForServeFetch(t, s, 1)[0], key, "")
}

func TestNormalizeSHA256(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	for in, want := range map[string]string{
		hex:                      hex,
		strings.ToUpper(hex):     hex,
		"":                       "",
		hex[:62]:                 "",
		"sha256:" + hex[:57]:     "",
		strings.Repeat("zz", 32): "",
	} {
		if got := normalizeSHA256(in); got != want {
			t.Errorf("normalizeSHA256(%q) = %q, want %q", in, got, want)
		}
	}
}
