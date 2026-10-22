package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
)

// The fixture archive's htop is the vulnerable build being withdrawn: a binary
// in the mirrored codename with no manifest entry anywhere.
const hiddenHtopVersion = "3.3.0-4build1"

// hideMirrored records a hide the way the CLI does and rebuilds, which is what
// the SIGHUP the CLI sends triggers on a running server.
func hideMirrored(t *testing.T, s *Server, name, version string) {
	t.Helper()
	if err := s.auditDB.InsertAptMirrorHide(context.Background(), audit.AptMirrorHide{
		Name: name, Version: version, Codenames: []string{mirroredCodename}, HiddenBy: "tester",
	}); err != nil {
		t.Fatalf("record the hide: %v", err)
	}
	s.rebuildAptSnapshot(context.Background())
}

// verifyBodegaInRelease checks a served InRelease against bodega's published
// key and returns the signed Release.
func verifyBodegaInRelease(t *testing.T, s *Server, codename string) map[string]string {
	t.Helper()
	code, inRelease := mirrorGet(t, s, "/apt/dists/"+codename+"/InRelease")
	if code != http.StatusOK {
		t.Fatalf("GET InRelease for %s = %d, want 200", codename, code)
	}
	block, _ := clearsign.Decode(inRelease)
	if block == nil {
		t.Fatalf("InRelease for %s is not clearsigned", codename)
	}
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(s.aptSign.Load().pub())))
	if err != nil {
		t.Fatalf("read bodega's published key: %v", err)
	}
	if _, err := openpgp.CheckDetachedSignature(ring, bytesReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		t.Fatalf("InRelease for %s does not verify against bodega's key: %v", codename, err)
	}
	return mustParseRelease(t, block.Plaintext)
}

func TestMirroredHideDropsTheStanzaAndReSignsTheCodename(t *testing.T) {
	s, _ := aptProfileServer(t)
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	code, body := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+packagesPath)
	if code != http.StatusOK {
		t.Fatalf("GET the mirrored Packages = %d, want 200", code)
	}
	index := string(body)
	if strings.Contains(index, "Package: htop") {
		t.Errorf("the mirrored Packages still lists the hidden htop:\n%s", index)
	}
	if !strings.Contains(index, "Package: nginx\n") || !strings.Contains(index, "\n a continuation line the filter must not reflow\n") {
		t.Errorf("the rewrite lost or reflowed a stanza nobody hid:\n%s", index)
	}

	release := verifyBodegaInRelease(t, s, mirroredCodename)
	if got := aptReleaseDigests(release)[packagesPath]; got != sha256Hex(index) {
		t.Errorf("the signed Release names %s for Packages and the served body hashes to %s", got, sha256Hex(index))
	}
	// apt refuses an update whose Origin or Label changed, so the rewrite has
	// to keep the archive's.
	for field, want := range map[string]string{"Origin": "Ubuntu", "Label": "Ubuntu", "Codename": mirroredCodename, "Suite": mirroredCodename} {
		if release[field] != want {
			t.Errorf("rewritten Release %s = %q, want the archive's %q", field, release[field], want)
		}
	}

	// The sources stanza for the codename now names bodega's keyring.
	var stanza *aptsources.Sources
	for _, src := range s.aptStatusFor(nil).Sources {
		if src.Suite == mirroredCodename {
			stanza = &src
		}
	}
	if stanza == nil {
		t.Fatalf("no sources stanza for %s", mirroredCodename)
	}
	if stanza.Mirrored || !strings.Contains(stanza.Deb822, "Signed-By: "+aptsources.ClientKeyringPath) {
		t.Errorf("the stanza for a rewritten codename does not name bodega's keyring:\n%s", stanza.Deb822)
	}
}

func TestMirroredHideDropsTheStanzaFromAFilteredCodename(t *testing.T) {
	s, _ := aptProfileServer(t)
	aptProfileBind(t, s, "web", audit.ExpansionBlock, "nginx", "htop")
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	if index := aptProfileIndex(t, s, "fixture-web"); strings.Contains(index, "Package: htop") {
		t.Errorf("the filtered codename lists the hidden htop although the profile permits it:\n%s", index)
	}
}

func TestMirroredHidePoolRefusesWithAnAuditRow(t *testing.T) {
	s, archive := aptProfileServer(t)
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	code, body := mirrorGet(t, s, "/apt/"+profileHtopDeb)
	if code != http.StatusForbidden {
		t.Fatalf("pool fetch of a hidden mirrored version = %d, want 403:\n%s", code, body)
	}
	if got := archive.count(profileHtopDeb); got != 0 {
		t.Errorf("upstream GETs for a hidden version = %d, want 0", got)
	}
	ev := profileDenial(t, s, audit.DenialHidden)
	if ev.PkgName != "htop" || ev.PkgVersion != hiddenHtopVersion {
		t.Errorf("denial row names %s %s, want htop %s", ev.PkgName, ev.PkgVersion, hiddenHtopVersion)
	}

	if code, _ := mirrorGet(t, s, "/apt/"+profileNginxDeb); code != http.StatusOK {
		t.Errorf("pool fetch of a version nobody hid = %d, want 200", code)
	}
}

func TestMirroredUnhideRestoresTheUpstreamIndex(t *testing.T) {
	s, archive := aptProfileServer(t)
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	if _, err := s.auditDB.DeleteAptMirrorHide(context.Background(), "htop", hiddenHtopVersion); err != nil {
		t.Fatalf("remove the hide: %v", err)
	}
	s.rebuildAptSnapshot(context.Background())

	code, body := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+packagesPath)
	if code != http.StatusOK {
		t.Fatalf("GET the mirrored Packages = %d, want 200", code)
	}
	upstream, _ := archive.object("dists/" + mirroredCodename + "/" + packagesPath)
	if string(body) != upstream {
		t.Errorf("after unhide the Packages is not the archive's bytes:\n%s", body)
	}
	_, inRelease := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/InRelease")
	if want, _ := archive.object("dists/" + mirroredCodename + "/InRelease"); string(inRelease) != want {
		t.Errorf("after unhide the InRelease is not the archive's signed document")
	}
	if code, _ := mirrorGet(t, s, "/apt/"+profileHtopDeb); code != http.StatusOK {
		t.Errorf("pool fetch after unhide = %d, want 200", code)
	}
}

func TestLocateMirroredAptVersion(t *testing.T) {
	s, _ := aptProfileServer(t)

	found, err := LocateMirroredAptVersion(context.Background(), s.cfg, nil, "htop", hiddenHtopVersion)
	if err != nil || len(found) != 1 || found[0] != mirroredCodename {
		t.Fatalf("locate a version the mirror serves = %v, %v; want [%s]", found, err, mirroredCodename)
	}

	_, err = LocateMirroredAptVersion(context.Background(), s.cfg, nil, "htop", "9.9.9-1")
	if err == nil {
		t.Fatal("a version no mirror serves was accepted")
	}
	if !strings.Contains(err.Error(), "searched "+mirroredCodename) {
		t.Errorf("the refusal does not name the codenames searched: %v", err)
	}
}
