package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// TestMutationAPIAdmitsEveryKnownType pins the mutation API's type gate to
// manifest.AllTypes. The handler used to carry its own switch listing seven
// types, which silently lost cargo: a crate manifest 'bodega pkg import'
// accepted was rejected over HTTP with "unknown type". A hand-maintained
// second list is the defect, so the test asserts against AllTypes rather than
// against a list of its own.
func TestMutationAPIAdmitsEveryKnownType(t *testing.T) {
	for _, typ := range manifest.AllTypes {
		t.Run(typ, func(t *testing.T) {
			s, _, _ := refreshTestServer(t)
			body := fmt.Sprintf(`{"name":"parity","type":%q,"versions":[{"version":"1.0.0"}]}`, typ)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+typ, strings.NewReader(body))
			r.SetPathValue("type", typ)
			w := httptest.NewRecorder()

			s.handleCreateEntry(w, r)

			if w.Code == http.StatusNotFound {
				t.Fatalf("type %q rejected as unknown by the mutation API but present in manifest.AllTypes", typ)
			}
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
			}
			if pm, _ := s.store.GetPackage(t.Context(), typ, "parity"); pm == nil {
				t.Errorf("type %q returned 201 but stored nothing", typ)
			}
		})
	}
}

// TestAdmitAndMutationAPIAgreeOnTypes is the other half: the shared admit path
// and the HTTP surface must accept the same set. The two used to disagree
// because each carried its own list.
func TestAdmitAndMutationAPIAgreeOnTypes(t *testing.T) {
	cfg := &config.Config{}
	for _, typ := range manifest.AllTypes {
		pm := &manifest.PackageManifest{
			Name:     "parity",
			Type:     typ,
			Versions: []manifest.VersionEntry{{Version: "1.0.0"}},
		}
		if res := admit.Admit(t.Context(), nil, nil, cfg, pm, ""); !res.OK() {
			t.Errorf("admit refused %q, which manifest.AllTypes lists: %s", typ, res.Reason)
		}
	}
	pm := &manifest.PackageManifest{
		Name:     "parity",
		Type:     "not-a-real-ecosystem",
		Versions: []manifest.VersionEntry{{Version: "1.0.0"}},
	}
	if res := admit.Admit(t.Context(), nil, nil, cfg, pm, ""); res.OK() {
		t.Error("admit accepted a type bodega does not manage")
	}
}

// TestMutationAPIConflictRecordsNoAdmission pins that the mutation API decides
// a name clash before admission, the same order both import paths keep. A 409
// stores nothing, so it must leave no admitted row and take no provenance pin.
// The cost is that a manifest both malformed and already present reports the
// clash rather than the malformation.
func TestMutationAPIConflictRecordsNoAdmission(t *testing.T) {
	s, registry := admittingServer(t)
	body := fmt.Sprintf(`{"name":"sigstore","versions":[{"version":"3.0.0","url":%q}]}`, registry)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm", strings.NewReader(body))
	r.SetPathValue("type", manifest.TypeNpm)
	w := httptest.NewRecorder()

	s.handleCreateEntry(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if rows, pinned := admissionTrail(t, s); len(rows) != 0 || pinned {
		t.Fatalf("a conflict left %d admission row(s) and pinned = %v: %+v", len(rows), pinned, rows)
	}
}
