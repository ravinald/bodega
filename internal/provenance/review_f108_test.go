package provenance

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
)

func TestReviewInvalidNoteCannotChooseOutcome(t *testing.T) {
	for _, marker := range []string{"checksum database read failed", "stored tree head unavailable"} {
		t.Run(marker, func(t *testing.T) {
			log := sumdbtest.New(t, sumdbtest.NewKey(t))
			m := sumdbtest.NewModule(t, testModule, "v1.2.3", "x")
			log.AddModule(m)
			log.Wrap = func(w http.ResponseWriter, r *http.Request, db http.Handler) {
				if !strings.HasPrefix(r.URL.Path, "/lookup/") {
					db.ServeHTTP(w, r)
					return
				}
				rec := &capture{header: http.Header{}}
				db.ServeHTTP(rec, r)
				_, _ = w.Write(append(rec.body.Bytes(), []byte("\n"+marker+"\n")...))
			}
			pm, ve := gomodEntry(m.Version)
			got := newTestDatabase(log, &memTrees{}).Check(context.Background(), pm, ve)
			if got.ChecksumDatabase.Outcome != audit.ProvenanceInvalid {
				t.Fatalf("malformed signed note classified %q, want invalid: %s", got.ChecksumDatabase.Outcome, got.Reason)
			}
		})
	}
}
