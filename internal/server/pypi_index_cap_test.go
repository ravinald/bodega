package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// pypiIndexWriter accumulated the whole proxied index before rewriting it, and
// nothing capped that buffer: the only bound was spool_max_artifact_bytes
// (8 GiB) on the miss path, and nothing at all on the cache-hit path where
// proxyS3 streams a stored object straight in.
//
// B33 settled the shape for the npm packument, and this is the same writer one
// ecosystem over: refuse over the ceiling rather than serve the document
// unrewritten, because an unrewritten body is the bypass the rewrite exists to
// close.
func TestPypiIndexWriterRefusesAnOversizedUpstream(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &pypiIndexWriter{ResponseWriter: rec, indexURL: "https://pypi.org/simple/six/", pkg: "six"}

	w.WriteHeader(200)
	chunk := strings.Repeat("x", 1<<20)
	var writeErr error
	for written := int64(0); written <= maxUpstreamBody+int64(len(chunk)); written += int64(len(chunk)) {
		if _, err := w.Write([]byte(chunk)); err != nil {
			writeErr = err
			break
		}
	}
	if writeErr == nil {
		t.Fatal("the writer accepted a body past the ceiling; nothing bounds the allocation")
	}
	if !strings.Contains(writeErr.Error(), "rewrite buffer") {
		t.Errorf("write error does not name the buffer: %v", writeErr)
	}

	if err := w.flush(); err == nil {
		t.Fatal("flush served an oversized index rather than refusing")
	}
	if rec.Code != 502 {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "xxxx") {
		t.Error("the oversized body was served through")
	}
}

// An ordinary index is well under the ceiling and still rewrites.
func TestPypiIndexWriterRewritesAnOrdinaryIndex(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &pypiIndexWriter{ResponseWriter: rec, indexURL: "https://pypi.org/simple/six/", pkg: "six"}

	const page = `<!DOCTYPE html><html><body>` +
		`<a href="https://files.pythonhosted.org/packages/six-1.16.0-py2.py3-none-any.whl#sha256=abc">six-1.16.0-py2.py3-none-any.whl</a>` +
		`</body></html>`
	w.WriteHeader(200)
	if _, err := w.Write([]byte(page)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/pypi/wheels/") {
		t.Errorf("the href was not rewritten onto bodega's route:\n%s", body)
	}
	if !strings.Contains(body, "#sha256=abc") {
		t.Errorf("the integrity fragment was dropped:\n%s", body)
	}
}
