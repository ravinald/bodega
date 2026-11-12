// Package gcstest is an in-process stand-in for the Cloud Storage API, for
// tests that drive bodega's gcs code through the real SDK. Only tests import
// it, so it is in no binary.
package gcstest

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gstorage "cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// Server answers the JSON and XML calls the SDK's HTTP client makes for the
// operations bodega uses: bucket get, create and patch, testIamPermissions,
// object get, list and delete, single-request and resumable uploads with
// generation preconditions, and media reads.
//
// It models what the tests assert on and nothing past it: an object is
// immutable once written and a write is visible only when its last byte has
// arrived, which is the service's documented behavior and the reason a read
// here serves the bytes it captured when the request began.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	buckets  map[string]*bucket
	uploads  map[string]*upload
	nextGen  int64
	denied   map[string]bool
	requests []string
	fail     map[string]int
	races    map[string]int
}

type bucket struct {
	meta    map[string]any
	metagen int64
	objects map[string]*object
}

type object struct {
	data        []byte
	generation  int64
	updated     time.Time
	contentType string
}

type upload struct {
	bucket, name, contentType string
	query                     url.Values
	data                      []byte
}

// New starts a fake holding no buckets and stops it when t ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		buckets: map[string]*bucket{},
		uploads: map[string]*upload{},
		denied:  map[string]bool{},
		fail:    map[string]int{},
		races:   map[string]int{},
		nextGen: 1000,
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Host is what STORAGE_EMULATOR_HOST takes to send an SDK client here.
func (s *Server) Host() string { return s.Listener.Addr().String() }

// Client is an SDK client on this fake, with no credentials.
func (s *Server) Client(t testing.TB) *gstorage.Client {
	t.Helper()
	c, err := gstorage.NewClient(t.Context(), option.WithEndpoint(s.URL+"/storage/v1/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("gcs client on the fake: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// AddBucket creates a bucket as the service does for a create naming nothing:
// no uniform access, public access prevention inherited, no versioning.
func (s *Server) AddBucket(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buckets[name] = &bucket{meta: map[string]any{"name": name, "location": "US"}, metagen: 1, objects: map[string]*object{}}
}

// Deny makes testIamPermissions report the caller as lacking permission.
func (s *Server) Deny(permission string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denied[permission] = true
}

// FailNext refuses the next n requests whose "METHOD path" starts with prefix
// with a 403, before any of them changes state. A 403 is an answer the SDK
// does not retry, so the caller sees it at once.
func (s *Server) FailNext(prefix string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail[prefix] = n
}

// RaceNext makes another writer land on bucket/key just before each of the
// next n uploads to it is judged, so each fails its generation precondition.
func (s *Server) RaceNext(bucketName, key string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.races[bucketName+"/"+key] = n
}

// Bucket returns a bucket's metadata as the API would print it, or nil.
func (s *Server) Bucket(name string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[name]
	if b == nil {
		return nil
	}
	raw, _ := json.Marshal(b.view())
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// Object returns the live bytes at a key and whether an object is there.
func (s *Server) Object(bucketName, key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[bucketName]
	if b == nil || b.objects[key] == nil {
		return nil, false
	}
	return b.objects[key].data, true
}

// Requests returns every request seen so far as "METHOD path?query".
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

func (b *bucket) view() map[string]any {
	out := map[string]any{"kind": "storage#bucket", "metageneration": strconv.FormatInt(b.metagen, 10)}
	for k, v := range b.meta {
		out[k] = v
	}
	return out
}

func (o *object) view(bucketName, name string) map[string]any {
	sum := make([]byte, 4)
	binary.BigEndian.PutUint32(sum, crc32.Checksum(o.data, crc32.MakeTable(crc32.Castagnoli)))
	return map[string]any{
		"kind":           "storage#object",
		"bucket":         bucketName,
		"name":           name,
		"generation":     strconv.FormatInt(o.generation, 10),
		"metageneration": "1",
		"size":           strconv.Itoa(len(o.data)),
		"contentType":    o.contentType,
		"crc32c":         base64.StdEncoding.EncodeToString(sum),
		"etag":           "etag-" + strconv.FormatInt(o.generation, 10),
		"timeCreated":    o.updated.Format(time.RFC3339Nano),
		"updated":        o.updated.Format(time.RFC3339Nano),
	}
}

func apiError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := r.URL.EscapedPath()
	line := r.Method + " " + path
	if r.URL.RawQuery != "" {
		s.requests = append(s.requests, line+"?"+r.URL.RawQuery)
	} else {
		s.requests = append(s.requests, line)
	}
	for prefix, n := range s.fail {
		if n > 0 && strings.HasPrefix(line, prefix) {
			s.fail[prefix] = n - 1
			apiError(w, http.StatusForbidden, "injected refusal")
			return
		}
	}

	switch {
	case strings.HasPrefix(path, "/upload/storage/v1/b/"):
		s.serveUpload(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/upload/storage/v1/b/"), "/o"))
	case path == "/storage/v1/b":
		s.createBucket(w, r)
	case strings.HasPrefix(path, "/storage/v1/b/"):
		s.serveJSON(w, r, strings.TrimPrefix(path, "/storage/v1/b/"))
	default:
		s.serveMedia(w, r, strings.TrimPrefix(path, "/"))
	}
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request) {
	var meta map[string]any
	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil || r.Method != http.MethodPost {
		apiError(w, http.StatusBadRequest, "bad bucket create")
		return
	}
	name, _ := meta["name"].(string)
	if r.URL.Query().Get("project") == "" {
		apiError(w, http.StatusBadRequest, "Required parameter: project")
		return
	}
	if s.buckets[name] != nil {
		apiError(w, http.StatusConflict, "Your previous request to create the named bucket succeeded and you already own it.")
		return
	}
	if _, ok := meta["location"]; !ok {
		meta["location"] = "US"
	}
	meta["location"] = strings.ToUpper(meta["location"].(string))
	meta["projectNumber"] = "1"
	b := &bucket{meta: meta, metagen: 1, objects: map[string]*object{}}
	s.buckets[name] = b
	writeJSON(w, b.view())
}

func (s *Server) serveJSON(w http.ResponseWriter, r *http.Request, rest string) {
	name, tail, _ := strings.Cut(rest, "/")
	b := s.buckets[name]
	if b == nil {
		apiError(w, http.StatusNotFound, "The specified bucket does not exist.")
		return
	}
	q := r.URL.Query()
	switch {
	case tail == "" && r.Method == http.MethodGet:
		writeJSON(w, b.view())
	case tail == "" && r.Method == http.MethodPatch:
		if want := q.Get("ifMetagenerationMatch"); want != "" && want != strconv.FormatInt(b.metagen, 10) {
			apiError(w, http.StatusPreconditionFailed, "metageneration mismatch")
			return
		}
		var patch map[string]any
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			apiError(w, http.StatusBadRequest, "bad patch")
			return
		}
		for k, v := range patch {
			old, isMap := b.meta[k].(map[string]any)
			if in, ok := v.(map[string]any); ok && isMap && k == "iamConfiguration" {
				for ik, iv := range in {
					old[ik] = iv
				}
				continue
			}
			if v == nil {
				delete(b.meta, k)
				continue
			}
			b.meta[k] = v
		}
		b.metagen++
		writeJSON(w, b.view())
	case tail == "" && r.Method == http.MethodDelete:
		if len(b.objects) > 0 {
			apiError(w, http.StatusConflict, "The bucket you tried to delete is not empty.")
			return
		}
		delete(s.buckets, name)
		w.WriteHeader(http.StatusNoContent)
	case tail == "iam/testPermissions":
		var held []string
		for _, p := range q["permissions"] {
			if !s.denied[p] {
				held = append(held, p)
			}
		}
		writeJSON(w, map[string]any{"kind": "storage#testIamPermissionsResponse", "permissions": held})
	case tail == "o" && r.Method == http.MethodGet:
		var names []string
		for k := range b.objects {
			if strings.HasPrefix(k, q.Get("prefix")) {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		items := make([]map[string]any, 0, len(names))
		for _, k := range names {
			items = append(items, b.objects[k].view(name, k))
		}
		writeJSON(w, map[string]any{"kind": "storage#objects", "items": items})
	case strings.HasPrefix(tail, "o/"):
		key, err := url.PathUnescape(strings.TrimPrefix(tail, "o/"))
		o := b.objects[key]
		if err != nil || o == nil {
			apiError(w, http.StatusNotFound, "No such object: "+name+"/"+key)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, o.view(name, key))
		case http.MethodDelete:
			delete(b.objects, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			apiError(w, http.StatusMethodNotAllowed, "method")
		}
	default:
		apiError(w, http.StatusNotFound, "no such route: "+r.Method+" "+rest)
	}
}

// publish stores a finished upload, holding it to the generation precondition
// the request carried. ifGenerationMatch=0 is the API's "must not exist".
func (s *Server) publish(w http.ResponseWriter, u *upload) {
	b := s.buckets[u.bucket]
	if b == nil {
		apiError(w, http.StatusNotFound, "The specified bucket does not exist.")
		return
	}
	if id := u.bucket + "/" + u.name; s.races[id] > 0 {
		s.races[id]--
		s.nextGen++
		b.objects[u.name] = &object{data: []byte("another writer"), generation: s.nextGen, updated: time.Now().UTC()}
	}
	if want := u.query.Get("ifGenerationMatch"); want != "" {
		var have int64
		if cur := b.objects[u.name]; cur != nil {
			have = cur.generation
		}
		if want != strconv.FormatInt(have, 10) {
			apiError(w, http.StatusPreconditionFailed, "At least one of the pre-conditions you specified did not hold.")
			return
		}
	}
	s.nextGen++
	o := &object{data: u.data, generation: s.nextGen, updated: time.Now().UTC(), contentType: u.contentType}
	b.objects[u.name] = o
	writeJSON(w, o.view(u.bucket, u.name))
}

func (s *Server) serveUpload(w http.ResponseWriter, r *http.Request, bucketName string) {
	q := r.URL.Query()
	if id := q.Get("upload_id"); id != "" {
		s.resume(w, r, id)
		return
	}
	u := &upload{bucket: bucketName, name: q.Get("name"), query: q}
	var meta struct {
		Name        string `json:"name"`
		ContentType string `json:"contentType"`
	}
	switch q.Get("uploadType") {
	case "multipart":
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			apiError(w, http.StatusBadRequest, "bad multipart content type")
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		head, err := mr.NextPart()
		if err == nil {
			err = json.NewDecoder(head).Decode(&meta)
		}
		var media *multipart.Part
		if err == nil {
			media, err = mr.NextPart()
		}
		if err == nil {
			u.contentType = media.Header.Get("Content-Type")
			u.data, err = io.ReadAll(media)
		}
		if err == nil {
			// The closing boundary is what says the body arrived whole.
			_, err = mr.NextPart()
		}
		if err != io.EOF {
			apiError(w, http.StatusBadRequest, fmt.Sprintf("truncated upload: %v", err))
			return
		}
		if meta.Name != "" {
			u.name = meta.Name
		}
		s.publish(w, u)
	case "resumable":
		_ = json.NewDecoder(r.Body).Decode(&meta)
		if meta.Name != "" {
			u.name = meta.Name
		}
		u.contentType = r.Header.Get("X-Upload-Content-Type")
		id := strconv.Itoa(len(s.uploads) + 1)
		s.uploads[id] = u
		w.Header().Set("Location", s.URL+"/upload/storage/v1/b/"+bucketName+"/o?uploadType=resumable&upload_id="+id)
		w.WriteHeader(http.StatusOK)
	default:
		apiError(w, http.StatusBadRequest, "unsupported uploadType")
	}
}

// resume takes one chunk of a resumable session. A chunk whose Content-Range
// ends in "/*" leaves the session open; one naming the total finishes it.
func (s *Server) resume(w http.ResponseWriter, r *http.Request, id string) {
	u := s.uploads[id]
	if u == nil {
		apiError(w, http.StatusNotFound, "no such upload session")
		return
	}
	chunk, err := io.ReadAll(r.Body)
	if err != nil {
		apiError(w, http.StatusBadRequest, "truncated chunk")
		return
	}
	rng := strings.TrimPrefix(r.Header.Get("Content-Range"), "bytes ")
	span, total, _ := strings.Cut(rng, "/")
	if span != "*" {
		first, _, _ := strings.Cut(span, "-")
		if off, _ := strconv.Atoi(first); off != len(u.data) {
			apiError(w, http.StatusBadRequest, "chunk out of order")
			return
		}
		u.data = append(u.data, chunk...)
	}
	if total == "*" {
		if len(u.data) > 0 {
			w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", len(u.data)-1))
		}
		w.Header().Set("X-Http-Status-Code-Override", "308")
		w.WriteHeader(http.StatusOK)
		return
	}
	delete(s.uploads, id)
	s.publish(w, u)
}

func (s *Server) serveMedia(w http.ResponseWriter, r *http.Request, rest string) {
	name, escaped, _ := strings.Cut(rest, "/")
	key, err := url.PathUnescape(escaped)
	b := s.buckets[name]
	if err != nil || b == nil || b.objects[key] == nil {
		http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", http.StatusNotFound)
		return
	}
	o := b.objects[key]
	if gen := r.URL.Query().Get("generation"); gen != "" && gen != strconv.FormatInt(o.generation, 10) {
		http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", http.StatusNotFound)
		return
	}
	sum := make([]byte, 4)
	binary.BigEndian.PutUint32(sum, crc32.Checksum(o.data, crc32.MakeTable(crc32.Castagnoli)))
	h := w.Header()
	h.Set("X-Goog-Generation", strconv.FormatInt(o.generation, 10))
	h.Set("X-Goog-Metageneration", "1")
	h.Set("X-Goog-Hash", "crc32c="+base64.StdEncoding.EncodeToString(sum))
	h.Set("Last-Modified", o.updated.Format(http.TimeFormat))
	h.Set("Content-Type", o.contentType)
	h.Set("Content-Length", strconv.Itoa(len(o.data)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(o.data)
}
