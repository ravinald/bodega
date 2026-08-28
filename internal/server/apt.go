package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"compress/gzip"
	"net/http"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- APT repository (dynamic index generation) ----------------------------

// handleAptPool proxies .deb files from S3 pool/main/...
func (s *Server) handleAptPool(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if !isSafePath(p) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := manifest.AptKey("pool/" + p)
	setCacheImmutable(w, path.Base(p))
	store, err := s.aptPoolStore("pool/" + p)
	if err != nil {
		s.logger.Error("storage backend recorded for pooled .deb is not configured",
			"pool_path", p, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	s.proxyS3(w, r, store, key)
}

// aptPoolStore resolves a pooled .deb to the backend recorded for its version.
//
// A .deb is addressed by pool path, so unlike every other artifact route there
// is no package and version in the request to look the entry up by. The
// snapshot carries the reverse mapping instead, built from the same
// _pool_path metadata the Packages generator reads.
func (s *Server) aptPoolStore(poolPath string) (storage.ObjectStore, error) {
	if s.stores == nil {
		return nil, nil
	}
	if snap := s.aptSnap.Load(); snap != nil {
		if name := snap.poolStorage[poolPath]; name != "" {
			return s.stores.ByName(name)
		}
	}
	return s.stores.ForType(manifest.TypeApt), nil
}

// handleAptDists routes /apt/dists/{distpath...} to the appropriate handler
// based on the path structure. Go's ServeMux doesn't support mid-segment
// wildcards like "binary-{arch}", so we parse the path here.
func (s *Server) handleAptDists(w http.ResponseWriter, r *http.Request) {
	distpath := r.PathValue("distpath")
	parts := strings.Split(distpath, "/")

	if len(parts) == 2 {
		switch parts[1] {
		case "Release":
			s.handleAptRelease(w, r, parts[0])
			return
		case "InRelease":
			s.handleAptSigned(w, r, parts[0], "InRelease")
			return
		case "Release.gpg":
			s.handleAptSigned(w, r, parts[0], "Release.gpg")
			return
		}
	}

	// <suite>/<component>/binary-<arch>/Packages[.gz]
	if len(parts) == 4 && strings.HasPrefix(parts[2], "binary-") {
		suite := parts[0]
		component := parts[1]
		arch := strings.TrimPrefix(parts[2], "binary-")
		file := parts[3]
		switch file {
		case "Packages":
			s.handleAptPackages(w, r, suite, component, arch)
			return
		case "Packages.gz":
			s.handleAptPackagesGz(w, r, suite, component, arch)
			return
		}
	}

	http.NotFound(w, r)
}

// handleAptRelease serves the snapshot's Release for a suite.
func (s *Server) handleAptRelease(w http.ResponseWriter, r *http.Request, suite string) {
	idx, snap, ok := s.aptIndex(w, r, suite)
	if !ok {
		return
	}

	// A snapshot approaching Valid-Until means the refresh loop has stopped:
	// nothing else lets it age. Past that instant every client fails apt
	// update at once, including with [trusted=yes], because
	// Acquire::Check-Valid-Until is independent of trust.
	if remaining := time.Until(snap.validUntil); remaining < aptExpiryWarn {
		s.logger.Warn("apt Release nears Valid-Until; the index refresh loop is not running",
			"suite", suite,
			"valid_until", snap.validUntil.Format(time.RFC1123Z),
			"built_at", snap.builtAt.Format(time.RFC1123Z),
			"remaining", remaining.Round(time.Minute).String())
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(idx.release)
}

// handleAptSigned serves InRelease or Release.gpg from the snapshot, and 404s
// when the repository is unsigned.
//
// A 404 is the correct answer, not a placeholder: apt fetches InRelease first
// and falls back to Release on 404, the ordinary path for every archive
// predating InRelease. Serving unsigned bytes under a name that means signed
// would put a malformed document at a well-known URL.
func (s *Server) handleAptSigned(w http.ResponseWriter, r *http.Request, suite, file string) {
	idx, _, ok := s.aptIndex(w, r, suite)
	if !ok {
		return
	}
	body := idx.inRelease
	if file == "Release.gpg" {
		body = idx.releaseGPG
	}
	if body == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleAptPublicKey serves the armored signing key for a human to read and
// for `gpg --dearmor` to consume.
func (s *Server) handleAptPublicKey(w http.ResponseWriter, r *http.Request) {
	s.serveAptKey(w, r, s.aptSign.Load().pub())
}

// handleAptKeyring serves the dearmored keyring, which is what
// /etc/apt/keyrings/ and signed-by= take directly.
func (s *Server) handleAptKeyring(w http.ResponseWriter, r *http.Request) {
	s.serveAptKey(w, r, s.aptSign.Load().ring())
}

// serveAptKey writes one rendering of the loaded public key. The first fetch
// of this file is authenticated by TLS alone, which is why the fingerprint is
// published out of band — see docs/USAGE.md.
func (s *Server) serveAptKey(w http.ResponseWriter, r *http.Request, body []byte) {
	if len(body) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleAptPackages serves the snapshot's Packages index for one architecture.
func (s *Server) handleAptPackages(w http.ResponseWriter, r *http.Request, suite, component, arch string) {
	idx, _, ok := s.aptIndex(w, r, suite)
	if !ok {
		return
	}
	data, found := idx.packages[arch]
	if component != "main" || !found {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleAptPackagesGz serves the gzip-compressed Packages index.
func (s *Server) handleAptPackagesGz(w http.ResponseWriter, r *http.Request, suite, component, arch string) {
	idx, _, ok := s.aptIndex(w, r, suite)
	if !ok {
		return
	}
	data, found := idx.packagesGz[arch]
	if component != "main" || !found {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// aptIndex looks a suite up in the loaded snapshot, writing the response
// itself and returning ok=false when it cannot. An unserved suite is a 404;
// no snapshot at all is a 503, because the suite may well be served and the
// operator's next step is to look at why the build failed, not at their
// sources.list.
func (s *Server) aptIndex(w http.ResponseWriter, r *http.Request, suite string) (*aptSuiteIndex, *aptSnapshot, bool) {
	snap := s.aptSnap.Load()
	if snap == nil {
		s.logger.Error("apt index requested before any snapshot was built", "suite", suite)
		http.Error(w, "apt index unavailable: no snapshot has been built", http.StatusServiceUnavailable)
		return nil, nil, false
	}
	idx := snap.suites[suite]
	if idx == nil {
		http.NotFound(w, r)
		return nil, nil, false
	}
	return idx, snap, true
}

// ---- Index snapshot --------------------------------------------------------

const (
	// aptClockSkew backdates Date so a client running behind the server's
	// clock does not reject a Release stamped in its own future.
	aptClockSkew = 24 * time.Hour

	// aptValidity is the Valid-Until window, measured from the backdated Date.
	// It has to cover any plausible gap between rebuilds: the snapshot's
	// expiry is fixed at build time while real time keeps moving, so a server
	// whose refresh loop dies serves an expired Release from then on.
	aptValidity = 14 * 24 * time.Hour

	// aptRefreshInterval is how often the index is regenerated with no other
	// trigger. Well inside aptValidity so a handful of missed ticks cost
	// nothing.
	aptRefreshInterval = time.Hour

	// aptRetryInterval is the interval used while no snapshot exists at all.
	// Until one does every apt request is a 503, and the ordinary way to land
	// there is transient: expired credentials, or a network that was not up
	// when systemd started the unit. An hour of 503s is the wrong price for a
	// backend that recovers in seconds.
	aptRetryInterval = 15 * time.Second

	// aptRebuildTimeout bounds a rebuild that no request is waiting on, so a
	// wedged backend cannot pin the goroutine forever.
	aptRebuildTimeout = 5 * time.Minute

	// aptExpiryWarn is how long before Valid-Until the server starts logging
	// at Warn, so a dead refresh loop surfaces while apt update still works.
	aptExpiryWarn = 24 * time.Hour

	// aptAuditLogLimit caps how many entries one audit warning names.
	aptAuditLogLimit = 10
)

// aptSuiteIndex is one suite's generated dists/<suite>/ tree.
type aptSuiteIndex struct {
	release    []byte
	inRelease  []byte            // nil when unsigned
	releaseGPG []byte            // nil when unsigned
	packages   map[string][]byte // arch -> Packages
	packagesGz map[string][]byte // arch -> Packages.gz
}

// aptSnapshot is one internally consistent generation of every served suite's
// index. Release carries SHA256 digests of the Packages bodies beside it and
// apt fetches the two in separate requests, so they have to be generated
// together and retired together: bytes from two generations are what a
// client reports as "Hash Sum mismatch".
type aptSnapshot struct {
	suites     map[string]*aptSuiteIndex
	builtAt    time.Time
	validUntil time.Time

	// poolStorage maps a pool path to the backend name its version entry
	// records, with an empty record stored as the default. A present entry
	// and an absent one have to be distinguishable: present-but-empty means
	// "default", while absent means there is no entry to have recorded
	// anything and the type rule applies.
	poolStorage map[string]string
}

// rebuildAptSnapshot regenerates the index and publishes it to every
// subsequent request. On failure the previous snapshot keeps serving: a stale
// index is a smaller problem than a truncated one, which would have clients
// remove packages that are still published.
func (s *Server) rebuildAptSnapshot(ctx context.Context) {
	snap, err := s.buildAptSnapshot(ctx)
	if err != nil {
		s.logger.Error("apt index rebuild failed, previous snapshot still serving",
			"error", err, "have_snapshot", s.aptSnap.Load() != nil)
		return
	}
	s.aptSnap.Store(snap)
	s.logger.Debug("apt index rebuilt",
		"suites", len(snap.suites), "valid_until", snap.validUntil.Format(time.RFC1123Z))
}

// aptRefreshLoop rebuilds on a ticker until ctx is canceled. Valid-Until is
// fixed when a snapshot is built, so without this the index expires in place.
//
// The interval is short until the first snapshot exists and settles to hourly
// afterwards: with no snapshot every apt request is a 503, and the failures
// that put it there are usually over in seconds.
func (s *Server) aptRefreshLoop(ctx context.Context) {
	interval := s.aptTickInterval()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reloadManifests(ctx)
			s.rebuildAptSnapshot(ctx)
			if want := s.aptTickInterval(); want != interval {
				interval = want
				t.Reset(interval)
				s.logger.Info("apt index refresh interval changed", "interval", interval.String())
			}
		}
	}
}

// aptTickInterval is the retry interval until a snapshot exists and the
// refresh interval afterwards.
func (s *Server) aptTickInterval() time.Duration {
	if s.aptSnap.Load() == nil {
		return aptRetryInterval
	}
	return aptRefreshInterval
}

// reloadManifests re-reads the manifest index from the backend so the tick
// sees edits made outside the process.
//
// Without it the loop re-stamps Valid-Until from an unchanged in-memory cache
// forever: GetPackage answers from that cache and only LoadIndex clears it, so
// a package withdrawn on disk would stay published until someone sent SIGHUP.
// A failure here is not fatal — the previous index is still coherent, and
// refusing to re-stamp Valid-Until over it would eventually expire the whole
// repository over a transient read error.
func (s *Server) reloadManifests(ctx context.Context) {
	if err := s.store.LoadIndex(ctx); err != nil {
		s.logger.Error("could not reload manifests; rebuilding the apt index from the cached copy",
			"error", err)
		return
	}
	s.aptPool.Store(nil)
}

// buildAptSnapshot generates every served suite's index from current manifest
// and pool state.
func (s *Server) buildAptSnapshot(ctx context.Context) (*aptSnapshot, error) {
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list apt pool keys: %w", err)
	}

	date := time.Now().UTC().Add(-aptClockSkew)
	snap := &aptSnapshot{
		suites:     make(map[string]*aptSuiteIndex),
		builtAt:    time.Now().UTC(),
		validUntil: date.Add(aptValidity),
	}
	snap.poolStorage = s.aptPoolStorage(ctx)
	served := s.cfg.ServedAptSuites()
	for _, suite := range served {
		snap.suites[suite] = s.buildAptSuiteIndex(ctx, suite, debKeys, date, snap.validUntil)
	}
	s.auditAptEntries(ctx, served)
	return snap, nil
}

// aptPoolStorage maps each pooled path to the backend its version entry names,
// resolving an unrecorded name to the default rather than omitting it. Omitting
// it would send a pre-existing .deb down the type rule, which is precisely the
// hierarchy consultation the empty-means-default rule forbids.
//
// Built over every apt entry rather than inside the per-suite generator: a
// hidden entry and an entry in an unserved suite are both absent from the
// index and both still served from /apt/pool/, so filtering here would send
// their reads to the wrong backend.
func (s *Server) aptPoolStorage(ctx context.Context) map[string]string {
	var out map[string]string
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			poolPath := ve.Metadata["_pool_path"]
			if poolPath == "" {
				continue
			}
			if out == nil {
				out = make(map[string]string)
			}
			if ve.Storage == "" {
				out[poolPath] = storage.DefaultName
			} else {
				out[poolPath] = ve.Storage
			}
		}
	}
	return out
}

// buildAptSuiteIndex generates one suite's Packages bodies and the Release
// that vouches for them.
func (s *Server) buildAptSuiteIndex(ctx context.Context, suite string, debKeys []string, date, validUntil time.Time) *aptSuiteIndex {
	// Collect unique architectures from manifest metadata.
	arches := s.aptArchitectures(ctx, suite)
	if len(arches) == 0 {
		arches = []string{"amd64"}
	}

	idx := &aptSuiteIndex{
		packages:   make(map[string][]byte, len(arches)),
		packagesGz: make(map[string][]byte, len(arches)),
	}

	// Generate Packages content for each arch to compute checksums.
	type indexEntry struct {
		path string
		data []byte
	}
	var entries []indexEntry
	for _, arch := range arches {
		pkgData := s.generateAptPackages(ctx, suite, arch, debKeys)
		entries = append(entries, indexEntry{
			path: "main/binary-" + arch + "/Packages",
			data: pkgData,
		})
		// Gzip variant.
		var gz bytes.Buffer
		gw := gzip.NewWriter(&gz)
		_, _ = gw.Write(pkgData)
		_ = gw.Close()
		entries = append(entries, indexEntry{
			path: "main/binary-" + arch + "/Packages.gz",
			data: gz.Bytes(),
		})
		idx.packages[arch] = pkgData
		idx.packagesGz[arch] = gz.Bytes()
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Origin: bodega\n")
	fmt.Fprintf(&buf, "Label: bodega\n")
	fmt.Fprintf(&buf, "Suite: %s\n", suite)
	fmt.Fprintf(&buf, "Codename: %s\n", suite)
	fmt.Fprintf(&buf, "Components: main\n")
	fmt.Fprintf(&buf, "Architectures: %s\n", strings.Join(arches, " "))
	fmt.Fprintf(&buf, "Date: %s\n", date.Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Valid-Until: %s\n", validUntil.Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "SHA256:\n")
	for _, e := range entries {
		h := sha256.Sum256(e.data)
		fmt.Fprintf(&buf, " %s %d %s\n", hex.EncodeToString(h[:]), len(e.data), e.path)
	}
	idx.release = buf.Bytes()
	s.signAptRelease(idx, suite)
	return idx
}

// aptSigning is the loaded signing key and the two renderings of its public
// half the keyring routes serve. The three are swapped as one value: a client
// that fetched a keyring from one generation and an InRelease from another
// reads a good archive as a forged one.
//
// The public forms are rendered at load rather than per request, so the key
// clients fetch is by construction the key the running process signs with.
type aptSigning struct {
	signer     aptsign.Signer
	pubArmored []byte
	keyring    []byte
}

// pub and ring read through a nil *aptSigning, which is the unsigned
// configuration, so the routes need no separate nil check.
func (a *aptSigning) pub() []byte {
	if a == nil {
		return nil
	}
	return a.pubArmored
}

func (a *aptSigning) ring() []byte {
	if a == nil {
		return nil
	}
	return a.keyring
}

// aptStatus is what the running server knows about how apt clients reach it,
// and nothing else in the tree can derive: whether an index signature exists,
// which suites answer, and the URL in force. Every wrong sources line this
// repository has shipped was an emitter guessing at one of those three.
type aptStatus struct {
	Signed       bool                 `json:"signed"`
	Fingerprints []string             `json:"fingerprints,omitempty"`
	KeyringURL   string               `json:"keyring_url,omitempty"`
	Suites       []string             `json:"suites"`
	PublicURL    string               `json:"public_url"`
	Sources      []aptsources.Sources `json:"sources"`
}

// aptSourcesState reports the client-facing apt state, with the public URL
// resolved for the request that asked.
//
// public_url wins when the operator set one: only they know the name a proxy
// publishes this server under. With none set the request answers for itself,
// which is right for the web UI running in a browser and honors
// X-Forwarded-Proto, so it stays right behind a proxy that terminates TLS on
// a different hostname. r may be nil for a caller with no request in hand,
// such as the startup banner; the renderer then emits a placeholder host.
func (s *Server) aptSourcesState(r *http.Request) aptsources.State {
	st := aptsources.State{
		PublicURL:   s.cfg.ResolvePublicURL(""),
		LocalScheme: s.localScheme(),
		Suites:      s.cfg.ServedAptSuites(),
	}
	if st.PublicURL == "" && r != nil {
		st.PublicURL = requestScheme(r) + "://" + r.Host
	}
	if sign := s.aptSign.Load(); sign != nil {
		st.Signed = true
		st.Fingerprints = sign.signer.Fingerprints()
	}
	return st
}

// aptStatusFor renders one sources block per served suite, so a caller holding
// a package picks the block for that package's suite instead of composing a
// line of its own.
func (s *Server) aptStatusFor(r *http.Request) aptStatus {
	st := s.aptSourcesState(r)
	out := aptStatus{
		Signed:       st.Signed,
		Fingerprints: st.Fingerprints,
		Suites:       st.Suites,
		PublicURL:    st.PublicURL,
		Sources:      make([]aptsources.Sources, 0, len(st.Suites)),
	}
	if st.Signed {
		out.KeyringURL = aptsources.KeyringRoute
	}
	if len(st.Suites) == 0 {
		return aptStatus{Signed: out.Signed, Fingerprints: out.Fingerprints, KeyringURL: out.KeyringURL,
			Suites: []string{}, PublicURL: out.PublicURL, Sources: []aptsources.Sources{aptsources.Render(st)}}
	}
	for _, suite := range st.Suites {
		one := st
		one.Suites = []string{suite}
		out.Sources = append(out.Sources, aptsources.Render(one))
	}
	return out
}

// localScheme is the scheme this process's own listener answers on. It is a
// fallback for a caller with no request and no public_url, never a description
// of how a client reaches the server: behind a proxy both TLS keys are empty
// here and every client still speaks https.
func (s *Server) localScheme() string {
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return "https"
	}
	return "http"
}

// loadAptSigner installs the signing key, if one is present, and renders the
// two public forms the keyring routes serve. It runs at startup and again on
// every SIGHUP, which is what makes the published rotation runbook work.
//
// Absent key at startup: unsigned, and that is a configuration rather than a
// fault, so it logs at Info. Present but unusable: loud, because the operator
// installed a key and would otherwise have no way to learn the repository is
// still unsigned — apt reports nothing, since a missing InRelease is
// indistinguishable from an archive that never had one.
//
// A reload never takes signing away. Whatever went wrong — the key unreadable,
// the mount gone, the file deleted — the previously loaded key keeps signing
// and the fault goes to the journal, because a client configured with
// Signed-By: has no unsigned fallback and would fail apt update outright.
// Serving unsigned is a deliberate act and needs a restart.
func (s *Server) loadAptSigner() {
	loaded := s.aptSign.Load() != nil
	paths := aptsign.DefaultKeyPaths(s.cfg.StoragePath)
	kr, err := aptsign.Load(paths)
	switch {
	case errors.Is(err, aptsign.ErrNoKey) && loaded:
		s.logger.Warn("apt signing key is gone from every search path; the loaded key keeps signing until a restart",
			"searched", strings.Join(paths, ", "))
		return
	case errors.Is(err, aptsign.ErrNoKey):
		s.logger.Info("no apt signing key installed; the apt repository is served unsigned",
			"searched", strings.Join(paths, ", "))
		return
	case err != nil:
		s.logger.Error("apt signing key present but unusable; the apt repository is signed with the previously loaded key, or not at all",
			"error", err, "previously_loaded", loaded)
		return
	}
	pub, err := kr.PublicKey()
	if err != nil {
		s.logger.Error("apt signing key loaded but its public half will not render; the key is not installed",
			"path", kr.Path(), "error", err, "previously_loaded", loaded)
		return
	}
	ring, err := kr.Keyring()
	if err != nil {
		s.logger.Error("apt signing key loaded but its keyring will not render; the key is not installed",
			"path", kr.Path(), "error", err, "previously_loaded", loaded)
		return
	}
	s.aptSign.Store(&aptSigning{signer: kr, pubArmored: pub, keyring: ring})
	s.logger.Info("apt signing key loaded",
		"path", kr.Path(), "keys", kr.Len(),
		"fingerprints", strings.Join(kr.Fingerprints(), " "))
}

// signAptRelease attaches InRelease and Release.gpg to a freshly generated
// suite index. Signing happens here, once per rebuild, rather than per
// request: Release is what carries the digests of the Packages bodies beside
// it, so a per-request signature would seal a different document every time
// and re-sign on every apt update.
//
// A signing failure leaves both nil and logs. The suite keeps serving its
// unsigned Release, which is the same shape a client sees before a key is
// installed, rather than taking the repository down.
func (s *Server) signAptRelease(idx *aptSuiteIndex, suite string) {
	sign := s.aptSign.Load()
	if sign == nil {
		return
	}
	inRelease, err := sign.signer.ClearSign(idx.release)
	if err != nil {
		s.logger.Error("apt InRelease signing failed; suite serves unsigned Release only",
			"suite", suite, "error", err)
		return
	}
	releaseGPG, err := sign.signer.DetachSign(idx.release)
	if err != nil {
		s.logger.Error("apt Release.gpg signing failed; suite serves unsigned Release only",
			"suite", suite, "error", err)
		return
	}
	idx.inRelease = inRelease
	idx.releaseGPG = releaseGPG
}

// auditAptEntries reports manifest entries the generator dropped. Both cases
// are silent to the client and produce "Unable to locate package", the same
// message a typo in the package name produces, so without a log line the
// operator has nothing to work from. Neither is an error: staging an entry
// before adding its suite to apt_suites is a legitimate order, and an
// unresolved entry is a normal intermediate state.
//
// Runs once per rebuild rather than inside the per-suite, per-arch generator
// loop, which would repeat every line N times.
func (s *Server) auditAptEntries(ctx context.Context, served []string) {
	servedSet := make(map[string]bool, len(served))
	for _, suite := range served {
		servedSet[suite] = true
	}

	var unserved, unresolved []string
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" {
				continue
			}
			if ve.Version == "" {
				unresolved = append(unresolved, name)
				continue
			}
			if len(ve.Suites) == 0 {
				continue // the default suite, which is always served
			}
			matched := false
			for _, suite := range ve.EffectiveSuites(s.cfg.AptCodename) {
				if servedSet[suite] {
					matched = true
					break
				}
			}
			if !matched {
				unserved = append(unserved, name+"@"+ve.Version+" ["+strings.Join(ve.Suites, ",")+"]")
			}
		}
	}

	if len(unserved) > 0 {
		s.logger.Warn("apt entries name no served suite and reach no index; add the suite to apt_suites or correct the entry",
			"count", len(unserved), "served", strings.Join(served, ","), "entries", capForLog(unserved))
	}
	if len(unresolved) > 0 {
		s.logger.Warn("apt entries have no version and reach no index; no CLI verb can address a versionless entry, so resolve or remove them",
			"count", len(unresolved), "packages", capForLog(unresolved))
	}
}

// capForLog sorts and truncates a list for a single log field, so a hundred
// staged entries do not produce a hundred-line record.
func capForLog(items []string) string {
	sort.Strings(items)
	if len(items) > aptAuditLogLimit {
		return strings.Join(items[:aptAuditLogLimit], " ") + fmt.Sprintf(" (+%d more)", len(items)-aptAuditLogLimit)
	}
	return strings.Join(items, " ")
}

// aptPoolListing is one cached pool listing and the moment it was taken.
type aptPoolListing struct {
	keys []string
	at   time.Time
}

// aptPoolKeys returns every pooled key, cached for metadata_ttl.
//
// The listing is unbounded and the whole pool is walked, so without a cache
// every apt-touching API write pays for a full listing and every configured
// backend multiplies it. Staleness is bounded and cheap: entries carry
// _pool_path, so this listing only resolves entries written before that
// existed, whose objects were uploaded long before the window opened. SIGHUP
// clears the cache for the operator who needs it gone sooner.
func (s *Server) aptPoolKeys(ctx context.Context) ([]string, error) {
	if s.stores == nil {
		return nil, nil
	}
	ttl := s.cache.MetadataTTL
	if cached := s.aptPool.Load(); cached != nil && ttl > 0 && time.Since(cached.at) < ttl {
		return cached.keys, nil
	}
	keys, err := s.listFanout(ctx, manifest.TypeApt, manifest.AptPoolPrefix)
	if err != nil {
		return nil, err
	}
	s.aptPool.Store(&aptPoolListing{keys: keys, at: time.Now()})
	return keys, nil
}

// aptArchitectures returns sorted unique architectures from the apt manifest
// entries published to suite.
func (s *Server) aptArchitectures(ctx context.Context, suite string) []string {
	seen := map[string]bool{}
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" || !ve.InSuite(suite, s.cfg.AptCodename) {
				continue
			}
			if arch := ve.Metadata["Architecture"]; arch != "" && arch != "all" {
				seen[arch] = true
			}
		}
	}
	var arches []string
	for a := range seen {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	return arches
}

// generateAptPackages builds a Debian Packages file for the given suite and
// architecture from manifest metadata and the S3 pool key listing.
func (s *Server) generateAptPackages(ctx context.Context, suite, arch string, debKeys []string) []byte {
	// Build a map of source-name+version → S3 pool key for Filename lookup.
	poolMap := make(map[string]string) // "pkgname_version" → relative pool path
	for _, key := range debKeys {
		filename := path.Base(key)
		if !strings.HasSuffix(filename, ".deb") {
			continue
		}
		// Key is like "packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb"
		// We want the relative path after "packages/apt/" for the Filename field.
		relPath := strings.TrimPrefix(key, manifest.AptPrefix)
		// Index by base filename for matching.
		poolMap[filename] = relPath
	}

	var buf bytes.Buffer
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil || isPackageHidden(pm) {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" || !ve.InSuite(suite, s.cfg.AptCodename) {
				continue
			}
			// An entry with no Version is unresolved. Its metadata may carry a
			// Version that would produce a complete-looking stanza, but no CLI
			// verb can address the entry to hide, freeze or remove it, so
			// publishing it hands clients a package nobody can withdraw.
			// auditAptEntries reports these once per rebuild.
			if ve.Version == "" {
				continue
			}
			veArch := ve.Metadata["Architecture"]
			if veArch == "" {
				continue
			}
			// Include if arch matches request or package is arch "all".
			if veArch != arch && veArch != "all" {
				continue
			}

			pkgName := ve.SourceName
			if pkgName == "" {
				pkgName = pm.Name
			}

			// Determine the pool path: prefer stored _pool_path, fall back to S3 lookup.
			poolPath := ve.Metadata["_pool_path"]
			if poolPath == "" {
				poolPath = s.findDebInPool(poolMap, pkgName, ve.Version, veArch)
			}
			if poolPath == "" {
				continue // no .deb uploaded yet
			}

			// Emit canonical apt fields from the manifest in Debian Policy §5.3
			// order. Package/Version/Architecture fall back to manifest fields
			// when metadata doesn't carry them (e.g., freshly edited entries).
			if ve.Metadata["Package"] == "" {
				writeDebField(&buf, "Package", pkgName)
			} else {
				writeDebField(&buf, "Package", ve.Metadata["Package"])
			}
			if ve.Metadata["Version"] == "" {
				writeDebField(&buf, "Version", ve.Version)
			} else {
				writeDebField(&buf, "Version", ve.Metadata["Version"])
			}
			writeDebField(&buf, "Architecture", veArch)

			canonical := []string{
				"Source", "Essential",
				"Maintainer", "Original-Maintainer", "Installed-Size",
				"Pre-Depends", "Depends", "Recommends", "Suggests", "Enhances",
				"Breaks", "Conflicts", "Replaces", "Provides",
				"Section", "Priority", "Multi-Arch", "Homepage",
			}
			// Fields the generator emits itself, from bodega's own record of
			// the artifact. Suppressed in the extras loop below so a metadata
			// copy scraped from upstream cannot land a second, contradictory
			// occurrence in the stanza. deb822 does not define a repeated
			// field, so which one a client keeps is a parser's choice.
			// Origin belongs to Release and names the wrong repository when
			// it arrives here from an upstream scrape.
			seen := map[string]bool{
				"Package": true, "Version": true, "Architecture": true,
				"Description": true, "Filename": true, "Size": true,
				"MD5sum": true, "SHA1": true, "SHA256": true, "Origin": true,
			}
			for _, f := range canonical {
				seen[f] = true
				writeDebField(&buf, f, ve.Metadata[f])
			}

			// Catch-all for less common fields (Built-Using, Python-Version, etc.)
			// so rare-but-legal Debian fields survive the round-trip.
			extras := make([]string, 0)
			for k := range ve.Metadata {
				if strings.HasPrefix(k, "_") || seen[k] {
					continue
				}
				extras = append(extras, k)
			}
			sort.Strings(extras)
			for _, k := range extras {
				writeDebField(&buf, k, ve.Metadata[k])
			}

			writeDebField(&buf, "Filename", poolPath)
			if ve.ArtifactSize > 0 {
				fmt.Fprintf(&buf, "Size: %d\n", ve.ArtifactSize)
			}
			if md5 := ve.Metadata["_md5"]; md5 != "" {
				fmt.Fprintf(&buf, "MD5sum: %s\n", md5)
			}
			if sha1 := ve.Metadata["_sha1"]; sha1 != "" {
				fmt.Fprintf(&buf, "SHA1: %s\n", sha1)
			}
			if sha256 := ve.Metadata["_sha256"]; sha256 != "" {
				fmt.Fprintf(&buf, "SHA256: %s\n", sha256)
			} else if ve.Checksum != nil && ve.Checksum.Algorithm == "sha256" {
				writeDebField(&buf, "SHA256", ve.Checksum.Value)
			}

			// Description goes last and re-introduces the continuation prefix
			// that deb822.ParseSingle stripped. A manifest-level description
			// is used only when metadata has none.
			desc := ve.Metadata["Description"]
			if desc == "" {
				desc = ve.Description
			}
			if desc == "" {
				desc = pm.Description
			}
			if desc != "" {
				writeDebDescription(&buf, desc)
			}
			buf.WriteString("\n")
		}
	}
	return buf.Bytes()
}

// findDebInPool searches the pool map for a .deb matching the given package name,
// version, and architecture.
func (s *Server) findDebInPool(poolMap map[string]string, pkgName, version, arch string) string {
	// Try the standard Debian naming convention first.
	candidate := pkgName + "_" + version + "_" + arch + ".deb"
	if rel, ok := poolMap[candidate]; ok {
		return rel
	}
	// Fallback: scan all pool entries for a match containing name and version.
	prefix := pkgName + "_" + version
	for filename, rel := range poolMap {
		if strings.HasPrefix(filename, prefix) {
			return rel
		}
	}
	return ""
}

// writeDebField writes a single "Key: Value" line to buf, sanitizing val to
// prevent field injection via embedded newlines.
func writeDebField(buf *bytes.Buffer, key, val string) {
	if val == "" {
		return
	}
	// Strip newlines and carriage returns to prevent field injection.
	val = strings.ReplaceAll(val, "\n", " ")
	val = strings.ReplaceAll(val, "\r", "")
	fmt.Fprintf(buf, "%s: %s\n", key, val)
}

// writeDebDescription emits a multi-line Description field using Debian's
// single-space continuation convention. Empty interior lines become " .",
// preserving paragraph breaks in long descriptions.
func writeDebDescription(buf *bytes.Buffer, val string) {
	lines := strings.Split(val, "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if i == 0 {
			fmt.Fprintf(buf, "Description: %s\n", line)
			continue
		}
		if line == "" {
			buf.WriteString(" .\n")
		} else {
			buf.WriteString(" ")
			buf.WriteString(line)
			buf.WriteString("\n")
		}
	}
}

// isSafePath rejects path values that contain traversal sequences or encoded
// traversal attempts. Use on any {path...} wildcard before constructing S3 keys.
func isSafePath(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	if strings.Contains(p, "%2e") || strings.Contains(p, "%2E") {
		return false
	}
	return p != ""
}

// requireStorage returns true when a backend is available to serve from. If
// not, it writes a 503 and returns false.
//
// The message names no driver on purpose: the old wording claimed S3 on a
// local install whose storage_path simply could not be created, which sent
// operators looking for a bucket the config never asked for. The reason the
// backend is missing is known where it was constructed, so the message points
// at the startup log rather than guessing.
func (s *Server) requireStorage(w http.ResponseWriter, store storage.ObjectStore) bool {
	if s.stores == nil || store == nil {
		http.Error(w, "storage backend unavailable — package serving disabled; see the server startup log for the backend error", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// aptSourcesBanner renders the apt client stanza for the startup banner. It
// runs after the signing key is loaded and the suites are resolved, so it
// prints what this process will actually serve rather than the example the
// command's help text used to carry.
//
// No request is in hand here, so a server with no public_url set prints a
// placeholder host and the note that says so.
func (s *Server) aptSourcesBanner() string {
	src := aptsources.Render(s.aptSourcesState(nil))
	var b strings.Builder
	b.WriteString("\n/etc/apt/sources.list.d/bodega.sources:\n")
	for _, line := range strings.Split(src.Deb822, "\n") {
		b.WriteString("  " + line + "\n")
	}
	for _, note := range src.Notes {
		b.WriteString("  # " + note + "\n")
	}
	b.WriteString("\n")
	return b.String()
}
