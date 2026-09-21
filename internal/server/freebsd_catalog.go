package server

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgsign"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- generated FreeBSD pkg catalogue ---------------------------------------
//
// The other half of internal/server/freebsd.go. That one mirrors: it copies
// upstream's archives byte for byte so FreeBSD's own signature reaches the
// client, and bodega holds no key. This one is for a repository with no
// upstream at all — packages an operator built out of poudriere or by hand —
// where there is no catalogue to copy and one has to be produced.
//
// What that costs is worth stating where the code is, not only in the docs.
// A generated catalogue carries bodega's signature or none, never FreeBSD's:
// regeneration is what discards upstream's attestation, and no amount of care
// here puts it back. A client reading a generated repository is trusting this
// mirror. manifest.VersionEntry.Generated is what keeps the two apart, and it
// refuses an entry that claims to be both.
//
// The ordering hazard the mirror spends most of its design on does not exist
// here, and for a reason worth naming rather than inferring from its absence:
// the catalogue is derived from the objects rather than fetched beside them,
// so it can only name bytes the store already holds. There is no generation
// skew to protect a client from.

const (
	// freeBSDManifestMember is the member every .pkg archive opens with, and
	// the one this reads. It is the same JSON a packagesite.yaml record
	// carries, which is why a record is that document plus the four fields
	// only the repository knows.
	freeBSDManifestMember = "+COMPACT_MANIFEST"

	// freeBSDCatalogDoc and freeBSDDataDoc are the archive member names the
	// generated meta.conf names in its "manifests" and "data" keys. The .sig
	// and .pub members are these plus a suffix, which is how a client knows
	// which document a signature covers.
	freeBSDCatalogDoc = "packagesite.yaml"
	freeBSDDataDoc    = "data"

	// freeBSDPkgSuffix is the only extension a generated catalogue admits.
	// Everything else under the prefix — a stray README, a leftover root
	// file, a partial upload — is not a package, and a record naming one
	// resolves an install onto bytes pkg cannot open.
	freeBSDPkgSuffix = ".pkg"

	// freeBSDManifestCap bounds one +COMPACT_MANIFEST. The widest record in
	// pkg.freebsd.org's FreeBSD:14:amd64 latest/ catalogue is 44,005 bytes,
	// and a compact manifest is that same document, so this is two orders of
	// magnitude of headroom over the widest real one.
	freeBSDManifestCap = 4 << 20 // 4 MiB

	// freeBSDGeneratedCap bounds how many objects one generated repository
	// may hold. A repository an operator builds themselves is hundreds of
	// packages; pkg.freebsd.org's widest is 38,325 and is mirrored rather
	// than generated. Past the cap the build refuses by name instead of
	// reading tens of thousands of objects on one request.
	freeBSDGeneratedCap = 50_000
)

// freeBSDCatalog is one repository's three root files, built together.
//
// Together is the point. data.pkg and packagesite.pkg describe the same
// object set, and a client reads one to resolve a package and the other to
// find it, so two halves from two builds is a repository that answers two
// different questions about what it holds.
type freeBSDCatalog struct {
	meta      []byte
	data      []byte
	catalogue []byte

	// objects fingerprints the object set this was built from, and key the
	// signing key it was built under. Either changing means the cached
	// archives describe something that is no longer true: a package added or
	// removed, or a key rotated behind an archive still carrying the old
	// .pub member.
	objects string
	key     string
	builtAt time.Time
}

// pkgSigning is the loaded pkg signing key and the public half every archive
// carries as its .pub member.
//
// Rendered at load rather than per signature, so the key inside an archive is
// by construction the key that signed the document beside it. pub is the bare
// key a client hashes for its fingerprint; pubMember is the same key framed
// for the archive, and the two differ for eddsa.
//
// err carries the third state, and it exists because the other two cannot
// express it. A nil *pkgSigning means no key is installed anywhere the server
// searches, which is a configuration an operator chose and which serves an
// unsigned catalogue. A key file that is present and unusable is not that: the
// operator installed a key and believes the repository is signed. Folding the
// two together publishes an unsigned catalogue on a mode change nobody asked
// for, so this is set instead and signer stays nil.
type pkgSigning struct {
	signer      pkgsign.Signer
	pub         []byte
	pubMember   []byte
	fingerprint string
	err         error
}

// loadPkgSigner installs the pkg catalogue signing key, if one is present.
//
// Unsigned is a supported configuration and the common one: pkg's own
// signature_type defaults to NONE, and a repository on a private network may
// reasonably stop at TLS. So a missing key is logged at info and the
// generated catalogue goes out with one tar member instead of three.
//
// A reload never takes signing away, for the reason the apt loader does not:
// a client configured with signature_type: FINGERPRINTS has no unsigned
// fallback and fails `pkg update` outright. Serving unsigned is a deliberate
// act and needs a restart.
func (s *Server) loadPkgSigner() {
	// Whether a usable key is loaded, rather than whether anything is stored:
	// a stored failure is not something to keep signing with, and reporting
	// it as one would tell an operator their old key is still covering them
	// when nothing is.
	prev := s.pkgSign.Load()
	signing := prev != nil && prev.signer != nil
	paths := pkgsign.DefaultKeyPaths(s.cfg.StoragePath)

	fail := func(msg string, err error) {
		if signing {
			// A reload never takes signing away. Whatever went wrong, the
			// key already in memory keeps signing and the fault goes to the
			// journal, because a client configured with
			// signature_type: FINGERPRINTS has no unsigned fallback.
			s.logger.Error(msg+"; the previously loaded key keeps signing until a restart",
				"error", err, "searched", strings.Join(paths, ", "))
			return
		}
		s.logger.Error(msg+"; every generated pkg repository refuses its catalogue until the key loads",
			"error", err, "searched", strings.Join(paths, ", "))
		s.pkgSign.Store(&pkgSigning{err: err})
	}

	kr, err := pkgsign.Load(paths)
	switch {
	case errors.Is(err, pkgsign.ErrNoKey) && signing:
		s.logger.Warn("pkg signing key is gone from every search path; the loaded key keeps signing until a restart",
			"searched", strings.Join(paths, ", "))
		return
	case errors.Is(err, pkgsign.ErrNoKey):
		s.logger.Info("no pkg signing key installed; a generated pkg repository is served unsigned",
			"searched", strings.Join(paths, ", "))
		// Cleared rather than left as it was, so an operator who removes a
		// key that would not load gets the unsigned repository they asked
		// for instead of a refusal citing a file that is no longer there.
		s.pkgSign.Store(nil)
		return
	case err != nil:
		fail("pkg signing key present but unusable", err)
		return
	}
	pub, err := kr.PublicKey()
	if err != nil {
		fail("pkg signing key loaded but its public half will not render", err)
		return
	}
	member, err := kr.PublicKeyMember()
	if err != nil {
		fail("pkg signing key loaded but its archive member will not render", err)
		return
	}
	s.pkgSign.Store(&pkgSigning{signer: kr, pub: pub, pubMember: member, fingerprint: kr.Fingerprint()})
	s.logger.Info("pkg signing key loaded",
		"path", kr.Path(), "algorithm", kr.Algorithm(), "fingerprint", kr.Fingerprint())
}

// freeBSDGeneratedCatalog returns the named root file for a generated
// repository, building the set when the object listing or the signing key has
// moved since the last build.
//
// Rebuild is driven by the listing rather than by a timer alone. A list is one
// call; reading every package to hash it is one call per object, and a client
// polls `pkg update` on a cron. The metadata TTL is the second trigger, and
// covers the one case a listing cannot see: an object replaced under a key it
// already had.
func (s *Server) freeBSDGeneratedCatalog(ctx context.Context, store storage.ObjectStore, abi, repo, file string) ([]byte, error) {
	cacheKey := abi + "\x00" + repo
	prefix := manifest.FreeBSDRepoPrefix(abi, repo)

	keys, err := store.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("list the objects under %s: %w", prefix, err)
	}
	packages, err := freeBSDGeneratedObjects(keys, prefix)
	if err != nil {
		return nil, err
	}
	sign := s.pkgSign.Load()
	if sign != nil && sign.err != nil {
		// Refused rather than served unsigned. The operator installed a key,
		// so a client is configured to demand a signature; answering with an
		// unsigned catalogue trades a 500 that names the key for a `pkg
		// update` failure that names the signature and nothing else.
		return nil, fmt.Errorf("freebsd %s@%s: a pkg signing key is installed but cannot be loaded, and a generated catalogue is not served unsigned once one is: %w. "+
			"Fix the key and reload (systemctl reload bodega, or SIGHUP), or remove it from every searched path to publish this repository unsigned", repo, abi, sign.err)
	}
	fingerprint := ""
	if sign != nil {
		fingerprint = sign.fingerprint
	}
	objects := freeBSDObjectFingerprint(packages)

	if cat, ok := s.freeBSDCat.Load(cacheKey); ok {
		if built, ok := cat.(*freeBSDCatalog); ok && built.fresh(objects, fingerprint, s.cache.MetadataTTL) {
			return built.file(file)
		}
	}

	// One build per repository at a time. Three root files are read back to
	// back by every `pkg update`, and a fleet updating on the same cron would
	// otherwise each read every object in the repository.
	unlock := s.freeBSDBuild.lock(cacheKey)
	defer unlock()
	if cat, ok := s.freeBSDCat.Load(cacheKey); ok {
		if built, ok := cat.(*freeBSDCatalog); ok && built.fresh(objects, fingerprint, s.cache.MetadataTTL) {
			return built.file(file)
		}
	}

	built, err := s.buildFreeBSDCatalog(ctx, store, abi, repo, packages, sign, objects)
	if err != nil {
		return nil, err
	}
	s.freeBSDCat.Store(cacheKey, built)
	s.logger.Info("freebsd: generated a pkg catalogue",
		"abi", abi, "repo", repo, "packages", len(packages), "signed", sign != nil, "fingerprint", built.key)
	return built.file(file)
}

// fresh reports whether a cached build still describes the repository.
func (c *freeBSDCatalog) fresh(objects, key string, ttl time.Duration) bool {
	if c.objects != objects || c.key != key {
		return false
	}
	if ttl <= 0 {
		return false
	}
	return time.Since(c.builtAt) < ttl
}

// file picks one of the three, and names the set when asked for anything else
// rather than answering an empty body.
func (c *freeBSDCatalog) file(name string) ([]byte, error) {
	switch name {
	case manifest.FreeBSDMetaFile:
		return c.meta, nil
	case manifest.FreeBSDDataFile:
		return c.data, nil
	case manifest.FreeBSDCatalogFile:
		return c.catalogue, nil
	}
	return nil, fmt.Errorf("%s is not one of the generated repository-root files (%s)", name, strings.Join(manifest.FreeBSDCatalogFiles, ", "))
}

// freeBSDGeneratedObjects is the repository-relative path of every package
// object under the prefix, sorted.
//
// Sorted because the record order decides the archive bytes, and an unstable
// order is a catalogue whose digest changes on every rebuild for a repository
// that did not change. storage.ObjectStore.List already promises sorted keys;
// this does not depend on that promise, because one backend answering in walk
// order would be a refetch for every client with nothing reporting it.
func freeBSDGeneratedObjects(keys []string, prefix string) ([]string, error) {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		rel, ok := strings.CutPrefix(key, prefix)
		if !ok || rel == "" {
			continue
		}
		if _, reserved := manifest.FreeBSDReservedRoot(rel); reserved {
			// The repository root is the generator's own namespace. An
			// object stored under one of those names is unreachable — the
			// route answers these from the build — and a record naming one
			// would point a client's install at the catalogue.
			continue
		}
		if !strings.HasSuffix(rel, freeBSDPkgSuffix) {
			continue
		}
		if err := manifest.FreeBSDValidRepoPath(rel); err != nil {
			// Refused by name rather than skipped. The object is in the
			// store and an operator put it there, so a catalogue quietly
			// omitting it answers `pkg install` with "No packages available",
			// which is what a typo produces. Publishing it instead is worse:
			// the record resolves and the download 400s on the route that
			// built it.
			return nil, fmt.Errorf("the object at %s%s cannot be published: %w. Nothing was generated; rename the object or remove it", prefix, rel, err)
		}
		out = append(out, rel)
	}
	if len(out) > freeBSDGeneratedCap {
		return nil, fmt.Errorf("the repository holds %d package objects, over the %d-object cap for a generated catalogue; every one of them is read to build it, so nothing was generated. A repository this size is an upstream to mirror rather than one to host: drop `generated` and set `url`",
			len(out), freeBSDGeneratedCap)
	}
	sort.Strings(out)
	return out, nil
}

// freeBSDObjectFingerprint identifies an object set, so a cached build can be
// told from one taken before a package was added or removed.
func freeBSDObjectFingerprint(paths []string) string {
	h := sha256.New()
	for _, p := range paths {
		_, _ = io.WriteString(h, p)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// buildFreeBSDCatalog reads every package and renders the three root files.
func (s *Server) buildFreeBSDCatalog(ctx context.Context, store storage.ObjectStore, abi, repo string, packages []string, sign *pkgSigning, objects string) (*freeBSDCatalog, error) {
	prefix := manifest.FreeBSDRepoPrefix(abi, repo)
	read := make([]freeBSDRecord, 0, len(packages))
	for _, rel := range packages {
		rec, err := freeBSDRecordFor(ctx, store, prefix+rel, rel)
		if err != nil {
			// Refused rather than skipped. A catalogue silently missing one
			// package answers `pkg install` with "No packages available to
			// install matching", which is what a typo produces, and nothing
			// anywhere names the object that could not be read.
			return nil, fmt.Errorf("freebsd %s@%s: %w. Nothing was generated; remove the object or re-upload it", repo, abi, err)
		}
		read = append(read, rec)
	}
	records, aliases, err := freeBSDDistinctRecords(read, prefix)
	if err != nil {
		return nil, fmt.Errorf("freebsd %s@%s: %w", repo, abi, err)
	}
	if len(aliases) > 0 {
		// One line whatever the count, because a poudriere tree aliases most
		// of what it holds and a line each would be the repository twice over
		// in the journal on every rebuild.
		s.logger.Info("freebsd: the same package is stored under more than one key; the catalogue names one of each",
			"abi", abi, "repo", repo, "collapsed", len(aliases), "example", aliases[0])
	}

	cat := &freeBSDCatalog{objects: objects, builtAt: time.Now()}
	if sign != nil {
		cat.key = sign.fingerprint
	}

	if cat.catalogue, err = s.freeBSDArchive(freeBSDCatalogDoc, freeBSDPackagesiteDoc(records), sign); err != nil {
		return nil, fmt.Errorf("freebsd %s@%s: build %s: %w", repo, abi, manifest.FreeBSDCatalogFile, err)
	}
	data, err := freeBSDDataDocument(records)
	if err != nil {
		return nil, fmt.Errorf("freebsd %s@%s: build the data document: %w", repo, abi, err)
	}
	if cat.data, err = s.freeBSDArchive(freeBSDDataDoc, data, sign); err != nil {
		return nil, fmt.Errorf("freebsd %s@%s: build %s: %w", repo, abi, manifest.FreeBSDDataFile, err)
	}
	cat.meta = freeBSDMetaConf()
	return cat, nil
}

// freeBSDMetaConf is the repository descriptor pkg reads before anything else.
//
// It names only what this generator publishes. Upstream's carries filesite
// keys as well; naming a filesite bodega does not generate would have pkg ask
// for an archive that 404s the first time somebody runs `pkg which`.
func freeBSDMetaConf() []byte {
	return []byte("version = 2;\n" +
		"packing_format = \"tzst\";\n" +
		"manifests = \"" + freeBSDCatalogDoc + "\";\n" +
		"data = \"" + freeBSDDataDoc + "\";\n" +
		"manifests_archive = \"packagesite\";\n")
}

// freeBSDPackagesiteDoc renders packagesite.yaml: newline-delimited compact
// JSON, one record per package, despite what the extension says.
func freeBSDPackagesiteDoc(records []json.RawMessage) []byte {
	var buf bytes.Buffer
	for _, rec := range records {
		buf.Write(rec)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// freeBSDDataDocument renders the data member: one JSON object, where
// packagesite.yaml is one record per line.
//
// groups and expired_packages are emitted empty rather than omitted. pkg reads
// all three keys, and a document carrying only the one it happens to need
// today is a document that breaks on the version of pkg that needs another.
func freeBSDDataDocument(records []json.RawMessage) ([]byte, error) {
	doc := struct {
		Groups          []json.RawMessage `json:"groups"`
		Packages        []json.RawMessage `json:"packages"`
		ExpiredPackages []json.RawMessage `json:"expired_packages"`
	}{
		Groups:          []json.RawMessage{},
		Packages:        records,
		ExpiredPackages: []json.RawMessage{},
	}
	return json.Marshal(doc)
}

// freeBSDArchive packs one document into the compressed tarball pkg fetches,
// with the signature and the public key beside it.
//
// Three members when a key is installed and one when none is, which is the
// shape F19 recorded upstream: packagesite.yaml.sig, packagesite.yaml.pub and
// packagesite.yaml. The signature lives inside the archive rather than beside
// it — there is no .sig on the wire, and a client will not look for one.
//
// Every header carries a zero modification time, so a repository whose object
// set has not changed produces the same bytes on every build. A timestamp
// there would have each rebuild refetch the whole catalogue on every client
// for no change at all.
func (s *Server) freeBSDArchive(doc string, body []byte, sign *pkgSigning) ([]byte, error) {
	var members []freeBSDMember
	if sign != nil {
		sig, err := sign.signer.Sign(body)
		if err != nil {
			return nil, fmt.Errorf("sign %s: %w", doc, err)
		}
		// Verified here, against the key about to be published beside it,
		// rather than left for a client to discover. A signature that does
		// not verify reaches the operator as a pkg repository failure days
		// later, naming the signature and never the key that made it.
		if err := pkgsign.Verify(sign.pub, body, sig); err != nil {
			return nil, fmt.Errorf("the %s signature does not verify against the public key it ships with, so nothing was published: %w", doc, err)
		}
		members = append(members,
			freeBSDMember{name: doc + ".sig", data: sig},
			freeBSDMember{name: doc + ".pub", data: sign.pubMember},
		)
	}
	members = append(members, freeBSDMember{name: doc, data: body})

	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		return nil, fmt.Errorf("open a zstd writer: %w", err)
	}
	tw := tar.NewWriter(zw)
	for _, m := range members {
		hdr := &tar.Header{
			Name:     m.name,
			Mode:     0o644,
			Size:     int64(len(m.data)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write the %s header: %w", m.name, err)
		}
		if _, err := tw.Write(m.data); err != nil {
			return nil, fmt.Errorf("write %s: %w", m.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close the tar stream: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close the zstd stream: %w", err)
	}
	return out.Bytes(), nil
}

// freeBSDMember is one tar member of a generated archive.
type freeBSDMember struct {
	name string
	data []byte
}

// freeBSDRecord is one catalogue record and the two things a catalogue must
// keep straight about it: the bytes it points at, and the package pkg will
// index it as.
//
// The two are not the same question and neither answers the other. One package
// stored under two keys — a poudriere alias, a copy — is two objects with one
// identity and one sum, and belongs in the catalogue once. Two builds of that
// package are two objects with one identity and two sums, and belong in no
// catalogue at all: pkg indexes both under one manifestdigest and refuses the
// pair. See freeBSDPkgIdentity for what pkg counts as one package.
type freeBSDRecord struct {
	repoPath string
	body     json.RawMessage
	sum      string
	identity string
	label    string
}

// freeBSDDistinctRecords is the set of records a catalogue may publish, in the
// order it was given them, with each package named once.
//
// The first record of an identity is the one kept, so the repopath a client
// downloads is the lexicographically smallest key the package is stored under
// and does not move while the store does not. An alias that appears or
// disappears leaves the record it collapsed into untouched, which is what
// keeps the catalogue's bytes — and therefore every client's refetch — tied to
// the packages rather than to the paths.
//
// A second record of an identity over different bytes fails the build and
// names both objects. Publishing either one would be choosing which package
// an operator meant, and publishing both is not on offer: pkg creates
// packages_digest UNIQUE after loading the records, so a catalogue carrying
// the pair fails `pkg update` outright and the client keeps the catalogue it
// had. A 500 naming the two objects is the same outage with the cause in it.
func freeBSDDistinctRecords(records []freeBSDRecord, prefix string) ([]json.RawMessage, []string, error) {
	bodies := make([]json.RawMessage, 0, len(records))
	kept := make(map[string]freeBSDRecord, len(records))
	var aliases []string
	for _, rec := range records {
		first, seen := kept[rec.identity]
		if !seen {
			kept[rec.identity] = rec
			bodies = append(bodies, rec.body)
			continue
		}
		if first.sum == rec.sum {
			aliases = append(aliases, prefix+rec.repoPath+" (published as "+first.repoPath+")")
			continue
		}
		return nil, nil, fmt.Errorf("%s%s and %s%s are two builds of one package (%s) and differ in their bytes (sha256 %s against %s). "+
			"pkg indexes both under one manifestdigest and refuses a catalogue holding the pair, so nothing was generated and the repository serves the catalogue it was serving before. "+
			"Remove the object that should not be published, or give one of the two a version of its own",
			prefix, first.repoPath, prefix, rec.repoPath, rec.label, first.sum, rec.sum)
	}
	return bodies, aliases, nil
}

// freeBSDRecordFor builds one packagesite.yaml record from a stored package.
//
// The record is the package's own +COMPACT_MANIFEST plus the four fields only
// the repository can know: where the bytes are, how big they are, and their
// digest. That is what `pkg repo` does, and copying the manifest through
// rather than re-deriving it is what keeps a field pkg reads and bodega has
// never heard of — an annotation, a new option group — from being dropped on
// the way.
func freeBSDRecordFor(ctx context.Context, store storage.ObjectStore, key, repoPath string) (freeBSDRecord, error) {
	var out freeBSDRecord
	res, err := store.GetStream(ctx, key)
	if err != nil {
		return out, fmt.Errorf("read %s: %w", key, err)
	}
	if res == nil {
		// Listed a moment ago and gone now: a delete landed between the
		// listing and the read. Reported rather than skipped, because the
		// next build lists again and the repository is correct then.
		return out, fmt.Errorf("%s was listed but is no longer in the store", key)
	}
	defer func() { _ = res.Body.Close() }()

	hasher := sha256.New()
	size := &countingWriter{}
	teed := io.TeeReader(res.Body, io.MultiWriter(hasher, size))

	compact, err := freeBSDCompactManifest(teed)
	if err != nil {
		return out, fmt.Errorf("%s: %w", key, err)
	}
	// The rest of the object is drained without decompressing it, because the
	// digest is over the whole .pkg file as a client downloads it and the
	// manifest member is only its first few kilobytes.
	if _, err := io.Copy(io.Discard, teed); err != nil {
		return out, fmt.Errorf("read %s to its end for a digest: %w", key, err)
	}

	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(compact))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		return out, fmt.Errorf("%s: %s is not a JSON object: %w", key, freeBSDManifestMember, err)
	}
	if len(fields["name"]) == 0 || len(fields["version"]) == 0 {
		return out, fmt.Errorf("%s: %s names no package name and version, so no client could resolve it", key, freeBSDManifestMember)
	}

	// Taken before the repository's own fields are written over the manifest,
	// because none of them reaches pkg's digest and adding them here would
	// make two names for one package look like two packages.
	identity, err := freeBSDPkgIdentity(fields)
	if err != nil {
		return out, fmt.Errorf("%s: %s: %w", key, freeBSDManifestMember, err)
	}

	// repopath is what F19's serving path reads as the only authority on
	// where an object lives, so it is written from the key this record was
	// built from rather than from anything inside the package. A record whose
	// repopath disagrees with the key resolves an install and then 404s,
	// after `pkg update` has already reported success.
	rel, err := json.Marshal(repoPath)
	if err != nil {
		return out, err
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	fields["repopath"] = rel
	fields["path"] = rel
	fields["sum"] = mustJSON(sum)
	fields["pkgsize"] = json.RawMessage(fmt.Sprintf("%d", size.n))

	body, err := json.Marshal(fields)
	if err != nil {
		return out, err
	}
	return freeBSDRecord{
		repoPath: repoPath,
		body:     body,
		sum:      sum,
		identity: identity,
		label:    freeBSDRecordLabel(fields),
	}, nil
}

// freeBSDRecordLabel names a package the way an operator wrote it down, for
// an error about two objects claiming to be it.
func freeBSDRecordLabel(fields map[string]json.RawMessage) string {
	var name, version string
	_ = json.Unmarshal(fields["name"], &name)
	_ = json.Unmarshal(fields["version"], &version)
	if version == "" {
		return name
	}
	return name + "-" + version
}

// mustJSON renders a string this package composed, where a marshalling error
// is not reachable.
func mustJSON(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

// countingWriter totals the bytes written through it, which is a package's
// pkgsize as a client downloads it.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// freeBSDCompactManifest extracts +COMPACT_MANIFEST from one .pkg archive.
func freeBSDCompactManifest(r io.Reader) ([]byte, error) {
	dec, closeDec, err := freeBSDPkgDecompressor(bufio.NewReader(r))
	if err != nil {
		return nil, err
	}
	defer closeDec()

	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read the package archive: %w", err)
		}
		if hdr.Name != freeBSDManifestMember {
			continue
		}
		if hdr.Size > freeBSDManifestCap {
			return nil, fmt.Errorf("%s is %d bytes, over the %d-byte cap", freeBSDManifestMember, hdr.Size, freeBSDManifestCap)
		}
		body, err := io.ReadAll(io.LimitReader(tr, freeBSDManifestCap+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", freeBSDManifestMember, err)
		}
		if int64(len(body)) > freeBSDManifestCap {
			return nil, fmt.Errorf("%s runs past the %d-byte cap though its tar header declared it smaller", freeBSDManifestMember, freeBSDManifestCap)
		}
		return body, nil
	}
	return nil, fmt.Errorf("the archive carries no %s member, so nothing in it says what package it is; this is not a pkg package", freeBSDManifestMember)
}

// freeBSDPkgDecompressor wraps a package archive in the decoder its magic
// bytes name, and returns a closer for decoders that hold one.
//
// Sniffed rather than taken from the extension, which is the lesson the
// mirror learned against a real repository: the extension names the archive
// and not the codec, and every pkg package since 1.17 is spelled .pkg
// whatever is inside it. xz is refused by name because Go ships no decoder
// for it, so the honest answer is that this package cannot be read here
// rather than a tar error four frames down.
func freeBSDPkgDecompressor(br *bufio.Reader) (io.Reader, func(), error) {
	magic, err := br.Peek(6)
	if err != nil && len(magic) == 0 {
		return nil, nil, fmt.Errorf("the object is empty, so it is not a pkg package")
	}
	switch {
	case bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		dec, err := zstd.NewReader(br)
		if err != nil {
			return nil, nil, fmt.Errorf("open a zstd reader: %w", err)
		}
		return dec.IOReadCloser(), dec.Close, nil
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, fmt.Errorf("open a gzip reader: %w", err)
		}
		return gz, func() { _ = gz.Close() }, nil
	case bytes.HasPrefix(magic, []byte("BZh")):
		return bzip2.NewReader(br), func() {}, nil
	case bytes.HasPrefix(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return nil, nil, fmt.Errorf("the package is xz-compressed, which needs a decoder Go does not ship; rebuild it with pkg 1.17 or later, which packs zstd")
	}
	// An uncompressed tar is legal and pkg writes one under
	// packing_format = "tar", so it is the fallback rather than a refusal.
	return br, func() {}, nil
}
