package builder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// ---- FreeBSD pkg catalogue -------------------------------------------------
//
// packagesite.pkg is a compressed tarball carrying three members:
// packagesite.yaml.sig, packagesite.yaml.pub and packagesite.yaml. The
// signature is inside the archive rather than beside it, which is what makes a
// byte-exact copy of the archive carry FreeBSD's own attestation to a client
// that has only the stock fingerprint. Nothing here rewrites the archive; it
// reads one member out of a copy to learn which objects the catalogue names.
//
// packagesite.yaml is newline-delimited compact JSON despite the extension.

const (
	// freeBSDCatalogMemberCap bounds the decompressed packagesite.yaml, and is
	// the only thing between a hostile repository and an unbounded
	// decompression on the build host. pkg.freebsd.org's FreeBSD:14:amd64
	// latest/ measures 63.4 MB across 38,325 records, so the cap is an order
	// of magnitude of headroom over the widest real one rather than a guess.
	freeBSDCatalogMemberCap = 1 << 30 // 1 GiB

	// freeBSDCatalogLineCap bounds one record. A pkg manifest record carries
	// its whole dependency list and option set inline; the widest in that
	// same catalogue is 44,005 bytes.
	freeBSDCatalogLineCap = 8 << 20 // 8 MiB

	// freeBSDMetaCap bounds meta.conf. Upstream's is 168 bytes.
	freeBSDMetaCap = 64 << 10
)

// freeBSDRecord is the one member of a packagesite.yaml record this mirror
// reads. The record carries a full pkg manifest; repopath is where the bytes
// are, and the rest is the client's business.
type freeBSDRecord struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	RepoPath string `json:"repopath"`
}

// freeBSDPackingFormat reads packing_format out of a meta.conf.
//
// meta.conf is plain unsigned UCL and is the first request every `pkg update`
// makes. The format is read from it rather than inferred from the .pkg
// extension, because the extension names the archive and not the codec: a
// repository built by pkg 1.16 serves packing_format = "txz" under files
// spelled .pkg, and guessing zstd for them decodes garbage.
//
// An absent key is reported rather than defaulted. A repository whose
// meta.conf does not say is one this mirror has not been taught to read, and
// picking a codec for it would fail later, inside the tar reader, where the
// error names neither the repository nor the key that was missing.
func freeBSDPackingFormat(meta []byte) (string, error) {
	format, err := freeBSDMetaValue(meta, "packing_format")
	if err != nil {
		return "", err
	}
	if format == "" {
		return "", fmt.Errorf("meta.conf names no packing_format, so the codec of packagesite.pkg is unknown; confirm the URL is a pkg repository root and not an index page")
	}
	return format, nil
}

// freeBSDDataMember is the archive member data.pkg carries its package records
// in, which meta.conf names under "data" and every current repository spells
// "data".
//
// Defaulted rather than refused when the key is absent: meta.conf version 1
// predates the key, and a repository publishing data.pkg under the customary
// name is not one to refuse to mirror. A member that is then missing from the
// archive is reported by name, which is the case where the default was wrong.
func freeBSDDataMember(meta []byte) (string, error) {
	member, err := freeBSDMetaValue(meta, "data")
	if err != nil {
		return "", err
	}
	if member == "" {
		return "data", nil
	}
	return member, nil
}

// freeBSDMetaValue reads one key out of a meta.conf, or "" when it is absent.
//
// meta.conf is plain unsigned UCL: one key per line, an optional trailing
// semicolon, and "#" to end of line. Nothing here needs a UCL parser, and a
// dependency that could reach a repository's own bytes is a larger surface
// than the four keys this mirror reads.
func freeBSDMetaValue(meta []byte, key string) (string, error) {
	if len(meta) > freeBSDMetaCap {
		return "", fmt.Errorf("meta.conf is %d bytes, over the %d-byte cap; this is not a pkg repository metadata file", len(meta), freeBSDMetaCap)
	}
	for _, line := range strings.Split(string(meta), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != key {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.TrimSuffix(value, ";")
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if value == "" {
			continue
		}
		return value, nil
	}
	return "", nil
}

// freeBSDDecompressor wraps r in the decoder packing_format names, and returns
// a closer for decoders that hold one.
//
// txz is refused by name rather than left to fail as a tar error. It was the
// default before pkg 1.17 and the Go standard library has no xz reader, so the
// honest answer is that this mirror cannot enumerate such a repository's
// catalogue — with the repository and the format in the message, because the
// next step is the operator's, not a retry.
func freeBSDDecompressor(format string, r io.Reader) (io.Reader, func(), error) {
	switch format {
	case "tzst", "zst", "zstd":
		dec, err := zstd.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("open zstd reader: %w", err)
		}
		return dec.IOReadCloser(), dec.Close, nil
	case "tgz", "gz", "gzip":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("open gzip reader: %w", err)
		}
		return gz, func() { _ = gz.Close() }, nil
	case "tbz", "bz2", "bzip2":
		return bzip2.NewReader(r), func() {}, nil
	case "tar", "none", "plain":
		return r, func() {}, nil
	case "txz", "xz":
		return nil, nil, fmt.Errorf("packing_format is %q, which this mirror cannot read: xz needs a decoder Go does not ship. "+
			"Mirror a repository built by pkg 1.17 or later (packing_format = \"tzst\"), or serve this one in proxy mode, where the catalogue is never parsed", format)
	}
	return nil, nil, fmt.Errorf("packing_format is %q, which is not one of tzst, tgz, tbz or tar", format)
}

// freeBSDCatalogRepoPaths returns the repopath of every record in a catalogue
// archive, in the order the catalogue lists them.
//
// The catalogue is the only authority on where a package's bytes are, and the
// two repositories on pkg.freebsd.org spell it differently: latest/ publishes
// "All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg" and base_latest/ publishes
// "./Hashed/FreeBSD-telnet-14.snap20260920075547~2$ea5o6tyi.pkg". Neither is
// derivable from a name and a version, and All/ answers 403 upstream, so
// there is no listing to fall back on.
func freeBSDCatalogRepoPaths(archive string, format string) ([]string, error) {
	var out []string
	err := freeBSDArchiveMember(archive, format, "packagesite.yaml", func(r io.Reader) error {
		var readErr error
		out, readErr = freeBSDRepoPathsFrom(r)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// freeBSDDataRepoPaths returns the repopath of every record in data.pkg.
//
// data.pkg is the archive pkg_repo_fetch_data_fd reads, and its member carries
// one record per package exactly as packagesite.yaml does — 535 of them in
// base_latest, 38,325 in latest, each with the same repopath the catalogue
// names. It is read because it is published: an archive naming an object this
// mirror never fetched is a repository that resolves an install and then 404s,
// whichever of the two documents the client happened to read.
//
// The document is one JSON object rather than a record per line, so it is
// walked with a decoder rather than a scanner: latest's runs to ~100 MB
// decompressed and only one field of each record is wanted.
func freeBSDDataRepoPaths(archive, format, member string) ([]string, error) {
	var out []string
	err := freeBSDArchiveMember(archive, format, member, func(r io.Reader) error {
		var readErr error
		out, readErr = freeBSDDataPathsFrom(r)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// freeBSDMirrorSet is every object the two published archives name between
// them, in catalogue order with data.pkg's extras after it.
//
// The union rather than either one alone. The two archives are fetched a
// moment apart from a repository that rebuilds continuously, so they can
// describe different generations; both are then published byte for byte,
// because rewriting either destroys the signature it carries. Mirroring the
// union is what makes "no published archive names an object this store does
// not hold" true of the pair rather than of the catalogue only.
func freeBSDMirrorSet(catalogArchive, dataArchive, format, dataMember string) ([]string, error) {
	paths, err := freeBSDCatalogRepoPaths(catalogArchive, format)
	if err != nil {
		return nil, err
	}
	dataPaths, err := freeBSDDataRepoPaths(dataArchive, format, dataMember)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(paths)+len(dataPaths))
	for _, p := range paths {
		seen[p] = true
	}
	for _, p := range dataPaths {
		if seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	return paths, nil
}

// freeBSDArchiveMember opens one member of a repository archive and hands it
// to read, bounded by freeBSDCatalogMemberCap.
//
// The member is matched on its base name because the two archives spell their
// paths differently and neither prefix is a fact worth depending on. Every
// other member — the .sig and the .pub that make a byte-exact copy carry
// FreeBSD's own attestation — is walked past untouched.
func freeBSDArchiveMember(archive, format, wantBase string, read func(io.Reader) error) error {
	f, err := os.Open(archive) //nolint:gosec // G304: the path is composed by this package under the build root.
	if err != nil {
		return fmt.Errorf("open %s: %w", archive, err)
	}
	defer func() { _ = f.Close() }()

	dec, closeDec, err := freeBSDDecompressor(format, f)
	if err != nil {
		return fmt.Errorf("%s: %w", archive, err)
	}
	defer closeDec()

	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", archive, err)
		}
		if path.Base(hdr.Name) != wantBase {
			continue
		}
		if err := read(io.LimitReader(tr, freeBSDCatalogMemberCap)); err != nil {
			return fmt.Errorf("%s: %w", archive, err)
		}
		return nil
	}
	return fmt.Errorf("%s carries no %s member, so nothing in it says which objects this repository publishes", archive, wantBase)
}

// freeBSDDataPathsFrom reads repopaths out of the packages array of a data
// document, skipping the groups and expired_packages arrays beside it.
func freeBSDDataPathsFrom(r io.Reader) ([]string, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read the data member: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("the data member opens with %v rather than a JSON object, so it is not a pkg data document", tok)
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read the data member: %w", err)
		}
		if name, _ := key.(string); name != "packages" {
			// Skipped by walking its tokens rather than decoding it: a value
			// decoded to hold it would put a hostile repository's whole
			// document in memory, which is what the cap above exists to stop.
			if err := freeBSDSkipJSONValue(dec); err != nil {
				return nil, fmt.Errorf("read the data member: %w", err)
			}
			continue
		}
		return freeBSDDataPackages(dec)
	}
	// A document naming no packages names no objects. groups and
	// expired_packages are the other two keys, and both are lists of names
	// rather than of bytes.
	return nil, nil
}

// freeBSDDataPackages decodes the packages array one record at a time.
func freeBSDDataPackages(dec *json.Decoder) ([]string, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read the packages array: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, fmt.Errorf("the data member's packages key holds %v rather than an array", tok)
	}
	var out []string
	seen := make(map[string]bool)
	for record := 1; dec.More(); record++ {
		var rec freeBSDRecord
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("data record %d is not a JSON record: %w", record, err)
		}
		rel, err := freeBSDRecordPath(rec, fmt.Sprintf("data record %d", record))
		if err != nil {
			return nil, err
		}
		if seen[rel] {
			continue
		}
		seen[rel] = true
		out = append(out, rel)
	}
	return out, nil
}

// freeBSDSkipJSONValue consumes the next value without holding it.
func freeBSDSkipJSONValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// freeBSDRecordPath is the repository-relative path one record names. where
// identifies the record for a message an operator reads without the document
// in front of them.
func freeBSDRecordPath(rec freeBSDRecord, where string) (string, error) {
	if rec.RepoPath == "" {
		return "", fmt.Errorf("%s (%s-%s) names no repopath, so nothing can say where its bytes are", where, rec.Name, rec.Version)
	}
	rel, err := cleanFreeBSDRepoPath(rec.RepoPath)
	if err != nil {
		return "", fmt.Errorf("%s (%s-%s): %w", where, rec.Name, rec.Version, err)
	}
	return rel, nil
}

// freeBSDRepoPathsFrom reads repopaths out of a packagesite.yaml stream.
//
// Streamed rather than read whole: the document is one record per line and
// runs to nine figures of bytes for a full ABI, and only one field of each
// record is wanted.
func freeBSDRepoPathsFrom(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), freeBSDCatalogLineCap)

	var out []string
	seen := make(map[string]bool)
	for line := 1; sc.Scan(); line++ {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec freeBSDRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("packagesite.yaml line %d is not a JSON record: %w", line, err)
		}
		rel, err := freeBSDRecordPath(rec, fmt.Sprintf("packagesite.yaml line %d", line))
		if err != nil {
			return nil, err
		}
		if seen[rel] {
			continue
		}
		seen[rel] = true
		out = append(out, rel)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read packagesite.yaml: %w", err)
	}
	return out, nil
}

// cleanFreeBSDRepoPath returns the repository-relative path a repopath names,
// or an error when it names something outside the repository.
//
// The two observed layouts spell the same idea differently, and the
// difference is a "." segment rather than a directory: pkg.freebsd.org's
// latest/ publishes "All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg" while its
// base_latest/ publishes "./Hashed/FreeBSD-telnet-14.snap...~2$ea5o6tyi.pkg".
// A "." is dropped rather than refused because every HTTP client normalizes
// it out before the request leaves — Go's own ServeMux redirects an unclean
// path — so keeping it would key the object under a path no request can ever
// spell, and the mirror would serve 404 for every base package it holds.
//
// ".." is a different answer and stays refused. The catalogue is untrusted
// from the mirror's point of view: it decides both the URL fetched and the
// local path written, so a record reading "../../../../etc/ssh/sshd_config"
// would have the mirror overwrite a file on the build host and then serve it
// back under a signed catalogue. Refused rather than cleaned, because
// cleaning a traversal away turns a repository this must not touch into one
// it silently accepts.
func cleanFreeBSDRepoPath(p string) (string, error) {
	switch {
	case strings.HasPrefix(p, "/"):
		return "", fmt.Errorf("repopath %q is absolute; a repopath is relative to the repository root", p)
	case strings.Contains(p, `\`):
		return "", fmt.Errorf("repopath %q holds a backslash, which no pkg repository publishes", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("repopath %q holds a control character at U+%04X", p, r)
		}
	}
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for i, seg := range segs {
		switch seg {
		case "..":
			return "", fmt.Errorf("repopath %q holds a %q segment, which resolves outside the repository", p, seg)
		case ".":
			continue
		case "":
			// A trailing empty segment is a directory, which names no
			// artifact; an interior one is a repopath nothing can request.
			return "", fmt.Errorf("repopath %q holds an empty segment at position %d, so it names no object", p, i)
		}
		out = append(out, seg)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("repopath %q resolves to the repository root, which names no object", p)
	}
	return strings.Join(out, "/"), nil
}
