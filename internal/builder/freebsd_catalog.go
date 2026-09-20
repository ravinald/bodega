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
	if len(meta) > freeBSDMetaCap {
		return "", fmt.Errorf("meta.conf is %d bytes, over the %d-byte cap; this is not a pkg repository metadata file", len(meta), freeBSDMetaCap)
	}
	for _, line := range strings.Split(string(meta), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "packing_format" {
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
	return "", fmt.Errorf("meta.conf names no packing_format, so the codec of packagesite.pkg is unknown; confirm the URL is a pkg repository root and not an index page")
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
	f, err := os.Open(archive) //nolint:gosec // G304: the path is composed by this package under the build root.
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", archive, err)
	}
	defer func() { _ = f.Close() }()

	dec, closeDec, err := freeBSDDecompressor(format, f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", archive, err)
	}
	defer closeDec()

	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", archive, err)
		}
		// The signature and the public key travel in the same archive and are
		// deliberately untouched: they are the attestation a byte-exact copy
		// carries to the client.
		if path.Base(hdr.Name) != "packagesite.yaml" {
			continue
		}
		return freeBSDRepoPathsFrom(io.LimitReader(tr, freeBSDCatalogMemberCap))
	}
	return nil, fmt.Errorf("%s carries no packagesite.yaml member, so it is not a pkg catalogue", archive)
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
		if rec.RepoPath == "" {
			return nil, fmt.Errorf("packagesite.yaml line %d (%s-%s) names no repopath, so nothing can say where its bytes are",
				line, rec.Name, rec.Version)
		}
		rel, err := cleanFreeBSDRepoPath(rec.RepoPath)
		if err != nil {
			return nil, fmt.Errorf("packagesite.yaml line %d (%s-%s): %w", line, rec.Name, rec.Version, err)
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
