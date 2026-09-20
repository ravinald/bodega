package manifest

import (
	"context"
	"crypto/md5" //nolint:gosec // MD5 used for manifest integrity, not cryptographic security.
	"fmt"
	"sort"
	"strings"
)

// Integrity verdicts, in the order a reader should worry about them.
const (
	// IntegrityOK means the sidecar exists and agrees with the manifest.
	IntegrityOK = "OK"
	// IntegrityFail means the sidecar exists and disagrees: someone edited
	// the manifest without going through a writer.
	IntegrityFail = "FAIL"
	// IntegrityUnverifiable means no sidecar exists, so nothing can be
	// compared. It is not a pass; see Store.VerifyIntegrity.
	IntegrityUnverifiable = "UNVERIFIABLE"
	// IntegrityError means the manifest or its sidecar could not be read.
	IntegrityError = "ERROR"
)

// IntegrityResult is one manifest object's verdict.
type IntegrityResult struct {
	// Path is the store-relative object name, e.g. "binary/hello/manifest.json".
	Path string
	// Type is the package type the object belongs to, "" for the store-wide
	// index.json, graph.json and metrics.json.
	Type string
	// Status is one of the Integrity* constants.
	Status string
	// Digest is the stored sidecar digest, empty when there is none.
	Digest string
	// Err carries the read failure behind IntegrityError.
	Err error
}

// Passed reports whether this object was compared against a sidecar and matched.
// UNVERIFIABLE is deliberately not a pass: a missing sidecar means nobody
// checked, and reporting that as success is how `pkg verify` came to answer
// yes to a manifest edited by hand.
func (r IntegrityResult) Passed() bool { return r.Status == IntegrityOK }

// md5Path returns the companion .md5 object name for a manifest.
func md5Path(name string) string { return name + ".md5" }

// computeMD5 returns the lowercase hex MD5 digest of data.
func computeMD5(data []byte) string {
	sum := md5.Sum(data) //nolint:gosec
	return fmt.Sprintf("%x", sum)
}

// isManifestObject reports whether a store-relative name is something the
// store itself wrote: one of the three files at the root, or a package
// manifest at <type>/<safeName>/manifest.json.
//
// It is a whitelist of shapes rather than "ends in .json" because a local
// install can be configured with manifest_dir pointing at a directory that
// holds other JSON — config.json is the common one — and a walk that claimed
// those would report the install unverifiable over a file no writer here owns.
// It does not gate on AllTypes: a store still holding manifests of a retired
// type should verify them, not quietly stop looking.
func isManifestObject(name string) bool {
	switch name {
	case indexFile, graphFile, metricsFile:
		return true
	}
	segs := strings.Split(name, "/")
	return len(segs) == 3 && segs[2] == manifestFile
}

// writeManifest stores data at name and its MD5 sidecar at name+".md5" in one
// call. Every manifest writer goes through here rather than calling
// Backend.Write directly, so a new writer cannot omit the sidecar by copying
// the shape of its neighbor: `pkg verify` treats a manifest with no sidecar as
// unverifiable, and one writer skipping it takes that object out of the
// integrity check for good.
//
// The manifest lands first. If the sidecar write then fails the caller sees an
// error and the object is left unverifiable, which `pkg verify` reports and
// exits non-zero on. The other order would leave a sidecar describing bytes
// that were never stored, and that reads as tampering.
func writeManifest(ctx context.Context, b Backend, name string, data []byte) error {
	if err := b.Write(ctx, name, data); err != nil {
		return err
	}
	if err := b.Write(ctx, md5Path(name), []byte(computeMD5(data)+"\n")); err != nil {
		return fmt.Errorf("write %s to %s: %w", md5Path(name), b.Label(), err)
	}
	return nil
}

// deleteManifest removes a manifest and its sidecar. A sidecar outliving its
// manifest would be read as an unverifiable object by the next walk.
func deleteManifest(ctx context.Context, b Backend, name string) error {
	if err := b.Delete(ctx, name); err != nil {
		return err
	}
	return b.Delete(ctx, md5Path(name))
}

// readMD5 returns the stored sidecar digest for name, or "" when there is none.
func readMD5(ctx context.Context, b Backend, name string) (string, error) {
	data, err := b.Read(ctx, md5Path(name))
	if err != nil {
		return "", fmt.Errorf("read %s from %s: %w", md5Path(name), b.Label(), err)
	}
	return strings.TrimSpace(string(data)), nil
}

// typeOf returns the package type a store-relative object name belongs to.
// The store-wide index.json, graph.json and metrics.json sit at the root and
// belong to no type, so they return "".
func typeOf(name string) string {
	typ, _, ok := strings.Cut(name, "/")
	if !ok {
		return ""
	}
	return typ
}

// VerifyIntegrity reads every manifest object in the store and compares it
// against its MD5 sidecar. Results come back sorted by path, one per object.
//
// It walks the backend rather than probing a path per package type. The store
// keeps one directory per package (<type>/<safeName>/manifest.json) plus three
// files at the root; a walk that built <type>.json from AllTypes was looking
// at a flat layout the store has not used, so it reported every type MISSING
// while the manifests sat one level down.
func (s *Store) VerifyIntegrity(ctx context.Context) ([]IntegrityResult, error) {
	b := s.resolveBackend()
	names, err := b.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list manifests in %s: %w", b.Label(), err)
	}

	var out []IntegrityResult
	for _, name := range names {
		if !isManifestObject(name) {
			continue
		}
		res := IntegrityResult{Path: name, Type: typeOf(name)}

		data, readErr := b.Read(ctx, name)
		switch {
		case readErr != nil:
			res.Status, res.Err = IntegrityError, readErr
		case data == nil:
			// Listed and then gone: a concurrent delete, not a tamper.
			continue
		default:
			stored, md5Err := readMD5(ctx, b, name)
			switch {
			case md5Err != nil:
				res.Status, res.Err = IntegrityError, md5Err
			case stored == "":
				res.Status = IntegrityUnverifiable
			default:
				res.Digest = stored
				if stored == computeMD5(data) {
					res.Status = IntegrityOK
				} else {
					res.Status = IntegrityFail
				}
			}
		}
		out = append(out, res)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// RestampMD5 recomputes the sidecar for every manifest of one package type,
// or for the whole store when typ is empty. It returns the paths it rewrote.
//
// This is the --break-glass-update-md5 escape hatch: it stamps whatever the
// manifest now says, so it turns a FAIL into an OK without looking at why they
// disagreed. That is the point, and it is why it is a flag on the root rather
// than a verb anyone reaches for.
func (s *Store) RestampMD5(ctx context.Context, typ string) ([]string, error) {
	b := s.resolveBackend()
	prefix := ""
	if typ != "" {
		prefix = typ + "/"
	}
	names, err := b.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("list %s in %s: %w", prefix, b.Label(), err)
	}

	var stamped []string
	for _, name := range names {
		if !isManifestObject(name) {
			continue
		}
		data, readErr := b.Read(ctx, name)
		if readErr != nil {
			return stamped, fmt.Errorf("read %s from %s: %w", name, b.Label(), readErr)
		}
		if data == nil {
			continue
		}
		if err := b.Write(ctx, md5Path(name), []byte(computeMD5(data)+"\n")); err != nil {
			return stamped, fmt.Errorf("write %s to %s: %w", md5Path(name), b.Label(), err)
		}
		stamped = append(stamped, name)
	}
	sort.Strings(stamped)
	return stamped, nil
}
