package main

import (
	"context"
	"crypto/md5"  //nolint:gosec // reads a digest recorded by apt, not a security primitive
	"crypto/sha1" //nolint:gosec // same: verifying a recorded digest, not signing
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

func newMoveCmd(gf *globalFlags) *cobra.Command {
	var toBackend string
	var deleteSource bool

	cmd := &cobra.Command{
		Use:   "move <type> <name>[@<version>] --to <backend>",
		Short: "Copy a package's artifacts to another storage backend",
		Long: `move copies the objects backing a package's versions to another named backend
and repoints the manifest at the copy.

Ordering is the whole design. Every object is copied, verified at the
destination, and only then does the manifest change; the source copy is left
alone unless --delete-source says otherwise. Both backends answer a missing
object with "not found" rather than an error, so an artifact lost between the
delete and the manifest write would be indistinguishable from one that was
never uploaded — there would be nothing left to say it had ever existed.

Without a version, every version of the package moves. Versions already on the
destination are skipped, so an interrupted move can be re-run. A frozen version
refuses the whole command, mirroring delete.

apt, git and pypi are not movable. All three upload as a whole directory with
no per-version granularity, so placing one package of the type away from the
rest splits a tree nothing can reunite, and 'bodega build sync' would refuse
for the whole type afterwards. Point storage_by_type at the backend you want
and re-upload instead.

Two backend names resolving to one directory or bucket is refused too, before
anything is copied. Each object would land on the one it was read from, and
--delete-source would then remove the only copy there is.`,
		Example: `  bodega pkg move binary awscli-v2 --to bulk
  bodega pkg move npm @bitwarden/cli@2026.4.0 --to archive
  bodega pkg move gomod github.com/aws/aws-sdk-go-v2@v1.30.0 --to archive --delete-source`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			name, version := splitVersionArg(args[1])
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q — must be one of: %s", t, strings.Join(manifest.AllTypes, ", "))
			}
			if toBackend == "" {
				return fmt.Errorf("--to is required: name the backend to move to")
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			if err := checkBackendName(cfg, toBackend); err != nil {
				return fmt.Errorf("--to: %w", err)
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			ctx := backgroundCtx()

			stores, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}
			dst, err := stores.ByName(toBackend)
			if err != nil {
				return err
			}

			pm, err := store.GetPackage(ctx, t, name)
			if err != nil {
				return fmt.Errorf("get %s/%s: %w", t, name, err)
			}
			if pm == nil {
				return fmt.Errorf("%s entry %q not found", t, name)
			}

			targets, err := selectForMove(stores, dst, pm, version, toBackend)
			if err != nil {
				return err
			}

			m := &mover{
				stores:  stores,
				dst:     dst,
				dstName: toBackend,
				store:   store,
				spool:   filepath.Join(cfg.BuildRoot, "tmp"),
				out:     os.Stdout,
				del:     deleteSource,
			}
			for _, i := range targets {
				if err := m.moveVersion(ctx, pm, i); err != nil {
					return err
				}
			}
			notifyServer(gf)
			return nil
		},
	}

	cmd.Flags().StringVar(&toBackend, "to", "", "Name of the destination storage backend (required)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false,
		"Delete the source objects after the manifest points at the copy (default: leave them)")
	return cmd
}

// splitVersionArg splits "name@version" on the LAST @, so a scoped npm package
// ("@bitwarden/cli@2026.4.0") keeps its leading @ and still yields a version.
func splitVersionArg(arg string) (name, version string) {
	if i := strings.LastIndex(arg, "@"); i > 0 {
		return arg[:i], arg[i+1:]
	}
	return arg, ""
}

// selectForMove returns the indices of the versions to move, refusing outright
// on anything that must not move rather than discovering it halfway through.
//
// Frozen is a hard refusal for the whole command, mirroring delete: a frozen
// version is one somebody pinned, and moving it changes where every future read
// of it goes. "Already on the destination" only skips, because refusing it
// would make a re-run after an interrupted move impossible, which is exactly
// when a migration command is needed most.
//
// Two names for one physical location is a refusal, and it covers the whole
// command rather than only --delete-source. The copy reads and writes one
// object, so the verify that follows re-reads what it just overwrote and
// passes; --delete-source then removes the artifact the manifest points at,
// and both backends answer a missing object with "not found", so nothing
// afterwards can tell it ever existed. Label is the identity because it is the
// only thing an ObjectStore exposes about where it writes, and it is what
// dedupByLabel already compares.
func selectForMove(stores storage.Resolver, dst storage.ObjectStore, pm *manifest.PackageManifest, version, dstName string) ([]int, error) {
	if directoryPlaced(pm.Type) {
		return nil, fmt.Errorf("%s is not movable: %s; "+
			"repoint storage_by_type.%s and re-upload instead",
			pm.Type, noPerPackagePlacement(pm.Type), pm.Type)
	}

	var candidates []int
	if version == "" {
		for i := range pm.Versions {
			candidates = append(candidates, i)
		}
	} else {
		i := versionIndex(pm, version)
		if i < 0 {
			return nil, fmt.Errorf("version %q not found in %s/%s; known: %s",
				version, pm.Type, pm.Name, knownVersions(pm))
		}
		candidates = []int{i}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%s/%s has no versions to move", pm.Type, pm.Name)
	}

	var frozen, already []string
	var out []int
	var collision string
	for _, i := range candidates {
		ve := pm.Versions[i]
		src, err := stores.ByName(ve.Storage)
		if err != nil {
			return nil, fmt.Errorf("%s/%s@%s: %w", pm.Type, pm.Name, versionLabel(ve), err)
		}
		switch {
		case ve.Frozen:
			frozen = append(frozen, versionLabel(ve))
		case effectiveStorage(ve.Storage) == dstName:
			already = append(already, versionLabel(ve))
		case src.Label() == dst.Label():
			collision = effectiveStorage(ve.Storage)
		default:
			out = append(out, i)
		}
	}
	if len(frozen) > 0 {
		return nil, fmt.Errorf("%s/%s: version(s) %s are frozen — unfreeze first with 'bodega pkg freeze %s %s'",
			pm.Type, pm.Name, strings.Join(frozen, ", "), pm.Type, pm.Name)
	}
	if collision != "" {
		return nil, fmt.Errorf("%s/%s: backends %q and %q are the same location (%s) — "+
			"every object would be copied onto itself, and --delete-source would then remove the only copy. "+
			"Name a different --to, or drop the duplicate entry from storage_backends",
			pm.Type, pm.Name, collision, dstName, dst.Label())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s/%s: version(s) %s are already recorded on %q — nothing to move",
			pm.Type, pm.Name, strings.Join(already, ", "), dstName)
	}
	for _, v := range already {
		fmt.Printf("  %s@%s: already on %q, skipping\n", pm.Name, v, dstName)
	}
	return out, nil
}

// mover carries the state one move needs. Split out of the cobra closure so
// the ordering guarantee can be tested against a store that fails on demand.
type mover struct {
	stores  storage.Resolver
	dst     storage.ObjectStore
	dstName string
	store   *manifest.Store
	spool   string
	out     io.Writer
	del     bool
}

// moveVersion copies one version's objects, verifies them at the destination,
// records the new backend, and only then considers the source.
func (m *mover) moveVersion(ctx context.Context, pm *manifest.PackageManifest, i int) error {
	ve := pm.Versions[i]
	label := pm.Name + "@" + versionLabel(ve)
	srcName := effectiveStorage(ve.Storage)
	src, err := m.stores.ByName(ve.Storage)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	keys, err := inventory.ArtifactKeys(ctx, src, pm, ve)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("%s: no object resolves for this version on %q; nothing to move", label, srcName)
	}

	var moved []string
	for n, key := range keys {
		info, err := src.Head(ctx, key)
		if err != nil {
			return fmt.Errorf("%s: head %s on %q: %w", label, key, srcName, err)
		}
		if !info.Exists {
			// Only the primary object is required. gomod's .info and .mod
			// travel with the .zip but a partial upload may have left one out,
			// and refusing the move would strand the version where it is.
			if n == 0 {
				return fmt.Errorf("%s: %s is not on %q — nothing to move", label, key, srcName)
			}
			fmt.Fprintf(m.out, "  %s: %s absent on %q, skipping\n", label, key, srcName)
			continue
		}

		fmt.Fprintf(m.out, "  %s: %s -> %s (%s)\n", label, srcName, m.dstName, key)
		size, err := m.copyObject(ctx, src, key)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := m.verify(ctx, key, size, ve, n == 0); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		moved = append(moved, key)
	}

	// The manifest write commits the move. Everything above is a copy that can
	// be repeated; nothing below may run before this line.
	want := m.dstName
	if want == storage.DefaultName {
		want = ""
	}
	pm.Versions[i].Storage = want
	if err := m.store.SavePackage(ctx, pm); err != nil {
		return fmt.Errorf("%s: record storage backend: %w", label, err)
	}
	if err := m.store.SaveIndex(ctx); err != nil {
		return fmt.Errorf("%s: save index: %w", label, err)
	}
	fmt.Fprintf(m.out, "  %s: manifest now points at %q\n", label, m.dstName)

	if !m.del {
		fmt.Fprintf(m.out, "  %s: source copy left on %q (--delete-source to remove)\n", label, srcName)
		return nil
	}
	// A failed delete leaves a stranded object, which costs space. A failed
	// delete that rolled the manifest back would cost the artifact. Report and
	// carry on.
	for _, key := range moved {
		if err := src.Delete(ctx, key); err != nil {
			fmt.Fprintf(m.out, "  %s: warning: could not delete %s from %q: %v\n", label, key, srcName, err)
			continue
		}
		fmt.Fprintf(m.out, "  %s: deleted %s from %q\n", label, key, srcName)
	}
	return nil
}

func (m *mover) copyObject(ctx context.Context, src storage.ObjectStore, key string) (int64, error) {
	return copyObject(ctx, src, m.dst, key, key, m.spool)
}

func (m *mover) verify(ctx context.Context, key string, spooled int64, ve manifest.VersionEntry, primary bool) error {
	return verifyCopy(ctx, m.dst, m.dstName, key, spooled, ve, primary)
}

// copyObject streams one object from src to dst through a temp file and
// returns the spooled size. srcKey and dstKey differ when the copy repairs a
// key rather than moving a backend.
//
// The spool lives under build_root rather than $TMPDIR because build_root is
// the volume sized for artifacts; a multi-gigabyte bundle through a tmpfs /tmp
// fills RAM instead. ObjectStore has no streaming Put — only Put([]byte) and
// PutFile — and adding a tenth interface method would mean touching both
// implementations and every mock, so the file on disk is what bridges them.
func copyObject(ctx context.Context, src, dst storage.ObjectStore, srcKey, dstKey, spool string) (int64, error) {
	if err := os.MkdirAll(spool, 0o755); err != nil {
		return 0, fmt.Errorf("create spool dir %s: %w", spool, err)
	}
	f, err := os.CreateTemp(spool, "move-*.part")
	if err != nil {
		return 0, fmt.Errorf("create spool file: %w", err)
	}
	spoolPath := f.Name()
	defer func() { _ = os.Remove(spoolPath) }()

	stream, err := src.GetStream(ctx, srcKey)
	if err != nil {
		_ = f.Close()
		return 0, fmt.Errorf("read %s from source: %w", srcKey, err)
	}
	if stream == nil {
		_ = f.Close()
		return 0, fmt.Errorf("read %s from source: object vanished between head and get", srcKey)
	}
	size, copyErr := io.Copy(f, stream.Body)
	_ = stream.Body.Close()
	closeErr := f.Close()
	if copyErr != nil {
		return 0, fmt.Errorf("spool %s: %w", srcKey, copyErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("close spool for %s: %w", srcKey, closeErr)
	}

	if err := dst.PutFile(ctx, spoolPath, dstKey); err != nil {
		return 0, fmt.Errorf("write %s to %q: %w", dstKey, dst.Label(), err)
	}
	return size, nil
}

// verifyCopy re-reads the object at the destination. Checking the spooled
// bytes would only prove the download worked; the question is whether the
// write landed, so the destination is what gets asked.
func verifyCopy(ctx context.Context, dst storage.ObjectStore, dstName, key string, spooled int64, ve manifest.VersionEntry, primary bool) error {
	info, err := dst.Head(ctx, key)
	if err != nil {
		return fmt.Errorf("verify %s on %q: %w", key, dstName, err)
	}
	if !info.Exists {
		return fmt.Errorf("verify %s on %q: not there after the write reported success", key, dstName)
	}
	if info.Size != spooled {
		return fmt.Errorf("verify %s on %q: %d bytes at the destination, %d copied", key, dstName, info.Size, spooled)
	}
	if !primary {
		return nil
	}
	if ve.ArtifactSize > 0 && info.Size != ve.ArtifactSize {
		return fmt.Errorf("verify %s on %q: %d bytes at the destination, manifest records %d",
			key, dstName, info.Size, ve.ArtifactSize)
	}
	if ve.Checksum == nil || ve.Checksum.Value == "" {
		return nil
	}
	got, err := digestObject(ctx, dst, key, ve.Checksum.Algorithm)
	if err != nil {
		return fmt.Errorf("verify %s on %q: %w", key, dstName, err)
	}
	if !strings.EqualFold(got, ve.Checksum.Value) {
		return fmt.Errorf("verify %s on %q: %s is %s, manifest records %s",
			key, dstName, ve.Checksum.Algorithm, got, ve.Checksum.Value)
	}
	return nil
}

// digestObject streams the object back out of store and hashes it.
func digestObject(ctx context.Context, store storage.ObjectStore, key, algorithm string) (string, error) {
	h, err := hasherFor(algorithm)
	if err != nil {
		return "", err
	}
	stream, err := store.GetStream(ctx, key)
	if err != nil {
		return "", err
	}
	if stream == nil {
		return "", fmt.Errorf("object not readable back")
	}
	defer func() { _ = stream.Body.Close() }()
	if _, err := io.Copy(h, stream.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hasherFor covers the four algorithms manifest.Checksum documents. md5 and
// sha1 are here because apt and some upstreams publish them; they are read
// back to confirm a copy landed intact, never to authenticate anything.
func hasherFor(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(algorithm) {
	case "md5":
		return md5.New(), nil //nolint:gosec // integrity check against a recorded digest
	case "sha1":
		return sha1.New(), nil //nolint:gosec // integrity check against a recorded digest
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("unsupported checksum algorithm %q", algorithm)
}
