package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

func newAttestCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "attest",
		Short: "Attestation operations (signing key, verify, backfill)",
	}
	keyParent := &cobra.Command{
		Use:   "key",
		Short: "Manage the attestation signing key",
		Long: `key manages the Ed25519 key bodega signs attestations with. It signs nothing
else: the apt and pkg keys are separate files, so a theft of one cannot forge
the others' statements.

The server only ever loads the key. It searches $CREDENTIALS_DIRECTORY (systemd
LoadCredential=), then ` + attestsign.SystemKeyPath + `, then
<storage_path>/` + attestsign.KeyFileName + `, and refuses a file readable beyond
its owner. The file may hold several keys: the newest one that is not retired
signs, and every key's public half is published at /api/v1/attestation/keys.`,
	}
	keyParent.AddCommand(
		newAttestKeyGenerateCmd(gf),
		newAttestKeyShowCmd(gf),
		newAttestKeyRetireCmd(gf),
	)
	parent.AddCommand(keyParent, newAttestVerifyCmd(gf), newAttestBackfillCmd(gf))
	return parent
}

func newAttestKeyGenerateCmd(gf *globalFlags) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an attestation signing key",
		Long: `generate creates an Ed25519 key and writes it mode 0600 to the first writable
path the server searches.

When a key file already exists, generate refuses unless --force is given. With
--force the new key is appended to the file and becomes the signer on the next
reload; the old keys stay in the file and stay published, so attestations they
signed still verify. Nothing is deleted. A verifier pinned to the old key ID
rejects every attestation signed after that reload until it pins the new one,
so publish the new key ID first, then reload, then retire the old key.`,
		Example: `  bodega attest key generate
  bodega attest key generate --force`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			fresh, err := attestsign.Generate()
			if err != nil {
				return err
			}
			existing, target, err := existingAttestKey(cfg)
			if err != nil {
				return err
			}
			out := fresh
			switch {
			case existing != nil && force:
				existing.Add(fresh)
				out = existing
			case existing != nil:
				return fmt.Errorf("an attestation signing key already exists at %s; pass --force to add a new key beside it, which becomes the signer on the next reload", target)
			}
			if err := out.WritePrivate(target); err != nil {
				return err
			}
			id := fresh.Signer().KeyID()
			fmt.Printf("Key written to %s (mode 0600, no passphrase).\n", target)
			fmt.Printf("  Algorithm: %s\n", attestsign.Algorithm)
			fmt.Printf("  Key ID:    %s\n", id)
			if out.Len() > 1 {
				fmt.Printf("\n%d keys in the file; this one signs after the next reload and the others stay published.\n", out.Len())
				fmt.Println("Retire an old key once nothing pins it: bodega attest key retire <keyid>")
			}
			fmt.Println("\nPublish the key ID somewhere that is not this server. A verifier that")
			fmt.Println("learns it only from /api/v1/attestation/keys is trusting TLS, not the key.")
			fmt.Println("\nReload bodega (systemctl reload bodega, or SIGHUP) to sign with it.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "add a new key to an existing file; it becomes the signer")
	return cmd
}

func newAttestKeyShowCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the attestation signing keys",
		Long: `show prints every key in the file the server would load: key ID, state, and
the PEM public key. The signing key is the one marked "signing".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kr, err := openAttestKey(cfg)
			if err != nil {
				return err
			}
			signing := kr.Signer().KeyID()
			fmt.Printf("Key file: %s\n", kr.Path())
			for _, k := range kr.Keys() {
				state := "published"
				switch {
				case !k.Retired.IsZero():
					state = "retired " + k.Retired.Format("2006-01-02")
				case k.KeyID == signing:
					state = "signing"
				}
				created := "unknown"
				if !k.Created.IsZero() {
					created = k.Created.Format("2006-01-02")
				}
				fmt.Printf("\nKey ID:    %s\nAlgorithm: %s\nCreated:   %s\nState:     %s\n%s", k.KeyID, k.Algorithm, created, state, k.PublicKeyPEM)
			}
			return nil
		},
	}
}

func newAttestKeyRetireCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "retire <keyid>",
		Short: "Erase a key's private half, keeping its public half published",
		Long: `retire removes the private half of one key from the file. Its public half stays
in the file and stays published, marked retired, so attestations it already
signed still verify.

<keyid> is the full 64-character key ID or a prefix of at least 16 characters,
and a prefix matching more than one key is refused. retire refuses the last key
that can sign: add its replacement with 'generate --force' first.

Reload the server (systemctl reload bodega, or SIGHUP) for it to take effect.`,
		Example: `  bodega attest key retire 3f1c0e8a9b7d6c5e`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kr, err := openAttestKey(cfg)
			if err != nil {
				return err
			}
			retired, err := kr.Retire(args[0])
			if err != nil {
				return err
			}
			if err := kr.WritePrivate(kr.Path()); err != nil {
				return err
			}
			fmt.Printf("Retired %s in %s; signing key is %s.\n", retired, kr.Path(), kr.Signer().KeyID())
			fmt.Println("Reload bodega (systemctl reload bodega, or SIGHUP) to publish the change.")
			return nil
		},
	}
}

// openAttestKey loads the file the server would load, or explains where it
// looked.
func openAttestKey(cfg *config.Config) (*attestsign.KeyRing, error) {
	kr, err := attestsign.Load(attestsign.DefaultKeyPaths(cfg.StoragePath))
	if errors.Is(err, attestsign.ErrNoKey) {
		return nil, fmt.Errorf("%w; run 'bodega attest key generate' to create one", err)
	}
	return kr, err
}

// existingAttestKey resolves the write target and reads whatever is already
// there, so generate can refuse before it writes anything.
func existingAttestKey(cfg *config.Config) (*attestsign.KeyRing, string, error) {
	kr, err := attestsign.Load(attestsign.DefaultKeyPaths(cfg.StoragePath))
	if err == nil {
		return kr, kr.Path(), nil
	}
	if !errors.Is(err, attestsign.ErrNoKey) {
		return nil, "", err
	}
	target, err := attestsign.FirstWritablePath(attestsign.WritablePaths(cfg.StoragePath))
	return nil, target, err
}

// verifyRequest is one `attest verify` invocation, resolved: the envelope,
// what the caller expects it to be about, and where the keys and bytes come
// from.
type verifyRequest struct {
	cfg      *config.Config
	gf       *globalFlags
	keyIDs   []string
	pubFile  string
	artifact string
	server   string
	plain    bool

	// typ, name and version are the package the caller asked about.
	typ, name, version string
	envelope           []byte
	client             *Client
}

func newAttestVerifyCmd(gf *globalFlags) *cobra.Command {
	var (
		req     verifyRequest
		pkgSpec string
	)
	cmd := &cobra.Command{
		Use:   "verify <envelope-file|type/name/version>",
		Short: "Verify a bodega attestation against a pinned key and the artifact bytes",
		Long: `verify checks one attestation and prints every check with what it expected and
what it observed:

  signature       the envelope is signed by a key ID you trust
  predicate-type  it is an in-toto v1 statement with the ` + attest.PredicateType + ` predicate
  subject-digest  its sha256 matches the artifact bytes
  subject-name    its purl names the package and version you asked about
  policy          the decision was admitted and no policy evaluation is a block

Any failed check exits non-zero.

The trusted key IDs come from --key, or from attestation_keyids in the config
file. Learn them somewhere other than the server being checked: the public key
for each ID is fetched from /api/v1/attestation/keys (or read from
--public-key) and accepted only when it hashes to the ID you pinned.

Given type/name/version, the envelope is fetched from the server, and so are the
artifact bytes unless --artifact names a local copy. Given an envelope file,
--package type/name/version is required, since nothing else says what the
envelope is supposed to be about, and the bytes come from --artifact or the
server. distfiles bytes are not fetched: pass --artifact.`,
		Example: `  bodega attest verify npm/lodash/4.17.21 --key 3f1c0e8a...
  bodega attest verify pypi/requests/2.31.0 --artifact requests-2.31.0-py3-none-any.whl
  bodega attest verify ./lodash.dsse.json --package npm/lodash/4.17.21 --artifact lodash-4.17.21.tgz \
    --public-key attest.pub`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			req.cfg, req.gf = cfg, gf
			if len(req.keyIDs) == 0 {
				req.keyIDs = cfg.AttestationKeyIDs
			}
			if len(req.keyIDs) == 0 {
				return errors.New("no trusted key ID: pass --key <keyid> or set attestation_keyids in the config file. " +
					"Get the ID from whoever runs the server, not from the server itself")
			}
			if data, err := os.ReadFile(args[0]); err == nil { //nolint:gosec // operator-named file
				if pkgSpec == "" {
					return errors.New("an envelope file needs --package type/name/version: nothing else says which package it should be about")
				}
				req.envelope = data
				if req.typ, req.name, req.version, err = splitPackageSpec(pkgSpec); err != nil {
					return err
				}
			} else {
				if pkgSpec != "" {
					return errors.New("--package is for an envelope file; the argument already names the package")
				}
				if req.typ, req.name, req.version, err = splitPackageSpec(args[0]); err != nil {
					return fmt.Errorf("%s is neither a readable file nor type/name/version: %w", args[0], err)
				}
			}
			results, err := req.run()
			if err != nil {
				return err
			}
			failed := 0
			for _, r := range results {
				if r.OK {
					fmt.Fprintf(cmd.OutOrStdout(), "ok    %-15s %s\n", r.Check, r.Observed)
					continue
				}
				failed++
				fmt.Fprintf(cmd.OutOrStdout(), "FAIL  %-15s expected %s\n      %-15s observed %s\n", r.Check, r.Expected, "", r.Observed)
			}
			if failed > 0 {
				return fmt.Errorf("attestation for %s/%s@%s failed %d of %d checks", req.typ, req.name, req.version, failed, len(results))
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&req.keyIDs, "key", nil, "Trusted attestation key ID; repeat for several (default: attestation_keyids)")
	cmd.Flags().StringVar(&req.pubFile, "public-key", "", "PEM file holding the public key(s); default fetches /api/v1/attestation/keys")
	cmd.Flags().StringVar(&req.artifact, "artifact", "", "Local copy of the artifact; default fetches it from the server")
	cmd.Flags().StringVar(&pkgSpec, "package", "", "type/name/version an envelope file must be about")
	cmd.Flags().StringVar(&req.server, "server", "", "bodega server to fetch from (default: $BODEGA_SERVER, server_url, public_url)")
	cmd.Flags().BoolVar(&req.plain, "allow-plaintext", false, "Permit --server over http")
	return cmd
}

// splitPackageSpec splits type/name/version. The name may hold slashes (an
// npm scope, a Go module path), so the type is the first segment and the
// version the last.
func splitPackageSpec(spec string) (typ, name, version string, err error) {
	typ, rest, ok := strings.Cut(spec, "/")
	i := strings.LastIndex(rest, "/")
	if !ok || i <= 0 || i == len(rest)-1 || !slices.Contains(manifest.AllTypes, typ) {
		return "", "", "", fmt.Errorf("%q is not type/name/version with type one of %s", spec, strings.Join(manifest.AllTypes, ", "))
	}
	return typ, rest[:i], rest[i+1:], nil
}

// run gathers the envelope, the keys and the bytes, then checks.
func (v *verifyRequest) run() ([]attest.Result, error) {
	if v.envelope == nil {
		body, err := v.fetch("/api/v1/packages/" + url.PathEscape(v.typ) + "/" + url.PathEscape(v.name) + "/" + url.PathEscape(v.version) + "/attestation")
		if err != nil {
			return nil, fmt.Errorf("fetch the attestation: %w", err)
		}
		v.envelope = body
	}
	env, st, err := attest.ParseEnvelope(v.envelope)
	if err != nil {
		return nil, err
	}
	trusted, err := v.trustedKeys()
	if err != nil {
		return nil, err
	}
	sum, err := v.artifactDigest(st)
	if err != nil {
		return nil, err
	}
	return attest.Verify(env, st, attest.VerifyInput{
		Trusted:        trusted,
		ArtifactSHA256: sum,
		WantPURL:       attest.PURLBase(attest.PURL(v.typ, v.name, v.version, "")),
	}), nil
}

// trustedKeys returns the public key for each pinned ID it can find. A key is
// accepted only when it hashes to the ID, so the source of the key material
// (the server under test, or a file) is not trusted for anything.
func (v *verifyRequest) trustedKeys() (map[string]ed25519.PublicKey, error) {
	var pems [][]byte
	if v.pubFile != "" {
		data, err := os.ReadFile(v.pubFile)
		if err != nil {
			return nil, err
		}
		for rest := data; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			pems = append(pems, pem.EncodeToMemory(block))
		}
	} else {
		body, err := v.fetch("/api/v1/attestation/keys")
		if err != nil {
			return nil, fmt.Errorf("fetch the published keys: %w", err)
		}
		var keys []struct {
			PublicKeyPEM string `json:"public_key_pem"`
		}
		if err := json.Unmarshal(body, &keys); err != nil {
			return nil, fmt.Errorf("parse /api/v1/attestation/keys: %w", err)
		}
		for _, k := range keys {
			pems = append(pems, []byte(k.PublicKeyPEM))
		}
	}
	want := map[string]bool{}
	for _, id := range v.keyIDs {
		want[strings.ToLower(strings.TrimSpace(id))] = true
	}
	out := map[string]ed25519.PublicKey{}
	for _, p := range pems {
		pub, err := attest.ParsePublicKeyPEM(p)
		if err != nil {
			continue
		}
		if id, err := attest.KeyIDOf(pub); err == nil && want[id] {
			out[id] = pub
		}
	}
	if len(out) == 0 {
		// Not an error: the signature check reports it with the IDs it
		// wanted, beside every other check.
		for id := range want {
			out[id] = nil
		}
	}
	return out, nil
}

// artifactDigest hashes --artifact, or the bytes the server serves for the
// object the statement names.
func (v *verifyRequest) artifactDigest(st *attest.Statement) (string, error) {
	if v.artifact != "" {
		f, err := os.Open(v.artifact)
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", fmt.Errorf("read %s: %w", v.artifact, err)
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	var key string
	if len(st.Subject) > 0 {
		key = st.Subject[0].Annotations[attest.ObjectKeyAnnotation]
	}
	route, err := servedPath(v.typ, v.name, v.version, key)
	if err != nil {
		return "", err
	}
	if err := v.connect(); err != nil {
		return "", err
	}
	resp, err := v.client.Get(route)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s; pass --artifact with a local copy instead", route, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", fmt.Errorf("read %s: %w", route, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// servedPath is the route a client fetches an artifact from. Most trees are
// served at their storage key under a route prefix; npm and cargo answer on
// their registries' own paths. The key comes from the statement, which is not
// yet verified: it only chooses which bytes to hash, and the digest check is
// what decides whether they are the right ones.
func servedPath(typ, name, version, key string) (string, error) {
	switch typ {
	case manifest.TypeNpm:
		return "/npm/" + name + "/-/" + path.Base(name) + "-" + url.PathEscape(version) + ".tgz", nil
	case manifest.TypeCargo:
		return "/cargo/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/download", nil
	}
	for _, m := range []struct{ key, route string }{
		{manifest.AptPrefix, "/apt/"},
		{manifest.PypiWheelPrefix, "/pypi/wheels/"},
		{manifest.GitPrefix, "/git/"},
		{manifest.BinaryPrefix, "/binaries/"},
		{"gomod/", "/go/"},
		{"charts/", "/helm/charts/"},
		{manifest.FreeBSDPrefix, "/freebsd/"},
	} {
		if rest, ok := strings.CutPrefix(key, m.key); ok && rest != "" {
			segs := strings.Split(rest, "/")
			for i, s := range segs {
				segs[i] = url.PathEscape(s)
			}
			return m.route + strings.Join(segs, "/"), nil
		}
	}
	return "", fmt.Errorf("no served route for %s object %q; pass --artifact with a local copy", typ, key)
}

func (v *verifyRequest) connect() error {
	if v.client != nil {
		return nil
	}
	client, _, err := pinClient(v.cfg, v.server, v.plain)
	if err != nil {
		return err
	}
	v.client = client
	return nil
}

func (v *verifyRequest) fetch(route string) ([]byte, error) {
	if err := v.connect(); err != nil {
		return nil, err
	}
	resp, err := v.client.Get(route)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s: %s", route, resp.Status, serverError(body))
	}
	return body, nil
}

func newAttestBackfillCmd(gf *globalFlags) *cobra.Command {
	var typ string
	cmd := &cobra.Command{
		Use:   "backfill",
		Short: "Sign attestations for objects pinned before bodega emitted them",
		Long: `backfill signs an attestation for every pinned object in storage that has none:
each object whose sha256 the checksum table records, found on the backend its
version records.

It pins each object's admission first, as a fetch would. An object with no
admission row gets one whose checks all say not_evaluated, and a row that
predates a check (the age or OSV gate) has that check signed as not_evaluated.
Neither is signed as a pass. The refusals a fetch applies apply here too: a
newest decision that is not admitted, or one naming another object, is
reported and not signed.

An object that already has an attestation is skipped, so a second run signs
nothing new. distfiles are not covered: their digest lives in the ports tree's
distinfo, not the checksum table.

Run it on the server host, as the user the server runs as: it reads the
attestation signing key and writes to the artifact backends. Exits non-zero
when any object was refused.`,
		Example: `  bodega attest backfill
  bodega attest backfill --type npm`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if typ != "" && !slices.Contains(manifest.AllTypes, typ) {
				return fmt.Errorf("--type %q is not one of %s", typ, strings.Join(manifest.AllTypes, ", "))
			}
			kr, err := openAttestKey(cfg)
			if err != nil {
				return err
			}
			db, err := openAuditDBErr(gf)
			if err != nil {
				return err
			}
			if db == nil {
				return errors.New("no audit store configured; backfill signs what the admissions table records, so set audit_db")
			}
			defer func() { _ = db.Close() }()
			if db.ReadOnly() || !db.EventsQueryable() {
				return fmt.Errorf("audit_sink %s keeps no admissions table to re-read before signing; backfill needs the sqlite or postgres sink", db.SinkName())
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			ctx := backgroundCtx()
			stores, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				return err
			}
			signer := kr.Signer()
			b := backfill{
				out:    cmd.OutOrStdout(),
				db:     db,
				store:  store,
				stores: stores,
				emit: &attest.Emitter{
					Signer:     func() attestsign.Signer { return signer },
					Admissions: db,
					PlatformID: cfg.ResolveAttestationPlatformID(),
				},
			}
			return b.run(ctx, typ)
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "Only this package type")
	return cmd
}

// backfill is one `attest backfill` run.
type backfill struct {
	out    io.Writer
	db     *audit.DB
	store  *manifest.Store
	stores storage.Resolver
	emit   *attest.Emitter
}

func (b *backfill) run(ctx context.Context, typ string) error {
	rows, err := b.db.ListChecksums(ctx, typ, "")
	if err != nil {
		return fmt.Errorf("list pinned checksums: %w", err)
	}
	var signed, had, absent, refused int
	for _, row := range rows {
		if row.PkgType == "" || row.Value == "" || !strings.EqualFold(row.Algorithm, "sha256") {
			continue
		}
		label := row.PkgType + "/" + row.PkgName + "@" + row.PkgVersion
		st, requiredBy, err := b.backendFor(ctx, row)
		if err != nil {
			fmt.Fprintf(b.out, "  %s: %v\n", label, err)
			refused++
			continue
		}
		if info, err := st.Head(ctx, row.ObjectKey); err != nil || info == nil || !info.Exists {
			absent++
			continue
		}
		if ek, err := attest.Newest(ctx, st, []string{row.ObjectKey}); err != nil {
			return fmt.Errorf("list attestations for %s: %w", row.ObjectKey, err)
		} else if ek != "" {
			had++
			continue
		}
		outcome, err := b.db.PinAdmission(ctx, audit.AdmissionPin{PkgType: row.PkgType, PkgName: row.PkgName, PkgVersion: row.PkgVersion, ObjectKey: row.ObjectKey})
		if err != nil {
			return fmt.Errorf("pin the admission for %s: %w", row.ObjectKey, err)
		}
		ek, err := b.emit.Emit(ctx, st, attest.Pin{
			Type: row.PkgType, Name: row.PkgName, Version: row.PkgVersion, ObjectKey: row.ObjectKey,
			SHA256: row.Value, RequiredBy: requiredBy, Outcome: outcome,
		})
		if err != nil {
			fmt.Fprintf(b.out, "  %s: not signed: %v\n", label, err)
			refused++
			continue
		}
		note := ""
		if outcome == audit.PinUnadmitted {
			note = " (no admission on record: signed as not_evaluated)"
		}
		fmt.Fprintf(b.out, "  %s: %s%s\n", label, ek, note)
		signed++
	}
	fmt.Fprintf(b.out, "Signed %d, already attested %d, not in storage %d, refused %d.\n", signed, had, absent, refused)
	if refused > 0 {
		return fmt.Errorf("%d object(s) were not signed; see the lines above", refused)
	}
	return nil
}

// backendFor returns the backend a pinned object lives on and its version's
// RequiredBy. A version with a manifest entry is wherever that entry records;
// one without (a proxy fill of something never cataloged) is where the type
// rule caches it.
func (b *backfill) backendFor(ctx context.Context, row audit.StoredChecksum) (storage.ObjectStore, []string, error) {
	pm, err := b.store.GetPackage(ctx, row.PkgType, row.PkgName)
	if err == nil && pm != nil {
		for _, ve := range pm.Versions {
			if ve.Version == row.PkgVersion || ve.Ref == row.PkgVersion {
				st, err := b.stores.ByName(ve.Storage)
				return st, ve.RequiredBy, err
			}
		}
	}
	return b.stores.ForType(row.PkgType), nil, nil
}
