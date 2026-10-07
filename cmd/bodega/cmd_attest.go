package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/config"
)

func newAttestCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "attest",
		Short: "Attestation operations (signing key management)",
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
	parent.AddCommand(keyParent)
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
