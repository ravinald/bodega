package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/config"
)

func newAptCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "apt",
		Short: "APT repository operations (signing key management)",
	}
	keyParent := &cobra.Command{
		Use:   "key",
		Short: "Manage the apt repository signing key",
		Long: `key manages the OpenPGP key the server signs the apt index with.

Generation lives here and nowhere else. The server only ever loads a key: it
searches $CREDENTIALS_DIRECTORY (systemd LoadCredential=), then
` + aptsign.SystemKeyPath + `, then <storage_path>/` + aptsign.KeyFileName + `. A
server that could create its own key would be a server that could mint one
after being compromised.

The key carries no passphrase. On an unattended service the passphrase would
have to be readable from somewhere with the same permissions as the key, so it
adds a failure mode and protects nothing. File permissions are the boundary:
bodega refuses to load a key readable beyond its owner.`,
	}
	keyParent.AddCommand(
		newAptKeyGenerateCmd(gf),
		newAptKeyShowCmd(gf),
		newAptKeyExportCmd(gf),
		newAptKeyRetireCmd(gf),
	)
	parent.AddCommand(keyParent)
	return parent
}

// newAptKeyGenerateCmd creates a signing key, or adds one to an existing file
// to open a rotation window.
func newAptKeyGenerateCmd(gf *globalFlags) *cobra.Command {
	var (
		rsa    bool
		rotate bool
		name   string
		email  string
		path   string
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an apt repository signing key",
		Long: `generate creates an Ed25519 signing key and writes it mode 0600 to the first
writable path the server searches.

--rsa produces RSA-4096 instead, for clients whose gnupg predates 2.1 and
cannot parse an EdDSA key at all.

--rotate appends the new key to the existing file rather than replacing it, so
the outgoing key stays first and the incoming one signs last. Both keys sign
every rebuild and both public keys are published, which is what carries clients
that have not updated their keyring across the window. Close it with
'bodega apt key retire <old-fingerprint>' once they have. A switch without the
window breaks every client that has not updated, and apt does not refresh
keyrings on its own.

The order is deliberate. Signature order is what decides whether a client with
only one of the two keys can verify: gpgv 2.4 walks the whole signature set,
but gpgv 2.5 stops at the first key it does not hold and exits without looking
at the rest. Oldest-first is therefore the correct order, because the window
exists for clients that have not updated. A client holding only the incoming
key must fetch the full served keyring at /apt/bodega-archive-keyring.gpg,
which carries both for as long as the window is open, rather than the incoming
key on its own.

Reload the server (systemctl reload bodega, or SIGHUP) for a new key to take
effect; the reload re-reads the key file and re-signs the index with it.`,
		Example: `  bodega apt key generate
  bodega apt key generate --rsa --name "acme archive" --email ops@acme.example
  bodega apt key generate --rotate`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if name == "" {
				name = cfg.AptSigningName
			}
			if email == "" {
				email = cfg.AptSigningEmail
			}

			kt := aptsign.KeyEd25519
			if rsa {
				kt = aptsign.KeyRSA4096
			}
			fresh, err := aptsign.Generate(name, email, kt)
			if err != nil {
				return err
			}

			existing, target, err := existingKey(cfg, path)
			if err != nil {
				return err
			}
			out := fresh
			switch {
			case existing != nil && rotate:
				existing.Add(fresh)
				out = existing
			case existing != nil:
				return fmt.Errorf("a signing key already exists at %s — pass --rotate to add this one beside it and open a transition window, or move the old file aside to replace it outright (every client keyring stops verifying the moment it goes)", target)
			}

			if err := out.WritePrivate(target); err != nil {
				return err
			}
			fmt.Printf("Key written to %s (mode 0600, no passphrase).\n", target)
			fmt.Printf("  Type:        %s\n", kt)
			fmt.Printf("  UID:         %s\n", uidString(name, email))
			fmt.Printf("  Fingerprint: %s\n", fresh.Fingerprints()[0])
			if out.Len() > 1 {
				fmt.Printf("\nRotation window open: %d keys now sign every rebuild.\n", out.Len())
				fmt.Println("Retire the old one once every client has fetched the new keyring:")
				fmt.Printf("  bodega apt key retire %s\n", existingFingerprintsExcept(out, fresh))
			}
			fmt.Println("\nPublish this fingerprint out of band. A client's first fetch of the")
			fmt.Println("public key is authenticated by TLS alone; the fingerprint is what")
			fmt.Println("turns that into a check somebody can actually make.")
			fmt.Println("\nReload bodega (systemctl reload bodega, or SIGHUP) to sign with it.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&rsa, "rsa", false, "generate RSA-4096 instead of Ed25519 (for gnupg older than 2.1)")
	cmd.Flags().BoolVar(&rotate, "rotate", false, "add the new key beside the existing one instead of failing")
	cmd.Flags().StringVar(&name, "name", "", "UID name (default: apt_signing_name)")
	cmd.Flags().StringVar(&email, "email", "", "UID email (default: apt_signing_email)")
	cmd.Flags().StringVar(&path, "path", "", "write to this file instead of the searched paths")
	return cmd
}

func newAptKeyShowCmd(gf *globalFlags) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the loaded apt signing key",
		Long: `show prints every key the server would sign with, from the same search order
the server uses. Two keys mean a rotation window is open.

The fingerprints printed here are what a client pins with signed-by=. Publish
them somewhere that is not the server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kr, err := openKey(cfg, path)
			if err != nil {
				return err
			}
			fmt.Printf("Key file: %s\n\n", kr.Path())
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "FINGERPRINT\tALGORITHM\tCREATED\tUID")
			for _, k := range kr.Keys() {
				algo := k.Algorithm
				if k.Algorithm == "rsa" {
					algo = fmt.Sprintf("rsa%d", k.Bits)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.Fingerprint, algo, k.Created.Format("2006-01-02"), k.UserID)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if kr.Len() > 1 {
				fmt.Printf("\n%d keys sign every rebuild — a rotation window is open. Retire the\n", kr.Len())
				fmt.Println("outgoing key once every client has fetched the new keyring.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "read this file instead of the searched paths")
	return cmd
}

func newAptKeyExportCmd(gf *globalFlags) *cobra.Command {
	var (
		path    string
		keyring bool
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print the public signing key",
		Long: `export writes the public half of every loaded key to stdout: armored by
default, dearmored with --keyring.

The dearmored form is what /etc/apt/keyrings/ and signed-by= take directly. The
server serves both at /apt/bodega-archive-keyring.asc and .gpg, so export is
for the out-of-band delivery that does not trust the server's TLS — a
configuration-management repository, an image build, a USB stick.`,
		Example: `  bodega apt key export > bodega-archive-keyring.asc
  bodega apt key export --keyring > /etc/apt/keyrings/bodega-archive-keyring.gpg`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kr, err := openKey(cfg, path)
			if err != nil {
				return err
			}
			var out []byte
			if keyring {
				out, err = kr.Keyring()
			} else {
				out, err = kr.PublicKey()
			}
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(out)
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "read this file instead of the searched paths")
	cmd.Flags().BoolVar(&keyring, "keyring", false, "emit the dearmored binary keyring instead of armored text")
	return cmd
}

func newAptKeyRetireCmd(gf *globalFlags) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "retire <fingerprint>",
		Short: "Remove a key from the signing file, closing a rotation window",
		Long: `retire drops one key from the signing file. Use it to close a rotation window
after every client has fetched the new keyring.

<fingerprint> is the full 40-character fingerprint or a prefix of at least 16
characters, and a prefix matching more than one key is refused rather than
resolved. Retiring the wrong key closes the window early and breaks every
client that has not fetched the incoming key yet, so a short argument is not
worth what it costs. 'bodega apt key show' prints the fingerprints.

It refuses to remove the last key: a file with no keys loads as an error and
takes the repository unsigned, which apt reports as nothing at all.

Reload the server (systemctl reload bodega, or SIGHUP) for the change to take
effect. The reload re-reads the key file, so the process stops signing with the
retired key and the served keyring drops it in the same step.`,
		Example: `  bodega apt key retire 5E4A2C0F9D1B7A3E6C8F0B2D4A6E8C0F1A3B5D7E
  bodega apt key retire 5E4A2C0F9D1B7A3E`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kr, err := openKey(cfg, path)
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
			fmt.Printf("Retired %s from %s. Remaining: %v\n", retired, kr.Path(), kr.Fingerprints())
			fmt.Println("Reload bodega (systemctl reload bodega, or SIGHUP) to stop signing with it.")
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "read this file instead of the searched paths")
	return cmd
}

// openKey loads the key the server would load, or explains where it looked.
func openKey(cfg *config.Config, path string) (*aptsign.KeyRing, error) {
	if path != "" {
		return aptsign.LoadPath(path)
	}
	kr, err := aptsign.Load(aptsign.DefaultKeyPaths(cfg.StoragePath))
	if errors.Is(err, aptsign.ErrNoKey) {
		return nil, fmt.Errorf("%w — run 'bodega apt key generate' to create one", err)
	}
	return kr, err
}

// existingKey resolves the write target and reads whatever is already there,
// so generate can tell "replace" from "rotate" before it writes anything.
func existingKey(cfg *config.Config, path string) (*aptsign.KeyRing, string, error) {
	if path != "" {
		kr, err := aptsign.LoadPath(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, path, nil
		}
		return kr, path, err
	}
	kr, err := aptsign.Load(aptsign.DefaultKeyPaths(cfg.StoragePath))
	if err == nil {
		return kr, kr.Path(), nil
	}
	if !errors.Is(err, aptsign.ErrNoKey) {
		return nil, "", err
	}
	target, err := aptsign.FirstWritablePath(aptsign.WritablePaths(cfg.StoragePath))
	return nil, target, err
}

func uidString(name, email string) string {
	if email == "" {
		return name
	}
	return fmt.Sprintf("%s <%s>", name, email)
}

// existingFingerprintsExcept names the keys that were already in the file, so
// the rotation hint can be copy-pasted.
func existingFingerprintsExcept(all *aptsign.KeyRing, fresh *aptsign.KeyRing) string {
	newFP := fresh.Fingerprints()[0]
	for _, fp := range all.Fingerprints() {
		if fp != newFP {
			return fp
		}
	}
	return ""
}
