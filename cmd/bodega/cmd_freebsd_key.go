package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/pkgsign"
)

func newFreeBSDCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:     "freebsd",
		Aliases: []string{"pkgrepo"},
		Short:   "FreeBSD pkg repository operations (signing key management)",
	}
	keyParent := &cobra.Command{
		Use:   "key",
		Short: "Manage the pkg repository signing key",
		Long: `key manages the key the server signs a generated pkg catalogue with.

It signs one kind of repository and not the other. A mirrored repository is
copied byte for byte so FreeBSD's own signature reaches the client inside
packagesite.pkg, and no key of bodega's is in that path at all. A repository
marked generated: true has no upstream catalogue to copy — its packages came
out of poudriere or off somebody's build host — so bodega produces one, and
this is the key that seals it.

Generation lives here and nowhere else. The server only ever loads a key: it
searches $CREDENTIALS_DIRECTORY (systemd LoadCredential=), then
` + pkgsign.SystemKeyPath + `, then <storage_path>/` + pkgsign.KeyFileName + `. A
server that could create its own key would be a server that could mint one
after being compromised.

The key carries no passphrase. On an unattended service the passphrase would
have to be readable from somewhere with the same permissions as the key, so it
adds a failure mode and protects nothing. File permissions are the boundary:
bodega refuses to load a key readable beyond its owner. A key delivered as a
systemd credential is the one exception, because systemd writes it 0440 on a
read-only tmpfs no other service can reach and no chmod can change.`,
	}
	keyParent.AddCommand(
		newFreeBSDKeyGenerateCmd(gf),
		newFreeBSDKeyShowCmd(gf),
		newFreeBSDKeyExportCmd(gf),
	)
	parent.AddCommand(keyParent)
	return parent
}

func newFreeBSDKeyGenerateCmd(gf *globalFlags) *cobra.Command {
	var (
		eddsa bool
		path  string
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a pkg repository signing key",
		Long: `generate creates an RSA-4096 signing key and writes it mode 0600 to the first
writable path the server searches.

--eddsa produces an Ed25519 key instead. It is smaller and faster and needs
pkg 1.20 or later, which is where the ecc signer arrived; RSA is the default
because a repository being stood up has no way to know how old the oldest
client in the fleet is. The hash follows the key — SHA-256 for RSA, BLAKE2b
for Ed25519 — and is never a separate choice, because a key signing the wrong
one produces a signature the client rejects without saying why.

There is no --rotate, and the difference from 'bodega apt key generate' is the
format rather than an omission. An apt InRelease carries as many signatures as
you like, so a rotation window signs with both keys at once. A pkg archive
carries exactly one .sig and one .pub member, so there is no second signature
to publish: a pkg rotation happens on the client, which trusts two fingerprint
files for as long as the window is open. Install the new fingerprint on every
client first, then replace this key.

Reload the server (systemctl reload bodega, or SIGHUP) for a new key to take
effect; the reload re-reads the key file and rebuilds every generated
catalogue with it.`,
		Example: `  bodega freebsd key generate
  bodega freebsd key generate --eddsa
  bodega freebsd key generate --path /etc/bodega/` + pkgsign.KeyFileName,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kt := pkgsign.KeyRSA
			if eddsa {
				kt = pkgsign.KeyEd25519
			}
			fresh, err := pkgsign.Generate(kt)
			if err != nil {
				return err
			}
			target, err := freeBSDKeyTarget(cfg, path)
			if err != nil {
				return err
			}
			if err := fresh.WritePrivate(target); err != nil {
				return err
			}

			fmt.Printf("Key written to %s (mode 0600, no passphrase).\n", target)
			fmt.Printf("  Type:        %s\n", kt)
			fmt.Printf("  Fingerprint: %s\n", fresh.Fingerprint())
			fmt.Println("\nPublish this fingerprint out of band. A client's first fetch of the")
			fmt.Println("public key is authenticated by TLS alone; the fingerprint is what")
			fmt.Println("turns that into a check somebody can actually make:")
			fmt.Println("\n  bodega freebsd key export --fingerprint \\")
			fmt.Println("    > /usr/local/etc/pkg/fingerprints/bodega/trusted/bodega")
			fmt.Println("\nReload bodega (systemctl reload bodega, or SIGHUP) to sign with it.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&eddsa, "eddsa", false, "generate Ed25519 instead of RSA-4096 (needs pkg 1.20 or later)")
	cmd.Flags().StringVar(&path, "path", "", "write to this file instead of the searched paths")
	return cmd
}

func newFreeBSDKeyShowCmd(gf *globalFlags) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the loaded pkg signing key",
		Long: `show prints the key the server would sign a generated catalogue with, from
the same search order the server uses.

The fingerprint printed here is what a client trusts under
/usr/local/etc/pkg/fingerprints/<repo>/trusted/. Publish it somewhere that is
not the server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kr, err := openPkgKey(cfg, path)
			if err != nil {
				return err
			}
			info := kr.Info()
			algo := info.Algorithm
			if info.Bits > 0 {
				algo = fmt.Sprintf("%s-%d", info.Algorithm, info.Bits)
			}
			fmt.Printf("Key file:    %s\n", kr.Path())
			fmt.Printf("Algorithm:   %s\n", algo)
			fmt.Printf("Fingerprint: %s\n", info.Fingerprint)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "read this file instead of the searched paths")
	return cmd
}

func newFreeBSDKeyExportCmd(gf *globalFlags) *cobra.Command {
	var (
		path        string
		fingerprint bool
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print the public signing key, or the trusted fingerprint file",
		Long: `export writes the PEM public key to stdout, or with --fingerprint the trusted
fingerprint file a client installs.

The two answer the two ways pkg checks a signature. signature_type: PUBKEY
names a PEM public key with pubkey= and ignores what the archive carries;
signature_type: FINGERPRINTS reads the .pub member out of the archive and
checks it against a fingerprint file first, which is how pkg.freebsd.org
works. Either way this is the out-of-band delivery that does not trust the
server's TLS — a configuration-management repository, an image build, a USB
stick.

The archive already carries the public key as a member, so a client using
FINGERPRINTS needs only the fingerprint file.`,
		Example: `  bodega freebsd key export > /usr/local/etc/pkg/keys/bodega.pub
  bodega freebsd key export --fingerprint \
    > /usr/local/etc/pkg/fingerprints/bodega/trusted/bodega`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			kr, err := openPkgKey(cfg, path)
			if err != nil {
				return err
			}
			if fingerprint {
				_, err := fmt.Print(kr.TrustedFingerprintFile())
				return err
			}
			pub, err := kr.PublicKey()
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(pub)
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "read this file instead of the searched paths")
	cmd.Flags().BoolVar(&fingerprint, "fingerprint", false, "emit the trusted fingerprint file instead of the public key")
	return cmd
}

// openPkgKey loads the key the server would load, or explains where it looked.
func openPkgKey(cfg *config.Config, path string) (*pkgsign.KeyRing, error) {
	if path != "" {
		return pkgsign.LoadPath(path)
	}
	kr, err := pkgsign.Load(pkgsign.DefaultKeyPaths(cfg.StoragePath))
	if errors.Is(err, pkgsign.ErrNoKey) {
		return nil, fmt.Errorf("%w — run 'bodega freebsd key generate' to create one", err)
	}
	return kr, err
}

// freeBSDKeyTarget resolves where a generated key lands, and refuses to write
// over one that is already there.
//
// Refused rather than replaced, because replacing is not a local act: every
// client holding the old fingerprint stops verifying the moment the new key
// signs, and pkg reports that as a repository it will not read rather than as
// a key it does not have. Moving the old file aside is one command and makes
// the decision visible in shell history.
func freeBSDKeyTarget(cfg *config.Config, path string) (string, error) {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("a signing key already exists at %s; move it aside to replace it, after installing the new fingerprint on every client — a client holding only the old one stops reading the repository the moment the new key signs", path)
		}
		return path, nil
	}
	kr, err := pkgsign.Load(pkgsign.DefaultKeyPaths(cfg.StoragePath))
	if err == nil {
		return "", fmt.Errorf("a signing key already exists at %s; move it aside to replace it, after installing the new fingerprint on every client — a client holding only the old one stops reading the repository the moment the new key signs", kr.Path())
	}
	if !errors.Is(err, pkgsign.ErrNoKey) {
		return "", err
	}
	return pkgsign.FirstWritablePath(pkgsign.WritablePaths(cfg.StoragePath))
}
