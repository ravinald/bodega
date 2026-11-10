package clientconf

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// SystemCA is the system a CA file is listed under when no one client owns
// it: the anchors in the operating system's trust store, and the copy the
// clients' own settings name.
const SystemCA = "ca"

// Where a private CA goes. Each client setting that takes a path names one
// copy: CASharedPath for a file under /etc, CAUserPath for a file in a home
// directory, which an account without root can write.
const (
	CASharedPath = "/usr/local/share/bodega/ca.pem"
	CAUserPath   = "~/.config/bodega/ca.pem"
)

// CA is a PEM file of CA certificates, checked.
type CA struct {
	Certs []*x509.Certificate
	// PEM holds the certificates alone, re-encoded, so nothing else the
	// operator's file carried is copied to a world-readable path.
	PEM []byte
}

// ParseCA reads every certificate in data and refuses a file doctor should
// not install: one with no certificate, one holding anything that is not a
// certificate (a private key would be copied where every account reads it),
// and one holding a certificate that is not a CA, which no client accepts as
// a trust anchor for another certificate.
func ParseCA(data []byte) (CA, error) {
	var ca CA
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return CA{}, fmt.Errorf("it holds a %q block, and a CA file holds certificates only; a key in it would be copied where every account on the host reads it", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CA{}, fmt.Errorf("certificate %d does not parse: %w", len(ca.Certs)+1, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return CA{}, fmt.Errorf("certificate %d (%s) is not a CA: its basic constraints do not set CA:TRUE, so no client trusts what it signs. "+
				"Pass the certificate that issued bodega's, not bodega's own", len(ca.Certs)+1, cert.Subject)
		}
		ca.Certs = append(ca.Certs, cert)
		ca.PEM = append(ca.PEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if len(ca.Certs) == 0 {
		return CA{}, fmt.Errorf("it holds no PEM certificate; a CA file opens with -----BEGIN CERTIFICATE-----")
	}
	return ca, nil
}

// CAHost is the host a CA is installed on.
type CAHost struct {
	// Base is the URL clients reach bodega at.
	Base string
	Home string
	// Root is the directory the absolute paths sit under, "" for the host's
	// own. A test roots them in a scratch directory.
	Root string
	GOOS string
	// OSRelease is the content of /etc/os-release, which names the Linux
	// family whose trust store command applies.
	OSRelease []byte
}

// CAInstall is a plan with a CA added to it.
type CAInstall struct {
	// Changes is the plan's changes with the CA setting merged into each
	// file a client reads one from, followed by the certificate files.
	Changes []Change
	// Step is the command that rebuilds the system trust store from the
	// anchors in Changes, or nil when no anchor differs from the host's.
	Step []string
	// Notes name what the operator still does by hand, one per system.
	Notes map[string]string
}

// systemStore is where one operating system family reads trust anchors, one
// certificate to a file, and the command that rebuilds its store from them.
type systemStore struct {
	dir, ext string
	step     []string
}

// systemStoreFor resolves the trust store of the host. certctl before FreeBSD
// 14 reads only *.pem from its trust path, so that is the extension there.
func systemStoreFor(h CAHost) (systemStore, error) {
	if h.GOOS == OSFreeBSD {
		return systemStore{"/usr/local/share/certs", ".pem", []string{"certctl", "rehash"}}, nil
	}
	if h.GOOS == OSLinux {
		for _, id := range osReleaseFamily(h.OSRelease) {
			switch id {
			case "debian", "ubuntu":
				return systemStore{"/usr/local/share/ca-certificates", ".crt", []string{"update-ca-certificates"}}, nil
			case "rhel", "fedora", "centos":
				return systemStore{"/etc/pki/ca-trust/source/anchors", ".pem", []string{"update-ca-trust", "extract"}}, nil
			}
		}
	}
	return systemStore{}, fmt.Errorf("doctor installs into the system trust store on Debian and Ubuntu, the RHEL family and FreeBSD, and this host is none of them")
}

// osReleaseFamily is ID followed by each ID_LIKE entry, the order os-release
// gives for "what this distribution is, then what it derives from".
func osReleaseFamily(data []byte) []string {
	var id string
	var like []string
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "ID":
			id = val
		case "ID_LIKE":
			like = strings.Fields(val)
		}
	}
	return append([]string{id}, like...)
}

// ownStoreSystems are the systems whose client reads a CA from its own
// setting. Every other system verifies through the system trust store, apart
// from Maven, whose JVM reads a keystore doctor does not write.
var ownStoreSystems = []string{manifest.TypeNpm, manifest.TypePypi, manifest.TypeOCI, manifest.TypeGit}

// AddCA plans the install of ca for every system changes configures: the
// client's own setting merged into the file the plan already writes for npm,
// pip, git and containerd, a ca.crt in the directory Docker and podman read
// per registry host, and for every other system an anchor in the operating
// system's trust store.
//
// The certificate files follow the plan's own changes, because Apply writes
// last to first: a setting naming a CA file is written only after that file.
func AddCA(changes []Change, ca CA, h CAHost) (CAInstall, error) {
	base, err := url.Parse(h.Base)
	if err != nil || base.Host == "" {
		return CAInstall{}, fmt.Errorf("%q is not a URL with a host", h.Base)
	}
	if base.Scheme != "https" {
		return CAInstall{}, fmt.Errorf("%s is plain http, where no client verifies a certificate, so there is no CA to install", h.Base)
	}
	in := CAInstall{Changes: slices.Clone(changes), Notes: map[string]string{}}
	var files []Change
	// resolve turns a path as a plan writes it into this host's: ~/ under the
	// home directory, anything else under Root.
	resolve := func(path string) (string, error) {
		target, err := TargetPath(path, h.Home)
		if err != nil || strings.HasPrefix(path, "~/") {
			return target, err
		}
		return filepath.Join(h.Root, target), nil
	}
	addFile := func(system, target string, content []byte) error {
		if slices.ContainsFunc(files, func(c Change) bool { return c.Target == target }) {
			return nil
		}
		sum := sha256.Sum256(content)
		c, err := NewChange(PlanRecord{System: system, Action: PlanInstall, Path: target, SHA256: hex.EncodeToString(sum[:])}, content, h.Home)
		if err != nil {
			return err
		}
		files = append(files, c)
		return nil
	}
	// shared installs the copy a setting in the file at planPath names, and
	// returns where that copy is.
	shared := func(planPath string) (string, error) {
		p := CASharedPath
		if strings.HasPrefix(planPath, "~/") {
			p = CAUserPath
		}
		target, err := resolve(p)
		if err != nil {
			return "", err
		}
		return target, addFile(SystemCA, target, ca.PEM)
	}

	var system []string
	for i, c := range in.Changes {
		rec := c.Record
		var edit func(body []byte, caPath string) []byte
		switch {
		case rec.System == manifest.TypeMaven:
			in.Notes[rec.System] = "the JVM reads its own keystore, which doctor does not write. Import the CA there: " +
				"keytool -importcert -cacerts -alias bodega -file <ca.pem>"
		case !slices.Contains(ownStoreSystems, rec.System):
			if !slices.Contains(system, rec.System) {
				system = append(system, rec.System)
			}
		case rec.System == manifest.TypeNpm && rec.Path != NodeMirrorSystemPath && rec.Path != NodeMirrorUserPath:
			edit = func(body []byte, caPath string) []byte { return setLine(body, "", "cafile=", "cafile="+caPath) }
		case rec.System == manifest.TypePypi:
			edit = func(body []byte, caPath string) []byte { return setLine(body, "[global]", "cert =", "cert = "+caPath) }
		case rec.System == manifest.TypeGit:
			edit = func(body []byte, caPath string) []byte {
				return setLine(body, fmt.Sprintf("[http %q]", trim(h.Base)+"/"), "sslCAInfo =", "\tsslCAInfo = "+caPath)
			}
		case rec.System == manifest.TypeOCI && strings.HasSuffix(rec.Path, "/hosts.toml"):
			edit = func(body []byte, caPath string) []byte {
				return setLine(body, "[host."+jsonString(trim(h.Base))+"]", "ca =", "  ca = "+jsonString(caPath))
			}
		case rec.System == manifest.TypeOCI && OCIRuntimeOf(rec.Path) == RuntimeDocker:
			// Docker reads certs.d beside daemon.json, keyed by the host and
			// port of the registry or mirror it is talking to.
			if err := addFile(rec.System, filepath.Join(filepath.Dir(c.Target), "certs.d", base.Host, "ca.crt"), ca.PEM); err != nil {
				return CAInstall{}, err
			}
		case rec.System == manifest.TypeOCI && OCIRuntimeOf(rec.Path) == RuntimePodman:
			// /etc/containers/certs.d, two levels above the drop-in.
			if err := addFile(rec.System, filepath.Join(filepath.Dir(filepath.Dir(c.Target)), "certs.d", base.Host, "ca.crt"), ca.PEM); err != nil {
				return CAInstall{}, err
			}
		}
		if edit == nil {
			continue
		}
		caPath, err := shared(rec.Path)
		if err != nil {
			return CAInstall{}, fmt.Errorf("%s: %w", rec.System, err)
		}
		in.Changes[i].New = edit(c.New, caPath)
	}

	if len(system) > 0 {
		store, err := systemStoreFor(h)
		if err != nil {
			return CAInstall{}, fmt.Errorf("%s verify through the system trust store: %w.\n"+
				"  Add the CA to this host's store by hand, then re-run without --ca-file, or name only the systems that read their own: %s",
				strings.Join(system, ", "), err, strings.Join(ownStoreSystems, ", "))
		}
		before := len(files)
		for i, cert := range ca.Certs {
			name := "bodega-ca"
			if i > 0 {
				name = fmt.Sprintf("bodega-ca-%d", i+1)
			}
			one := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			target, err := resolve(filepath.Join(store.dir, name+store.ext))
			if err != nil {
				return CAInstall{}, err
			}
			if err := addFile(SystemCA, target, one); err != nil {
				return CAInstall{}, err
			}
		}
		if slices.ContainsFunc(files[before:], func(c Change) bool { return !c.Unchanged() }) {
			in.Step = store.step
		}
	}
	in.Changes = append(in.Changes, files...)
	return in, nil
}

// setLine sets one "key = value" line of an INI, TOML or git config body: the
// first line under header opening with key is replaced by line, and with none
// there line is added as the section's first. A body lacking the header gains
// it at the end. An empty header means the file has no sections. Every other
// line is kept as it is.
func setLine(body []byte, header, key, line string) []byte {
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	start, end := 0, len(lines)
	if header != "" {
		start = -1
		for i, l := range lines {
			t := strings.TrimSpace(l)
			switch {
			case start < 0 && t == header:
				start = i + 1
			case start >= 0 && strings.HasPrefix(t, "["):
				end = i
			}
			if start >= 0 && end < len(lines) {
				break
			}
		}
		if start < 0 {
			lines = append(lines, header)
			start, end = len(lines), len(lines)
		}
	}
	for i := start; i < end; i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), key) {
			lines[i] = line
			return []byte(strings.Join(lines, "\n") + "\n")
		}
	}
	at := start
	if header == "" {
		at = end
	}
	lines = slices.Insert(lines, at, line)
	return bytes.TrimLeft([]byte(strings.Join(lines, "\n")+"\n"), "\n")
}
