package manifest

import (
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Store is the in-memory representation of all loaded manifests.
type Store struct {
	dir     string
	backend Backend
	Apt     []AptEntry
	Git     []GitEntry
	Pypi    PypiManifest
	Binary  []BinaryEntry
	Gomod   []GomodEntry
	Helm    []HelmEntry
	Npm     []NpmEntry
}

// LoadAll reads all four manifests from dir, verifying MD5 integrity for each.
func LoadAll(dir string) (*Store, error) {
	s := &Store{dir: dir}

	var errs []error
	var aptM AptManifest
	if err := loadManifest(dir, TypeApt, &aptM); err != nil {
		errs = append(errs, err)
	}
	s.Apt = aptM.Entries

	var gitM GitManifest
	if err := loadManifest(dir, TypeGit, &gitM); err != nil {
		errs = append(errs, err)
	}
	s.Git = gitM.Entries

	if err := loadManifest(dir, TypePypi, &s.Pypi); err != nil {
		errs = append(errs, err)
	}

	var binM BinaryManifest
	if err := loadManifest(dir, TypeBinary, &binM); err != nil {
		errs = append(errs, err)
	}
	s.Binary = binM.Entries

	var gomodM GomodManifest
	if err := loadManifest(dir, TypeGomod, &gomodM); err != nil {
		errs = append(errs, err)
	}
	s.Gomod = gomodM.Entries

	var helmM HelmManifest
	if err := loadManifest(dir, TypeHelm, &helmM); err != nil {
		errs = append(errs, err)
	}
	s.Helm = helmM.Entries

	var npmM NpmManifest
	if err := loadManifest(dir, TypeNpm, &npmM); err != nil {
		errs = append(errs, err)
	}
	s.Npm = npmM.Entries

	if len(errs) > 0 {
		return nil, joinErrors(errs)
	}
	return s, nil
}

// LoadAllFromBackend reads all manifests from a Backend (S3 or local).
func LoadAllFromBackend(ctx context.Context, b Backend) (*Store, error) {
	s := &Store{backend: b}

	var errs []error
	var aptM AptManifest
	if err := loadFromBackend(ctx, b, TypeApt, &aptM); err != nil {
		errs = append(errs, err)
	}
	s.Apt = aptM.Entries

	var gitM GitManifest
	if err := loadFromBackend(ctx, b, TypeGit, &gitM); err != nil {
		errs = append(errs, err)
	}
	s.Git = gitM.Entries

	if err := loadFromBackend(ctx, b, TypePypi, &s.Pypi); err != nil {
		errs = append(errs, err)
	}

	var binM BinaryManifest
	if err := loadFromBackend(ctx, b, TypeBinary, &binM); err != nil {
		errs = append(errs, err)
	}
	s.Binary = binM.Entries

	var gomodM GomodManifest
	if err := loadFromBackend(ctx, b, TypeGomod, &gomodM); err != nil {
		errs = append(errs, err)
	}
	s.Gomod = gomodM.Entries

	var helmM HelmManifest
	if err := loadFromBackend(ctx, b, TypeHelm, &helmM); err != nil {
		errs = append(errs, err)
	}
	s.Helm = helmM.Entries

	var npmM NpmManifest
	if err := loadFromBackend(ctx, b, TypeNpm, &npmM); err != nil {
		errs = append(errs, err)
	}
	s.Npm = npmM.Entries

	if len(errs) > 0 {
		return nil, joinErrors(errs)
	}
	return s, nil
}

// loadFromBackend reads and verifies a single manifest from a Backend.
func loadFromBackend(ctx context.Context, b Backend, manifestType string, dest interface{}) error {
	filename := manifestType + ".json"
	data, err := b.Read(ctx, filename)
	if err != nil {
		return fmt.Errorf("read manifest %s from %s: %w", filename, b.Label(), err)
	}
	if data == nil {
		return nil // missing manifest is ok
	}

	// Verify MD5
	storedMD5, err := b.ReadMD5(ctx, filename)
	if err != nil {
		return fmt.Errorf("read MD5 for %s: %w", filename, err)
	}
	if storedMD5 != "" {
		actual := fmt.Sprintf("%x", md5.Sum(data)) //nolint:gosec
		if storedMD5 != actual {
			return fmt.Errorf(
				"integrity check failed for %s (from %s): MD5 mismatch\n"+
					"Run: bootstrap --break-glass-update-md5 %s",
				filename, b.Label(), manifestType,
			)
		}
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("parse manifest %s: %w", filename, err)
	}
	return nil
}

// SaveToBackend marshals and writes a manifest via the Store's backend.
func (s *Store) SaveToBackend(ctx context.Context, manifestType string, v interface{}) error {
	if s.backend == nil {
		return s.saveManifest(manifestType, v)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s manifest: %w", manifestType, err)
	}
	data = append(data, '\n')
	return s.backend.Write(ctx, manifestType+".json", data)
}

// Backend returns the Store's backend, or nil if loaded from local filesystem.
func (s *Store) Backend() Backend { return s.backend }

// LoadType loads a single manifest by type name, verifying MD5 integrity.
func LoadType(dir, manifestType string, dest interface{}) error {
	return loadManifest(dir, manifestType, dest)
}

// loadManifest reads, integrity-checks, and unmarshals a single manifest file.
func loadManifest(dir, manifestType string, dest interface{}) error {
	path := filepath.Join(dir, manifestType+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing manifests are silently skipped; the zero value of dest is fine.
			return nil
		}
		return fmt.Errorf("read manifest %s: %w", path, err)
	}

	ok, err := VerifyMD5(path, data)
	if err != nil {
		return fmt.Errorf("integrity check for %s: %w", path, err)
	}
	if !ok {
		return fmt.Errorf(
			"integrity check failed for %s: MD5 mismatch — manifest may have been modified outside of bootstrap.\n"+
				"Run: bootstrap --break-glass-update-md5 %s",
			path, manifestType,
		)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("parse manifest %s: %w", path, err)
	}
	return nil
}

// SaveApt marshals and writes apt.json, updating the MD5 companion file.
func (s *Store) SaveApt() error {
	return s.saveManifest(TypeApt, AptManifest{ConfigVersion: CurrentConfigVersion, Entries: s.Apt})
}

// SaveGit marshals and writes git.json, updating the MD5 companion file.
func (s *Store) SaveGit() error {
	return s.saveManifest(TypeGit, GitManifest{ConfigVersion: CurrentConfigVersion, Entries: s.Git})
}

// SavePypi marshals and writes pypi.json, updating the MD5 companion file.
func (s *Store) SavePypi() error {
	s.Pypi.ConfigVersion = CurrentConfigVersion
	return s.saveManifest(TypePypi, s.Pypi)
}

// SaveBinary marshals and writes binary.json, updating the MD5 companion file.
func (s *Store) SaveBinary() error {
	return s.saveManifest(TypeBinary, BinaryManifest{ConfigVersion: CurrentConfigVersion, Entries: s.Binary})
}

// SaveGomod marshals and writes gomod.json, updating the MD5 companion file.
func (s *Store) SaveGomod() error {
	return s.saveManifest(TypeGomod, GomodManifest{ConfigVersion: CurrentConfigVersion, Entries: s.Gomod})
}

// SaveHelm marshals and writes helm.json, updating the MD5 companion file.
func (s *Store) SaveHelm() error {
	return s.saveManifest(TypeHelm, HelmManifest{ConfigVersion: CurrentConfigVersion, Entries: s.Helm})
}

// SaveNpm marshals and writes npm.json, updating the MD5 companion file.
func (s *Store) SaveNpm() error {
	return s.saveManifest(TypeNpm, NpmManifest{ConfigVersion: CurrentConfigVersion, Entries: s.Npm})
}

// saveManifest marshals v to JSON and writes it, then updates the MD5 file.
func (s *Store) saveManifest(manifestType string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s manifest: %w", manifestType, err)
	}
	data = append(data, '\n')

	path := filepath.Join(s.dir, manifestType+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s manifest: %w", path, err)
	}
	if err := WriteMD5File(path, data); err != nil {
		return err
	}
	return nil
}

// Dir returns the manifest directory.
func (s *Store) Dir() string { return s.dir }

// FindApt returns the entry matching name, or nil.
func (s *Store) FindApt(name string) *AptEntry {
	for i := range s.Apt {
		if s.Apt[i].Name == name {
			return &s.Apt[i]
		}
	}
	return nil
}

// FindGit returns the entry matching name, or nil.
func (s *Store) FindGit(name string) *GitEntry {
	for i := range s.Git {
		if s.Git[i].Name == name {
			return &s.Git[i]
		}
	}
	return nil
}

// FindBinary returns the entry matching name, or nil.
func (s *Store) FindBinary(name string) *BinaryEntry {
	for i := range s.Binary {
		if s.Binary[i].Name == name {
			return &s.Binary[i]
		}
	}
	return nil
}

// FindGomod returns the entry matching name, or nil.
func (s *Store) FindGomod(name string) *GomodEntry {
	for i := range s.Gomod {
		if s.Gomod[i].Name == name {
			return &s.Gomod[i]
		}
	}
	return nil
}

// FindHelm returns the entry matching name, or nil.
func (s *Store) FindHelm(name string) *HelmEntry {
	for i := range s.Helm {
		if s.Helm[i].Name == name {
			return &s.Helm[i]
		}
	}
	return nil
}

// FindNpm returns the entry matching name, or nil.
func (s *Store) FindNpm(name string) *NpmEntry {
	for i := range s.Npm {
		if s.Npm[i].Name == name {
			return &s.Npm[i]
		}
	}
	return nil
}

// RemoveApt deletes the entry with the given name and saves.
func (s *Store) RemoveApt(name string) error {
	orig := len(s.Apt)
	filtered := s.Apt[:0]
	for _, e := range s.Apt {
		if e.Name != name {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == orig {
		return fmt.Errorf("apt entry %q not found", name)
	}
	s.Apt = filtered
	return s.SaveApt()
}

// RemoveGit deletes the entry with the given name and saves.
func (s *Store) RemoveGit(name string) error {
	orig := len(s.Git)
	filtered := s.Git[:0]
	for _, e := range s.Git {
		if e.Name != name {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == orig {
		return fmt.Errorf("git entry %q not found", name)
	}
	s.Git = filtered
	return s.SaveGit()
}

// RemoveBinary deletes the entry with the given name and saves.
func (s *Store) RemoveBinary(name string) error {
	orig := len(s.Binary)
	filtered := s.Binary[:0]
	for _, e := range s.Binary {
		if e.Name != name {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == orig {
		return fmt.Errorf("binary entry %q not found", name)
	}
	s.Binary = filtered
	return s.SaveBinary()
}

// RemoveGomod deletes the entry with the given name and saves.
func (s *Store) RemoveGomod(name string) error {
	orig := len(s.Gomod)
	filtered := s.Gomod[:0]
	for _, e := range s.Gomod {
		if e.Name != name {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == orig {
		return fmt.Errorf("gomod entry %q not found", name)
	}
	s.Gomod = filtered
	return s.SaveGomod()
}

// RemoveHelm deletes the entry with the given name and saves.
func (s *Store) RemoveHelm(name string) error {
	orig := len(s.Helm)
	filtered := s.Helm[:0]
	for _, e := range s.Helm {
		if e.Name != name {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == orig {
		return fmt.Errorf("helm entry %q not found", name)
	}
	s.Helm = filtered
	return s.SaveHelm()
}

// RemoveNpm deletes the entry with the given name and saves.
func (s *Store) RemoveNpm(name string) error {
	orig := len(s.Npm)
	filtered := s.Npm[:0]
	for _, e := range s.Npm {
		if e.Name != name {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == orig {
		return fmt.Errorf("npm entry %q not found", name)
	}
	s.Npm = filtered
	return s.SaveNpm()
}

// AllNames returns every name defined across all manifests, keyed by type.
func (s *Store) AllNames() map[string][]string {
	m := map[string][]string{
		TypeApt:    make([]string, 0, len(s.Apt)),
		TypeGit:    make([]string, 0, len(s.Git)),
		TypePypi:   {},
		TypeBinary: make([]string, 0, len(s.Binary)),
		TypeGomod:  make([]string, 0, len(s.Gomod)),
		TypeHelm:   make([]string, 0, len(s.Helm)),
		TypeNpm:    make([]string, 0, len(s.Npm)),
	}
	for _, e := range s.Apt {
		m[TypeApt] = append(m[TypeApt], e.Name)
	}
	for _, e := range s.Git {
		m[TypeGit] = append(m[TypeGit], e.Name)
	}
	for _, e := range s.Binary {
		m[TypeBinary] = append(m[TypeBinary], e.Name)
	}
	for _, e := range s.Gomod {
		m[TypeGomod] = append(m[TypeGomod], e.Name)
	}
	for _, e := range s.Helm {
		m[TypeHelm] = append(m[TypeHelm], e.Name)
	}
	for _, e := range s.Npm {
		m[TypeNpm] = append(m[TypeNpm], e.Name)
	}
	return m
}

// joinErrors concatenates multiple errors into one.
func joinErrors(errs []error) error {
	msg := ""
	for _, e := range errs {
		if msg != "" {
			msg += "; "
		}
		msg += e.Error()
	}
	return fmt.Errorf("%s", msg)
}
