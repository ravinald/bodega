package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// ---- what pkg counts as one package ----------------------------------------
//
// pkg loads a catalogue into SQLite and then creates a UNIQUE index over
// manifestdigest (2.8.2, libpkg/repo/binary/update.c:746). Two records it
// hashes alike take the whole repository down rather than one package: the
// client reports the entries processed, fails on
// "UNIQUE constraint failed: packages.manifestdigest", and keeps whatever
// catalogue it already had.
//
// That digest is not taken over the record. pkg_checksum_generate
// (libpkg/pkg_checksum.c:194) hashes a fixed field set — name, origin,
// version, arch, the vital flag, options, required and provided shlibs,
// users, groups, dependencies, provides and requires — sorted by key and then
// by value, each pair's key and value concatenated with no separator. Comment,
// description, maintainer, flatsize, pkgsize, sum and repopath reach none of
// it. So two objects that differ in their bytes, their size and the path they
// are stored under are one package to that index, and a digest of the record
// or of the object would say they were two.
//
// This reproduces the equivalence rather than the digest, and hashes with
// SHA-256 instead of pkg's BLAKE2b-base32: what a caller needs is whether two
// records fall together, and the encoding of that answer is nobody's business
// outside this file. What has to match upstream is the field set and the
// ordering, which is why both are spelled out above and traced below.

// freeBSDIdentityEntry is one key/value pair on its way into the identity, in
// pkg's own shape: pkg pushes options under their own option name and every
// repeated field under a fixed singular key ("required_shlib", "depend"), so
// the pairs are not a map and two of them may share a key.
type freeBSDIdentityEntry struct{ key, value string }

// freeBSDIdentityFields are the list-valued manifest fields, each with the
// entry key pkg files its members under.
var freeBSDIdentityFields = []struct{ field, entry string }{
	{"shlibs_required", "required_shlib"},
	{"shlibs_provided", "provided_shlib"},
	{"users", "user"},
	{"groups", "group"},
	{"provides", "provide"},
	{"requires", "require"},
}

// freeBSDPkgIdentity is the package two catalogue records describe, equal
// exactly when pkg would index them under one manifestdigest.
//
// A field of the wrong JSON type fails rather than being read past. The
// identity decides whether two objects may both be published, so a field
// quietly treated as absent is a pair that looks distinct here and collides at
// the client, which is the failure this whole path exists to prevent.
func freeBSDPkgIdentity(fields map[string]json.RawMessage) (string, error) {
	var entries []freeBSDIdentityEntry
	push := func(key, value string) { entries = append(entries, freeBSDIdentityEntry{key, value}) }

	// Pushed whether or not the manifest carries them, because pkg pushes
	// them unconditionally: a record with no origin is one entry with an
	// empty value, not one entry fewer.
	for _, name := range []string{"name", "origin", "version", "arch"} {
		v, err := freeBSDIdentityScalar(fields, name)
		if err != nil {
			return "", err
		}
		push(name, v)
	}
	vital, err := freeBSDIdentityVital(fields)
	if err != nil {
		return "", err
	}
	push("vital", vital)

	options, err := freeBSDIdentityObject(fields, "options")
	if err != nil {
		return "", err
	}
	for key, value := range options {
		push(key, value)
	}

	for _, list := range freeBSDIdentityFields {
		values, err := freeBSDIdentityList(fields, list.field)
		if err != nil {
			return "", err
		}
		for _, v := range values {
			push(list.entry, v)
		}
	}

	deps, err := freeBSDIdentityDeps(fields)
	if err != nil {
		return "", err
	}
	for _, dep := range deps {
		push("depend", dep)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key != entries[j].key {
			return entries[i].key < entries[j].key
		}
		return entries[i].value < entries[j].value
	})
	h := sha256.New()
	for _, e := range entries {
		_, _ = io.WriteString(h, e.key)
		_, _ = io.WriteString(h, e.value)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// freeBSDIdentityScalar reads one string-valued field, accepting the literal
// text of a number or a boolean.
//
// Tolerant on type because a manifest is written by whatever built the
// package and pkg's own reader coerces a scalar to a string; refusing a
// version spelled 2 rather than "2" would take a repository down over a
// difference pkg does not see. An object or an array is a different matter:
// there is no text of one that pkg would agree with, so it fails.
func freeBSDIdentityScalar(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	switch raw[0] {
	case '{', '[':
		return "", fmt.Errorf("%s is %s, and pkg hashes it as a string; the catalogue cannot say which package this is", name, freeBSDJSONKind(raw))
	}
	return string(raw), nil
}

// freeBSDIdentityVital renders the vital flag the way pkg does: "1" or "0",
// always present.
func freeBSDIdentityVital(fields map[string]json.RawMessage) (string, error) {
	raw, ok := fields["vital"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "0", nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		if b {
			return "1", nil
		}
		return "0", nil
	}
	s, err := freeBSDIdentityScalar(fields, "vital")
	if err != nil {
		return "", err
	}
	switch s {
	case "", "0", "false", "no", "off":
		return "0", nil
	}
	return "1", nil
}

// freeBSDIdentityObject reads an object of scalars, which is what options is.
func freeBSDIdentityObject(fields map[string]json.RawMessage, name string) (map[string]string, error) {
	raw, ok := fields[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%s is %s, and pkg reads it as an object of values: %w", name, freeBSDJSONKind(raw), err)
	}
	out := make(map[string]string, len(obj))
	for key, value := range obj {
		v, err := freeBSDIdentityScalar(map[string]json.RawMessage{key: value}, key)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[key] = v
	}
	return out, nil
}

// freeBSDIdentityList reads an array of strings.
func freeBSDIdentityList(fields map[string]json.RawMessage, name string) ([]string, error) {
	raw, ok := fields[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%s is %s, and pkg reads it as a list: %w", name, freeBSDJSONKind(raw), err)
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		v, err := freeBSDIdentityScalar(map[string]json.RawMessage{name: item}, name)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// freeBSDIdentityDeps renders each dependency as pkg does, "<name>~<origin>".
func freeBSDIdentityDeps(fields map[string]json.RawMessage) ([]string, error) {
	raw, ok := fields["deps"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var deps map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &deps); err != nil {
		return nil, fmt.Errorf("deps is %s, and pkg reads it as an object of dependencies: %w", freeBSDJSONKind(raw), err)
	}
	out := make([]string, 0, len(deps))
	for name, dep := range deps {
		origin, err := freeBSDIdentityScalar(dep, "origin")
		if err != nil {
			return nil, fmt.Errorf("deps.%s: %w", name, err)
		}
		out = append(out, name+"~"+origin)
	}
	return out, nil
}

// freeBSDJSONKind names what a value is, for an error a person reads.
func freeBSDJSONKind(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "empty"
	}
	switch raw[0] {
	case '{':
		return "an object"
	case '[':
		return "a list"
	case '"':
		return "a string"
	case 't', 'f':
		return "a boolean"
	case 'n':
		return "null"
	}
	return "a number"
}
