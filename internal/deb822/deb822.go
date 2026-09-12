// Package deb822 parses Debian-style control file blocks (the "deb822"
// format used by dpkg, apt, and debian/control). Values are single-line
// or space/tab-continued; a continuation line whose content is "." is
// preserved as a blank line inside the value, per Debian's convention
// for paragraph breaks within long fields like Description.
//
// ParseSingle reads one paragraph; ParseStream reads a multi-paragraph
// document (a Packages index, a dpkg status file) one paragraph at a time,
// and ParseStreamRaw hands the paragraph's own bytes over with the fields so a
// filter can copy what it keeps rather than re-serialize it.
package deb822

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// SourceName is the source package a binary paragraph belongs to.
//
// Debian omits Source: when it matches the binary name and writes
// "expat (2.4.7-1)" when the source was built at a version the binary does not
// share, so the bare field is neither always present nor always a bare name.
// Two callers want the same answer for different reasons — an advisory lookup
// keyed on the source name, and a profile whose membership closes over it —
// and Ubuntu renames, splits and transitions binaries within one stable source
// often enough that the two disagreeing would show up as a package refused on
// ordinary maintenance.
func SourceName(fields map[string]string) string {
	if src := SourceField(fields["Source"]); src != "" {
		return src
	}
	return strings.TrimSpace(fields["Package"])
}

// SourceVersion is the version of the source package a binary paragraph was
// built from: what the Source: field carries in parentheses, and the binary's
// own Version: where the field carries none.
//
// Debian writes "Source: nginx (1.24.0-2ubuntu7.1)" exactly when the two
// differ, which is what a binNMU produces — source 1.24.0-2ubuntu7.1 shipping
// a binary at 1.24.0-2ubuntu7.1+b1. A caller whose membership closes over the
// source name has to compare a version against the source too. Handed the
// binary's, an exact pin taken from the source record refuses that binary and
// keeps its siblings, which leaves the kept package uninstallable for a reason
// the operator cannot find in the pin they wrote.
func SourceVersion(fields map[string]string) string {
	src := fields["Source"]
	if i := strings.IndexByte(src, '('); i >= 0 {
		if j := strings.IndexByte(src[i:], ')'); j > 1 {
			if v := strings.TrimSpace(src[i+1 : i+j]); v != "" {
				return v
			}
		}
	}
	return strings.TrimSpace(fields["Version"])
}

// SourceField strips the version a Source: field carries, for a caller reading
// the field on its own rather than a whole paragraph.
func SourceField(val string) string {
	if i := strings.IndexByte(val, '('); i > 0 {
		val = val[:i]
	}
	return strings.TrimSpace(val)
}

// ParseSingle parses one deb822 paragraph. Continuation lines are joined
// into the value with "\n"; the leading continuation whitespace is
// stripped, and a continuation line consisting solely of "." becomes an
// empty line in the joined value. Callers re-emitting the paragraph
// must re-add the single-space continuation prefix and translate blank
// lines back to " .".
func ParseSingle(data []byte) (map[string]string, error) {
	fields := make(map[string]string)
	var (
		currentKey string
		value      strings.Builder
	)
	flush := func() {
		if currentKey != "" {
			fields[currentKey] = value.String()
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if currentKey == "" {
				return nil, fmt.Errorf("line %d: continuation before any field", lineNum)
			}
			content := strings.TrimLeft(line, " \t")
			if content == "." {
				content = ""
			}
			value.WriteByte('\n')
			value.WriteString(content)
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("line %d: expected Key: value, got %q", lineNum, line)
		}
		flush()
		currentKey = strings.TrimSpace(line[:colon])
		value.Reset()
		value.WriteString(strings.TrimSpace(line[colon+1:]))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return fields, nil
}

// ParseStream reads a multi-paragraph document and calls fn once per
// paragraph, in file order. Paragraphs are separated by a blank line, and a
// trailing separator is not required.
//
// It streams rather than returning a slice because the documents that need it
// are large: an Ubuntu universe Packages index is tens of thousands of
// paragraphs and hundreds of megabytes uncompressed, while a caller matching a
// host inventory against it keeps a few hundred. fn owns the map it is handed
// and may retain it.
//
// An error from fn stops the walk and is returned unchanged, so a caller that
// has seen enough can end the read with a sentinel of its own.
func ParseStream(r io.Reader, fn func(fields map[string]string) error) error {
	return ParseStreamRaw(r, func(_ []byte, fields map[string]string) error { return fn(fields) })
}

// ParseStreamRaw is ParseStream with the paragraph's own bytes handed to fn
// beside the parsed fields.
//
// It exists for a caller that copies paragraphs through rather than rewriting
// them. ParseSingle returns a map, so the field order, the continuation
// layout and any field this package folds are all gone by the time fn sees
// them; re-serializing from the map is a second grammar to get wrong, and it
// gets it wrong silently — a Packages index that still parses, with a
// Description that lost its leading space or a rare field flattened onto one
// line. A filter that decides per paragraph and emits raw needs no grammar at
// all on the way out.
//
// raw is the paragraph including its trailing newline and excluding the blank
// line that ended it. The buffer behind it is reused on the next paragraph, so
// fn must copy anything it retains.
func ParseStreamRaw(r io.Reader, fn func(raw []byte, fields map[string]string) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var para bytes.Buffer
	flush := func() error {
		if para.Len() == 0 {
			return nil
		}
		raw := para.Bytes()
		fields, err := ParseSingle(raw)
		if err != nil {
			para.Reset()
			return err
		}
		if len(fields) == 0 {
			para.Reset()
			return nil
		}
		err = fn(raw, fields)
		para.Reset()
		return err
	}

	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimRight(line, " \t\r")) == 0 {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		para.Write(line)
		para.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return flush()
}
