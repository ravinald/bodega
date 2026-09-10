// Package deb822 parses Debian-style control file blocks (the "deb822"
// format used by dpkg, apt, and debian/control). Values are single-line
// or space/tab-continued; a continuation line whose content is "." is
// preserved as a blank line inside the value, per Debian's convention
// for paragraph breaks within long fields like Description.
//
// ParseSingle reads one paragraph; ParseStream reads a multi-paragraph
// document (a Packages index, a dpkg status file) one paragraph at a time.
package deb822

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

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
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var para bytes.Buffer
	flush := func() error {
		if para.Len() == 0 {
			return nil
		}
		fields, err := ParseSingle(para.Bytes())
		para.Reset()
		if err != nil {
			return err
		}
		if len(fields) == 0 {
			return nil
		}
		return fn(fields)
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
