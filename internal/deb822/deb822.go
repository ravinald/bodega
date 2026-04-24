// Package deb822 parses Debian-style control file blocks (the "deb822"
// format used by dpkg, apt, and debian/control). Values are single-line
// or space/tab-continued; a continuation line whose content is "." is
// preserved as a blank line inside the value, per Debian's convention
// for paragraph breaks within long fields like Description.
//
// Only single-paragraph parsing is exposed today. Multi-paragraph input
// (Packages indices, Release files, dpkg status files) is a future
// addition when a consumer needs it.
package deb822

import (
	"bufio"
	"bytes"
	"fmt"
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
