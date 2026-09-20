package deb822

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSingle_BasicFields(t *testing.T) {
	input := "Package: bash\nVersion: 5.2.21-2ubuntu4\nArchitecture: amd64\n"
	got, err := ParseSingle([]byte(input))
	if err != nil {
		t.Fatalf("ParseSingle: %v", err)
	}
	want := map[string]string{
		"Package":      "bash",
		"Version":      "5.2.21-2ubuntu4",
		"Architecture": "amd64",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %q = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d fields, want %d: %v", len(got), len(want), got)
	}
}

func TestParseSingle_Continuation(t *testing.T) {
	input := "Description: short synopsis\n long-body line one\n long-body line two\n"
	got, err := ParseSingle([]byte(input))
	if err != nil {
		t.Fatalf("ParseSingle: %v", err)
	}
	want := "short synopsis\nlong-body line one\nlong-body line two"
	if got["Description"] != want {
		t.Errorf("Description = %q, want %q", got["Description"], want)
	}
}

func TestParseSingle_DotParagraphSeparator(t *testing.T) {
	input := "Description: synopsis\n paragraph one\n .\n paragraph two\n"
	got, err := ParseSingle([]byte(input))
	if err != nil {
		t.Fatalf("ParseSingle: %v", err)
	}
	want := "synopsis\nparagraph one\n\nparagraph two"
	if got["Description"] != want {
		t.Errorf("Description = %q, want %q", got["Description"], want)
	}
}

func TestParseSingle_WhitespaceAroundKeyAndValue(t *testing.T) {
	input := "Package:   bash  \nVersion:5.2.21\n"
	got, err := ParseSingle([]byte(input))
	if err != nil {
		t.Fatalf("ParseSingle: %v", err)
	}
	if got["Package"] != "bash" {
		t.Errorf("Package = %q, want %q", got["Package"], "bash")
	}
	if got["Version"] != "5.2.21" {
		t.Errorf("Version = %q, want %q", got["Version"], "5.2.21")
	}
}

func TestParseSingle_EmptyInput(t *testing.T) {
	got, err := ParseSingle(nil)
	if err != nil {
		t.Fatalf("ParseSingle(nil): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d fields, want empty", len(got))
	}
}

func TestParseSingle_ContinuationBeforeField(t *testing.T) {
	input := " stray continuation\nPackage: bash\n"
	_, err := ParseSingle([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "continuation") {
		t.Fatalf("want continuation-before-field error, got %v", err)
	}
}

func TestParseSingle_MissingColon(t *testing.T) {
	input := "Package bash\n"
	_, err := ParseSingle([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("want Key:value format error, got %v", err)
	}
}

func TestParseSingle_TabContinuation(t *testing.T) {
	input := "Description: synopsis\n\tbody\n"
	got, err := ParseSingle([]byte(input))
	if err != nil {
		t.Fatalf("ParseSingle: %v", err)
	}
	if got["Description"] != "synopsis\nbody" {
		t.Errorf("Description = %q, want %q", got["Description"], "synopsis\nbody")
	}
}

func TestParseSingle_RealBashControl(t *testing.T) {
	input := "Package: bash\n" +
		"Version: 5.2.21-2ubuntu4\n" +
		"Architecture: amd64\n" +
		"Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n" +
		"Installed-Size: 1884\n" +
		"Depends: base-files (>= 2.1.12), debianutils (>= 5.6-0.1)\n" +
		"Pre-Depends: libc6 (>= 2.34), libtinfo6 (>= 6)\n" +
		"Section: shells\n" +
		"Priority: required\n" +
		"Multi-Arch: foreign\n" +
		"Homepage: http://tiswww.case.edu/php/chet/bash/bashtop.html\n" +
		"Description: GNU Bourne Again SHell\n" +
		" Bash is an sh-compatible command language interpreter that executes\n" +
		" commands read from the standard input or from a file.  Bash also\n" +
		" incorporates useful features from the Korn and C shells (ksh and csh).\n" +
		" .\n" +
		" Bash is ultimately intended to be a conformant implementation of the\n" +
		" IEEE POSIX Shell and Tools specification (IEEE Working Group 1003.2).\n"
	got, err := ParseSingle([]byte(input))
	if err != nil {
		t.Fatalf("ParseSingle: %v", err)
	}
	if got["Package"] != "bash" {
		t.Errorf("Package = %q", got["Package"])
	}
	if !strings.HasPrefix(got["Description"], "GNU Bourne Again SHell\nBash is") {
		t.Errorf("Description head = %q", got["Description"][:40])
	}
	if !strings.Contains(got["Description"], "\n\nBash is ultimately") {
		t.Errorf("Description missing blank-paragraph split: %q", got["Description"])
	}
}

func TestParseStream_ParagraphsInOrder(t *testing.T) {
	// No trailing blank line after the last paragraph, which is what a
	// Packages index served over HTTP often ends with.
	input := "Package: apparmor\nVersion: 3.0.4\n\n" +
		"Package: ca-certificates\nVersion: 20230311\nArchitecture: all\n\n\n" +
		"Package: zerofree\nVersion: 1.1.1"

	var names, versions []string
	if err := ParseStream(strings.NewReader(input), func(fields map[string]string) error {
		names = append(names, fields["Package"])
		versions = append(versions, fields["Version"])
		return nil
	}); err != nil {
		t.Fatalf("ParseStream: %v", err)
	}

	if got, want := strings.Join(names, " "), "apparmor ca-certificates zerofree"; got != want {
		t.Errorf("packages = %q, want %q", got, want)
	}
	if got, want := strings.Join(versions, " "), "3.0.4 20230311 1.1.1"; got != want {
		t.Errorf("versions = %q, want %q", got, want)
	}
}

// TestParseStream_StopsOnCallbackError keeps the walk abandonable. A caller
// reading a hundred-megabyte index to answer one question should not have to
// read the rest of it.
func TestParseStream_StopsOnCallbackError(t *testing.T) {
	stop := errors.New("seen enough")
	seen := 0
	err := ParseStream(strings.NewReader("Package: a\n\nPackage: b\n\nPackage: c\n"), func(map[string]string) error {
		seen++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Errorf("error = %v, want the caller's own sentinel", err)
	}
	if seen != 1 {
		t.Errorf("callback ran %d times after asking to stop", seen)
	}
}

// TestParseStream_ReportsAMalformedParagraph keeps a broken index from reading
// as a short one. Silently skipping the paragraph would report every package
// after it as absent.
func TestParseStream_ReportsAMalformedParagraph(t *testing.T) {
	err := ParseStream(strings.NewReader("Package: a\n\nthis line has no colon\n"), func(map[string]string) error {
		return nil
	})
	if err == nil {
		t.Fatal("a paragraph that is not deb822 was accepted")
	}
	if !strings.Contains(err.Error(), "expected Key: value") {
		t.Errorf("error = %q, want it to name the malformed line", err)
	}
}
