package server

import "testing"

func TestCargoCrateFromIndexPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path  string
		want  string
		valid bool
	}{
		// 1-character crate
		{"1/z", "z", true},
		// 2-character crate
		{"2/io", "io", true},
		// 3-character crate
		{"3/l/lyx", "lyx", true},
		// 4+ character crates
		{"se/rd/serde", "serde", true},
		{"to/ki/tokio", "tokio", true},
		{"th/an/thanos", "thanos", true},

		// Wrong shard prefix for 4-char path
		{"se/rd/wrong", "", false},
		// Wrong shard for 3-char crate
		{"3/x/lyx", "", false},
		// Wrong length-prefix
		{"1/io", "", false},
		{"2/z", "", false},
		{"3/se/serde", "", false},
		// Path traversal / illegal characters
		{"../escape", "", false},
		{"se/rd/SERDE", "", false},      // uppercase rejected
		{"se/rd/.hidden", "", false},    // leading dot rejected
		{"se/rd/serde$evil", "", false}, // illegal char
		// Wrong segment counts
		{"serde", "", false},
		{"a/b/c/d", "", false},
	}

	for _, c := range cases {
		got, ok := cargoCrateFromIndexPath(c.path)
		if ok != c.valid {
			t.Errorf("cargoCrateFromIndexPath(%q) ok=%v, want %v", c.path, ok, c.valid)
			continue
		}
		if got != c.want {
			t.Errorf("cargoCrateFromIndexPath(%q) crate=%q, want %q", c.path, got, c.want)
		}
	}
}

func TestCargoCrateNamePattern(t *testing.T) {
	t.Parallel()

	good := []string{"a", "z", "io", "go", "serde", "tokio", "snake_case", "kebab-case", "abc123"}
	for _, n := range good {
		if !cargoCrateNamePattern.MatchString(n) {
			t.Errorf("cargoCrateNamePattern: %q should be valid", n)
		}
	}

	bad := []string{
		"",
		"-leading-dash",
		"_leading-underscore",
		"UPPER",
		"has space",
		"has.dot",
		"has/slash",
		"@scoped",
	}
	for _, n := range bad {
		if cargoCrateNamePattern.MatchString(n) {
			t.Errorf("cargoCrateNamePattern: %q should be rejected", n)
		}
	}
}

func TestCargoVersionPattern(t *testing.T) {
	t.Parallel()

	good := []string{"1", "1.0", "1.0.0", "1.0.0-rc.1", "1.0.0+build.42", "0.0.0"}
	for _, v := range good {
		if !cargoVersionPattern.MatchString(v) {
			t.Errorf("cargoVersionPattern: %q should be valid", v)
		}
	}

	bad := []string{"", "1 0", "1/0", "1.0.0\nhack", "../escape"}
	for _, v := range bad {
		if cargoVersionPattern.MatchString(v) {
			t.Errorf("cargoVersionPattern: %q should be rejected", v)
		}
	}
}
