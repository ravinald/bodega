package builder

import "testing"

// TestSHA256SumFor is issue #91: the matcher used to take the first line
// merely ending in ".tar.gz", so a release publishing more than one artifact
// handed the caller some other file's digest to compare against.
func TestSHA256SumFor(t *testing.T) {
	const (
		other  = "1111111111111111111111111111111111111111111111111111111111111111"
		source = "2222222222222222222222222222222222222222222222222222222222222222"
	)
	// A release with the source archive listed after two other tarballs, which
	// is the shape the old prefix/suffix test got wrong.
	body := other + "  netbox-linux-amd64.tar.gz\n" +
		other + "  netbox-darwin-arm64.tar.gz\n" +
		source + "  v4.5.5.tar.gz\n"

	for _, tc := range []struct {
		name, body, want string
		file             string
	}{
		{"names the archive", body, source, "v4.5.5.tar.gz"},
		{"names no such file", body, "", "v4.5.6.tar.gz"},
		{"binary mode star", "*" + source + "\n", "", "v4.5.5.tar.gz"},
		{"binary mode name", source + " *v4.5.5.tar.gz\n", source, "v4.5.5.tar.gz"},
		{"path prefix", source + "  dist/v4.5.5.tar.gz\n", source, "v4.5.5.tar.gz"},
		{"short digest", "abc  v4.5.5.tar.gz\n", "", "v4.5.5.tar.gz"},
		{"empty body", "", "", "v4.5.5.tar.gz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sha256SumFor(tc.body, tc.file); got != tc.want {
				t.Errorf("sha256SumFor(_, %q) = %q, want %q", tc.file, got, tc.want)
			}
		})
	}
}
