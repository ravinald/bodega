package manifest

import "testing"

func TestRpmEVROmitsAZeroEpoch(t *testing.T) {
	for _, tc := range []struct{ epoch, ver, rel, want string }{
		{"0", "2.4.57", "5.el9", "2.4.57-5.el9"},
		{"", "2.4.57", "5.el9", "2.4.57-5.el9"},
		{"2", "1.20.1", "20.el9", "2:1.20.1-20.el9"},
		{"00", "1", "1", "1-1"},
	} {
		if got := RpmEVR(tc.epoch, tc.ver, tc.rel); got != tc.want {
			t.Errorf("RpmEVR(%q, %q, %q) = %q, want %q", tc.epoch, tc.ver, tc.rel, got, tc.want)
		}
	}
}

func TestRpmFileIdentity(t *testing.T) {
	for _, tc := range []struct{ file, name, version string }{
		{"nginx-1.20.1-20.el9.x86_64.rpm", "nginx", "1.20.1-20.el9"},
		{"python3.12-pip-23.2.1-4.el9.noarch.rpm", "python3.12-pip", "23.2.1-4.el9"},
		{"389-ds-base-2.4.5-5.el9_4.x86_64.rpm", "389-ds-base", "2.4.5-5.el9_4"},
		{"nginx.x86_64.rpm", "", ""},
		{"nginx-1.0-1.x86_64.deb", "", ""},
	} {
		if n, v := RpmFileIdentity(tc.file); n != tc.name || v != tc.version {
			t.Errorf("RpmFileIdentity(%q) = %q, %q, want %q, %q", tc.file, n, v, tc.name, tc.version)
		}
	}
}

func TestRpmPathElementValidation(t *testing.T) {
	for _, v := range []string{"9", "10", "9.4"} {
		if !RpmValidReleasever(v) {
			t.Errorf("releasever %q refused", v)
		}
	}
	for _, v := range []string{"", "9-stream", "9.4.1", "../9", "9/x86_64", "$releasever"} {
		if RpmValidReleasever(v) {
			t.Errorf("releasever %q accepted", v)
		}
	}
	for _, a := range []string{"i686", "x86_64/..", "X86_64", ""} {
		if RpmValidBasearch(a) {
			t.Errorf("basearch %q accepted", a)
		}
	}
	for _, n := range []string{"..", ".hidden", "a/b", "-x", ""} {
		if RpmValidRepoName(n) {
			t.Errorf("repository name %q accepted", n)
		}
	}
}
