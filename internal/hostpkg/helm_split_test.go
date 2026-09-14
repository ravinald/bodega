package hostpkg

import "testing"

// splitChart was a fourth rule for the same derivation, and it disagreed with
// manifest.ParseKey on the v-prefixed shape helm charts are routinely
// published at: a "v" stops a right-to-left scan for a digit, so the whole
// string came back as the name at no version. ParseKey reads it as a name and
// a version, because builder.ParseSemVer accepts the prefix and keeps it.
func TestSplitChartAgreesWithParseKey(t *testing.T) {
	cases := []struct{ chart, name, version string }{
		{"cert-manager-1.14.0-rc.1", "cert-manager", "1.14.0-rc.1"},
		{"ingress-nginx-4.11.2", "ingress-nginx", "4.11.2"},
		{"kube-prometheus-stack-62.7.0", "kube-prometheus-stack", "62.7.0"},
		{"foo--bar-1.2.3", "foo--bar", "1.2.3"},
		// The case that failed: name="mychart-v1.2.3", version="".
		{"mychart-v1.2.3", "mychart", "v1.2.3"},
		{"mychart-V1.2.3", "mychart", "V1.2.3"},
		// No version at all stays whole rather than losing its tail.
		{"cert-manager", "cert-manager", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.chart, func(t *testing.T) {
			name, version := splitChart(tc.chart)
			if name != tc.name || version != tc.version {
				t.Errorf("splitChart(%q) = (%q, %q), want (%q, %q)",
					tc.chart, name, version, tc.name, tc.version)
			}
		})
	}
}
