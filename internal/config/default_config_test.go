package config

import (
	"encoding/json"
	"testing"
)

// TestDefaultConfigContent guards the hand-written JSON literal in
// defaultConfigContent. A syntax error there fails silently in production:
// loadFileConfig skips a file it cannot parse, so the operator gets built-in
// defaults with no warning that their config file is unreadable. The value
// assertions catch the generated file drifting from the defaults Load applies.
func TestDefaultConfigContent(t *testing.T) {
	var got map[string]any
	if err := json.Unmarshal(defaultConfigContent(), &got); err != nil {
		t.Fatalf("defaultConfigContent is not valid JSON: %v", err)
	}

	want := map[string]any{
		"storage_backend":   "local",
		"storage_path":      "/var/lib/bodega",
		"listen_addr":       DefaultListenAddr,
		"apt_codename":      "noble",
		"apt_suites":        []any{"noble"},
		"region":            DefaultRegion,
		"build_root":        DefaultBuildRoot,
		"log_dir":           DefaultLogDir,
		"metadata_ttl":      "1h",
		"admin_permit_cidr": []any{"127.0.0.0/8", "::1/128"},
		// null rather than a list: the generated file has to teach the
		// tri-state, and an empty list here would ship every new install
		// trusting no proxy at all.
		"trusted_proxies": nil,
		"tls_min_version": DefaultTLSMinVersion,
		// Empty rather than a worked example: a namespace shipped in every
		// generated config is a namespace every install serves. For
		// binary_upstreams an empty map is also what keeps the un-namespaced
		// /binaries/ route serving from storage.
		"git_upstreams":    map[string]any{},
		"binary_upstreams": map[string]any{},
	}
	for k, v := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("generated config omits %q, so an operator gets no hint the knob exists", k)
			continue
		}
		if a, b := toJSON(t, got[k]), toJSON(t, v); a != b {
			t.Errorf("generated config %q = %s, want %s", k, a, b)
		}
	}
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %#v: %v", v, err)
	}
	return string(b)
}
