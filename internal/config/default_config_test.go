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
		"region":            DefaultRegion,
		"build_root":        DefaultBuildRoot,
		"log_dir":           DefaultLogDir,
		"metadata_ttl":      "1h",
		"admin_permit_cidr": []any{"127.0.0.0/8", "::1/128"},
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
