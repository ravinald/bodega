package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// groupFixture seeds one package per case the listing has to tell apart.
func groupFixture(t *testing.T) (*config.Config, *manifest.Store) {
	t.Helper()
	cfg := &config.Config{
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: t.TempDir()},
			"cold": {Driver: "local", Path: t.TempDir()},
		},
		StorageByGroup: map[string]string{"mirror-set": "bulk", "alpha": "cold"},
	}

	store := manifest.NewLocalStore(t.TempDir())
	seed := []struct {
		typ, name string
		groups    []string
		policy    string
	}{
		{manifest.TypeBinary, "example-tool-v2", []string{"mirror-set"}, ""},
		{manifest.TypeBinary, "kubectl", []string{"mirror-set"}, "cold"},
		{manifest.TypePypi, "examplesdk", []string{"mirror-set"}, ""},
		{manifest.TypeNpm, "left-pad", []string{"mirror-set", "alpha"}, ""},
		{manifest.TypeNpm, "lodash", nil, ""},
	}
	for _, s := range seed {
		if err := store.AddVersion(t.Context(), s.typ, s.name, manifest.VersionEntry{Version: "1.0.0"}); err != nil {
			t.Fatalf("AddVersion %s/%s: %v", s.typ, s.name, err)
		}
		pm, err := store.GetPackage(t.Context(), s.typ, s.name)
		if err != nil || pm == nil {
			t.Fatalf("GetPackage %s/%s: %v", s.typ, s.name, err)
		}
		pm.StorageGroups = s.groups
		pm.StoragePolicy = s.policy
		if err := store.SavePackage(t.Context(), pm); err != nil {
			t.Fatalf("SavePackage %s/%s: %v", s.typ, s.name, err)
		}
	}
	return cfg, store
}

// TestGroupMembersSeparateMembershipFromPlacement is the reason the listing
// carries a second column. Naming forty packages as held by a group that
// places thirty-eight of them is the report an operator acts on and then finds
// two packages somewhere else.
func TestGroupMembersSeparateMembershipFromPlacement(t *testing.T) {
	cfg, store := groupFixture(t)

	members, err := groupMembers(t.Context(), cfg, store, "mirror-set")
	if err != nil {
		t.Fatalf("groupMembers: %v", err)
	}
	got := map[string]groupMember{}
	for _, m := range members {
		got[m.Type+"/"+m.Package] = m
	}
	if len(got) != 4 {
		t.Fatalf("members = %+v, want the four packages naming the group", members)
	}

	if m := got["binary/example-tool-v2"]; !m.Deciding {
		t.Errorf("binary/example-tool-v2 deciding = false (%s), want the group to place it", m.Why)
	}
	// A storage_policy is the one level above the group, so it wins.
	if m := got["binary/kubectl"]; m.Deciding || !strings.Contains(m.Why, "storage_policy") {
		t.Errorf("binary/kubectl = %+v, want the package policy named as outranking the group", m)
	}
	// pypi never reaches the group level at all.
	if m := got["pypi/examplesdk"]; m.Deciding || !strings.Contains(m.Why, "pypi") {
		t.Errorf("pypi/examplesdk = %+v, want the group reported as not consulted", m)
	}
	// Two groups: the first by name decides, and the other says which won.
	if m := got["npm/left-pad"]; m.Deciding || !strings.Contains(m.Why, "alpha") {
		t.Errorf("npm/left-pad = %+v, want the group that wins by name", m)
	}

	alpha, err := groupMembers(t.Context(), cfg, store, "alpha")
	if err != nil {
		t.Fatalf("groupMembers(alpha): %v", err)
	}
	if len(alpha) != 1 || !alpha[0].Deciding {
		t.Errorf("alpha members = %+v, want npm/left-pad placed by it", alpha)
	}
}

// TestPrintGroupsCountsWhatItPlaces guards the summary against the same
// confusion: a group is listed with what it holds and what it decides, not one
// number standing for both.
func TestPrintGroupsCountsWhatItPlaces(t *testing.T) {
	cfg, store := groupFixture(t)

	var out bytes.Buffer
	if err := printGroups(t.Context(), &out, cfg, store); err != nil {
		t.Fatalf("printGroups: %v", err)
	}
	lines := strings.Split(out.String(), "\n")
	var row string
	for _, l := range lines {
		if strings.HasPrefix(l, "mirror-set") {
			row = l
		}
	}
	if row == "" {
		t.Fatalf("no mirror-set row in:\n%s", out.String())
	}
	fields := strings.Fields(row)
	if len(fields) != 4 || fields[1] != "bulk" || fields[2] != "4" || fields[3] != "1" {
		t.Errorf("mirror-set row = %q, want bulk holding 4 and deciding 1", row)
	}

	var empty bytes.Buffer
	if err := printGroups(t.Context(), &empty, &config.Config{}, store); err != nil {
		t.Fatalf("printGroups (no groups): %v", err)
	}
	if !strings.Contains(empty.String(), "storage_by_group is empty") {
		t.Errorf("output = %q, want it to name the key an operator would set", empty.String())
	}
}
