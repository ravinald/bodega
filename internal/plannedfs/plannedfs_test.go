package plannedfs

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPlannedTreeOverlaysTheDisk(t *testing.T) {
	root := t.TempDir()
	disk := filepath.Join(root, "etc", "app.conf")
	if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disk, []byte("on disk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaced := disk
	created := filepath.Join(root, "etc", "new.d", "bodega.conf")

	err := With(map[string][]byte{replaced: []byte("planned\n"), created: []byte("new\n")}, func() error {
		if got, err := ReadFile(replaced); err != nil || string(got) != "planned\n" {
			t.Errorf("ReadFile(replaced) = %q, %v; want the planned content", got, err)
		}
		if got, err := ReadFile(created); err != nil || string(got) != "new\n" {
			t.Errorf("ReadFile(created) = %q, %v", got, err)
		}
		if info, err := Stat(filepath.Dir(created)); err != nil || !info.IsDir() {
			t.Errorf("Stat of a directory only the plan creates = %v, %v; want a directory", info, err)
		}
		entries, err := ReadDir(filepath.Join(root, "etc"))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, []string{"app.conf", "new.d"}) {
			t.Errorf("ReadDir = %v, want app.conf and new.d", names)
		}
		if m, err := Glob(filepath.Join(root, "etc", "*", "*.conf")); err != nil || !slices.Equal(m, []string{created}) {
			t.Errorf("Glob = %v, %v; want the planned file", m, err)
		}
		if m, err := Glob(filepath.Join(root, "etc", "*")); err != nil || !slices.Equal(m, []string{disk, filepath.Dir(created)}) {
			t.Errorf("Glob over directories = %v, %v; want the disk file and the planned directory", m, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, err := ReadFile(replaced); err != nil || string(got) != "on disk\n" {
		t.Errorf("after With, ReadFile = %q, %v; want the disk again", got, err)
	}
	if _, err := Stat(created); !os.IsNotExist(err) {
		t.Errorf("after With, the planned file still reads as present: %v", err)
	}
}
