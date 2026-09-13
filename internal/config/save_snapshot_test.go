package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// SaveReport compared against the file as Load read it and never refreshed
// that snapshot, so changedKeys answered "what differs from startup" rather
// than "what this write changed". Every save after the first re-reported the
// same keys, and the "no changes to save" line B28 built was unreachable for
// the rest of the session once any key had moved.
func TestSaveReportOnlyNamesWhatThisWriteChanged(t *testing.T) {
	loadedFrom(t, `{"region": "us-east-1"}`+"\n")

	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	cfg.Region = "eu-west-1"
	if _, changed, sErr := cfg.SaveReport(); sErr != nil || len(changed) != 1 || changed[0] != "region" {
		t.Fatalf("first save reported %v (err %v), want [region]", changed, sErr)
	}

	// No further edit. The second save writes the same bytes and must say so.
	_, changed, err := cfg.SaveReport()
	if err != nil {
		t.Fatalf("second save: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("second save re-reported %v; nothing changed between them", changed)
	}

	// A third save after a real edit reports that edit and only that edit.
	cfg.Region = "ap-south-1"
	_, changed, err = cfg.SaveReport()
	if err != nil {
		t.Fatalf("third save: %v", err)
	}
	if len(changed) != 1 || changed[0] != "region" {
		t.Errorf("third save reported %v, want [region]", changed)
	}
}

// The file has to keep its shape across repeated saves, since the refreshed
// snapshot is what the next write re-emits byte for byte.
func TestRepeatedSavesLeaveTheFileStable(t *testing.T) {
	path := loadedFrom(t, `{
  "_comment_region": "where the bucket lives",
  "region": "us-east-1",
  "build_root": "/opt/bodega"
}
`)

	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.Region = "eu-west-1"
	if _, _, sErr := cfg.SaveReport(); sErr != nil {
		t.Fatalf("first save: %v", sErr)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if _, _, sErr := cfg.SaveReport(); sErr != nil {
		t.Fatalf("second save: %v", sErr)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("a second save with no edit rewrote the file:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	if want := `"_comment_region"`; !strings.Contains(string(second), want) {
		t.Errorf("the comment key did not survive: %s", second)
	}
}
