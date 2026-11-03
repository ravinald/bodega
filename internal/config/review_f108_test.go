package config_test

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

func TestReviewMalformedSumdbKeyNamesRelay(t *testing.T) {
	writeConfig(t, `{"gomod_sumdb_key":"sum.golang.org+nothex+AAAA"}`)
	_, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err == nil {
		t.Fatal("malformed key accepted")
	}
	if !strings.Contains(err.Error(), "relay") || !strings.Contains(err.Error(), "serves only sum.golang.org") {
		t.Fatalf("malformed-key error omits relay restriction: %v", err)
	}
}
