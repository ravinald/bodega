package builder

import (
	"context"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

type staticStore struct{ rules map[string][]policy.Rule }

func (s staticStore) GetPoliciesByType(_ context.Context, t string) ([]policy.Rule, error) {
	return s.rules[t], nil
}

func TestEnforcePolicyAllowsWhenNoChecker(t *testing.T) {
	c := &Config{}
	if err := c.EnforcePolicy(context.Background(), manifest.TypePypi, "django", "4.2", ""); err != nil {
		t.Errorf("nil checker should pass: %v", err)
	}
}

func TestEnforcePolicyAllowsWhenMatch(t *testing.T) {
	store := staticStore{rules: map[string][]policy.Rule{
		manifest.TypePypi: {audit.PolicyInfo{RegistryType: manifest.TypePypi, RuleKind: policy.KindPackage, Pattern: "django"}},
	}}
	c := &Config{Policy: policy.NewChecker(store)}
	if err := c.EnforcePolicy(context.Background(), manifest.TypePypi, "django", "4.2", ""); err != nil {
		t.Errorf("django should match: %v", err)
	}
}

func TestEnforcePolicyBlocksWhenNoMatch(t *testing.T) {
	store := staticStore{rules: map[string][]policy.Rule{
		manifest.TypePypi: {audit.PolicyInfo{RegistryType: manifest.TypePypi, RuleKind: policy.KindPackage, Pattern: "django"}},
	}}
	c := &Config{Policy: policy.NewChecker(store)}
	err := c.EnforcePolicy(context.Background(), manifest.TypePypi, "requests", "2.31", "")
	if !policy.IsViolation(err) {
		t.Fatalf("requests should be blocked, got %v", err)
	}
}
