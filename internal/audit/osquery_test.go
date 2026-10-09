package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// The order serveEnroll permits: the secret is looked up, a revoke commits,
// then the node is recorded under the id the lookup returned. The node must
// not land, or it outlives every revoke that could remove it.
func TestEnrollAfterRevokeWritesNothing(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	if err := db.InsertOsquerySecret(ctx, OsquerySecret{ID: "s1", Source: "osq", Identity: "web-01"}, "h1"); err != nil {
		t.Fatalf("insert secret: %v", err)
	}
	sec, err := db.OsquerySecretByHash(ctx, "osq", "h1")
	if err != nil {
		t.Fatalf("look up secret: %v", err)
	}
	if _, _, err := db.RevokeOsquerySecret(ctx, "s1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	err = db.EnrollOsqueryNode(ctx, OsqueryNode{Source: "osq", KeySHA256: "k", SecretID: sec.ID, Identity: sec.Identity})
	if !errors.Is(err, ErrNoOsquerySecret) {
		t.Fatalf("enroll after revoke: err = %v, want ErrNoOsquerySecret", err)
	}
	if _, found, err := db.OsqueryNodeByKey(ctx, "osq", "k"); err != nil || found {
		t.Errorf("node after refused enroll: found = %v, err = %v; want none", found, err)
	}
	if id, err := db.InventoryHostIdentity(ctx, "osq", "k"); err != nil || id != "" {
		t.Errorf("host mapping after refused enroll = %q, %v; want none", id, err)
	}
}

// A node is recorded only under the source and identity its secret holds.
func TestEnrollRefusesMismatchedSecret(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	if err := db.InsertOsquerySecret(ctx, OsquerySecret{ID: "s1", Source: "osq", Identity: "web-01"}, "h1"); err != nil {
		t.Fatalf("insert secret: %v", err)
	}
	for name, n := range map[string]OsqueryNode{
		"other source":   {Source: "osq-b", KeySHA256: "k1", SecretID: "s1", Identity: "web-01"},
		"other identity": {Source: "osq", KeySHA256: "k2", SecretID: "s1", Identity: "web-02"},
		"unknown secret": {Source: "osq", KeySHA256: "k3", SecretID: "s9", Identity: "web-01"},
	} {
		if err := db.EnrollOsqueryNode(ctx, n); !errors.Is(err, ErrNoOsquerySecret) {
			t.Errorf("%s: err = %v, want ErrNoOsquerySecret", name, err)
		}
		if id, _ := db.InventoryHostIdentity(ctx, n.Source, n.KeySHA256); id != "" {
			t.Errorf("%s: host mapped to %q, want none", name, id)
		}
	}
	if err := db.EnrollOsqueryNode(ctx, OsqueryNode{Source: "osq", KeySHA256: "k4", SecretID: "s1", Identity: "web-01"}); err != nil {
		t.Fatalf("matching enroll: %v", err)
	}
	if id, _ := db.InventoryHostIdentity(ctx, "osq", "k4"); id != "web-01" {
		t.Errorf("host mapped to %q, want web-01", id)
	}
}

// Enrolls racing a revoke either land before it, and go with it, or are
// refused: no node survives naming the revoked secret.
func TestRevokeRacingEnrollsLeavesNoNode(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	if err := db.InsertOsquerySecret(ctx, OsquerySecret{ID: "s1", Source: "osq", Identity: "web-01"}, "h1"); err != nil {
		t.Fatalf("insert secret: %v", err)
	}
	const enrolls = 40
	var wg sync.WaitGroup
	errs := make(chan error, enrolls)
	start := make(chan struct{})
	for i := range enrolls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := db.EnrollOsqueryNode(ctx, OsqueryNode{Source: "osq", KeySHA256: fmt.Sprintf("k%d", i), SecretID: "s1", Identity: "web-01"})
			if err != nil && !errors.Is(err, ErrNoOsquerySecret) {
				errs <- err
			}
		}()
	}
	close(start)
	if _, _, err := db.RevokeOsquerySecret(ctx, "s1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("enroll: %v", err)
	}
	for i := range enrolls {
		if n, found, err := db.OsqueryNodeByKey(ctx, "osq", fmt.Sprintf("k%d", i)); err != nil || found {
			t.Errorf("k%d after revoke: found = %v (secret %q), err = %v", i, found, n.SecretID, err)
		}
	}
}
