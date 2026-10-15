// Package idptest runs a local OIDC issuer for tests: discovery, a JWKS that
// can rotate, a device authorization endpoint, and ID tokens signed with
// whichever key is current.
package idptest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Issuer is a running test issuer. Its URL is the issuer string tokens carry.
type Issuer struct {
	URL    string
	Server *httptest.Server

	mu      sync.Mutex
	key     *rsa.PrivateKey
	kid     string
	keys    []jose.JSONWebKey
	serial  int
	jwksHit int

	// DeviceIDToken is what the token endpoint returns as id_token once a
	// device code is redeemed. Empty means no id_token in the response.
	DeviceIDToken string
}

// New starts an issuer with one signing key. It is closed when t ends.
func New(t testing.TB) *Issuer {
	t.Helper()
	is := &Issuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                is.URL,
			"jwks_uri":                              is.URL + "/jwks",
			"token_endpoint":                        is.URL + "/token",
			"authorization_endpoint":                is.URL + "/authorize",
			"device_authorization_endpoint":         is.URL + "/device",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		is.mu.Lock()
		is.jwksHit++
		set := jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey(nil), is.keys...)}
		is.mu.Unlock()
		writeJSON(w, set)
	})
	mux.HandleFunc("POST /device", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"device_code":      "dev-code",
			"user_code":        "ABCD-EFGH",
			"verification_uri": is.URL + "/activate",
			"expires_in":       300,
			"interval":         1,
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("device_code") != "dev-code" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		body := map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300}
		if is.DeviceIDToken != "" {
			body["id_token"] = is.DeviceIDToken
		}
		writeJSON(w, body)
	})
	is.Server = httptest.NewServer(mux)
	is.URL = is.Server.URL
	t.Cleanup(is.Server.Close)
	is.Rotate(false)
	return is
}

// Rotate makes a new key current. With keepOld the old public key stays in
// the JWKS, as an issuer publishes during a rollover; without it the old key
// is gone, and tokens it signed stop verifying once the key set refetches.
func (is *Issuer) Rotate(keepOld bool) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	is.serial++
	is.key, is.kid = key, fmt.Sprintf("k%d", is.serial)
	pub := jose.JSONWebKey{Key: key.Public(), KeyID: is.kid, Algorithm: "RS256", Use: "sig"}
	if keepOld {
		is.keys = append(is.keys, pub)
	} else {
		is.keys = []jose.JSONWebKey{pub}
	}
}

// JWKSFetches is how many times the JWKS has been read.
func (is *Issuer) JWKSFetches() int {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.jwksHit
}

// Token signs an ID token with the current key. iss, iat and exp default to
// this issuer, now and an hour from now unless claims sets them.
func (is *Issuer) Token(t testing.TB, claims map[string]any) string {
	t.Helper()
	c := map[string]any{
		"iss": is.URL,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		c[k] = v
	}
	is.mu.Lock()
	key, kid := is.key, is.kid
	is.mu.Unlock()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
