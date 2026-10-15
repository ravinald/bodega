package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/idp"
)

// loginFlow is one sign-in, with its outputs injectable for the tests.
type loginFlow struct {
	server         string
	provider       string
	allowPlaintext bool
	credPath       string
	out            io.Writer
	httpClient     *http.Client
}

func newLoginCmd(gf *globalFlags) *cobra.Command {
	var f loginFlow
	c := &cobra.Command{
		Use:   "login --server <url>",
		Short: "Sign in through the organization's identity provider and store a short-lived token",
		Long: `Sign in to a bodega server through one of its oidc_providers with the OAuth
device authorization flow, and store the bodega token the server issues.

bodega login prints a URL and a code. Open the URL on any device, sign in, and
enter the code; bodega login then exchanges the provider's ID token at
POST /api/v1/auth/exchange for a bodega token with the scopes the server's
claim mapping grants, valid for oidc_token_ttl (15 minutes by default).

The token is written to credentials.json in the user config directory with
mode 0600, keyed by server URL. bodega pkg import --server and bodega pin use
it for that server until it expires; $BODEGA_TOKEN still wins when set.

--provider picks the provider by name when the server offers more than one.

Examples:
  bodega login --server https://bodega.example.com
  bodega login --server https://bodega.example.com --provider okta`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			f.server = cfg.ResolveServerURL(f.server)
			if f.server == "" {
				return fmt.Errorf("no server to sign in to: pass --server https://bodega.example.com, or set $%s or server_url", config.EnvServerURL)
			}
			if f.credPath, err = config.LoginCredentialsPath(); err != nil {
				return err
			}
			f.out = os.Stdout
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
			defer cancel()
			return f.run(ctx)
		},
	}
	c.Flags().StringVar(&f.server, "server", "", "bodega server URL; defaults to $BODEGA_SERVER, then server_url")
	c.Flags().StringVar(&f.provider, "provider", "", "Provider name, when the server offers more than one")
	c.Flags().BoolVar(&f.allowPlaintext, "allow-plaintext", false, "Permit an http:// server; refused by default because the token would travel in the clear")
	return c
}

func (f *loginFlow) run(ctx context.Context) error {
	client, err := NewClient(f.server, "", f.allowPlaintext)
	if err != nil {
		return err
	}
	if f.httpClient != nil {
		client.HTTP = f.httpClient
	}
	p, err := f.pickProvider(client)
	if err != nil {
		return err
	}

	oc := &oauth2.Config{
		ClientID: p.ClientID,
		Endpoint: oauth2.Endpoint{DeviceAuthURL: p.DeviceAuthURL, TokenURL: p.TokenURL},
		Scopes:   []string{"openid", "profile", "email"},
	}
	octx := context.WithValue(ctx, oauth2.HTTPClient, client.HTTP)
	da, err := oc.DeviceAuth(octx)
	if err != nil {
		return fmt.Errorf("start device sign-in with %s (%s): %w", p.Name, p.Issuer, err)
	}
	if da.VerificationURIComplete != "" {
		fmt.Fprintf(f.out, "Open %s to sign in\n(or open %s and enter code %s)\n", da.VerificationURIComplete, da.VerificationURI, da.UserCode)
	} else {
		fmt.Fprintf(f.out, "Open %s and enter code %s\n", da.VerificationURI, da.UserCode)
	}
	tok, err := oc.DeviceAccessToken(octx, da)
	if err != nil {
		return fmt.Errorf("device sign-in with %s did not complete: %w", p.Name, err)
	}
	idToken, _ := tok.Extra("id_token").(string)
	if idToken == "" {
		return fmt.Errorf("%s returned no ID token; its OAuth client must allow the openid scope", p.Issuer)
	}

	got, err := exchangeIDToken(client, idToken)
	if err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil {
		return fmt.Errorf("server answered an expiry that does not parse: %q", got.ExpiresAt)
	}
	if err := config.SaveLoginCredential(f.credPath, f.server, config.LoginCredential{
		Token: got.Token, ExpiresAt: expires, Scopes: got.Scopes, Subject: got.Subject, Issuer: got.Issuer,
	}); err != nil {
		return err
	}
	fmt.Fprintf(f.out, "Signed in to %s as %s (%s).\n  Scopes:  %s\n  Expires: %s\n  Stored:  %s\n",
		f.server, got.Subject, got.Issuer, got.Scopes, expires.Local().Format(time.RFC1123), f.credPath)
	return nil
}

// pickProvider fetches the providers the server offers a device flow for and
// chooses one: the one --provider names, or the only one.
func (f *loginFlow) pickProvider(c *Client) (idp.ProviderInfo, error) {
	var providers []idp.ProviderInfo
	if err := getJSON(c, "/api/v1/auth/providers", &providers); err != nil {
		return idp.ProviderInfo{}, fmt.Errorf("list sign-in providers: %w", err)
	}
	if len(providers) == 0 {
		return idp.ProviderInfo{}, fmt.Errorf("%s offers no device sign-in: none of its oidc_providers has a client_id and a reachable issuer with a device authorization endpoint", f.server)
	}
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.Name
		if f.provider != "" && p.Name == f.provider {
			return p, nil
		}
	}
	if f.provider != "" {
		return idp.ProviderInfo{}, fmt.Errorf("--provider %q is not offered by %s; it offers %s", f.provider, f.server, strings.Join(names, ", "))
	}
	if len(providers) > 1 {
		return idp.ProviderInfo{}, fmt.Errorf("%s offers several providers; pick one with --provider (%s)", f.server, strings.Join(names, ", "))
	}
	return providers[0], nil
}

// exchangeResult is the body POST /api/v1/auth/exchange answers with.
type exchangeResult struct {
	Token     string `json:"token"`
	ID        string `json:"id"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
}

func exchangeIDToken(c *Client, idToken string) (exchangeResult, error) {
	body, _ := json.Marshal(map[string]string{"id_token": idToken})
	resp, err := c.HTTP.Post(c.BaseURL+"/api/v1/auth/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		return exchangeResult{}, fmt.Errorf("exchange the ID token at %s: %w", c.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return exchangeResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return exchangeResult{}, fmt.Errorf("%s refused the sign-in: %s\n%s", c.BaseURL, resp.Status, serverError(payload))
	}
	var out exchangeResult
	if err := json.Unmarshal(payload, &out); err != nil || out.Token == "" {
		return exchangeResult{}, fmt.Errorf("exchange answered a body with no token")
	}
	return out, nil
}
