// Package oidc adapts the backend's OIDCLogin gRPC surface onto the login
// package's Authorizer port. It carries the authorization code and PKCE values
// to Identity&Access and maps the verified principal back. Nothing here
// verifies, decrypts, or maps claims: that stays behind the contract boundary
// (ADR-0045).
package oidc

import (
	"context"

	identityv1 "github.com/gitfrok/bff/gen/proto/identity/v1"
)

// Authorizer exchanges codes through Identity&Access.
type Authorizer struct {
	client identityv1.OIDCLoginClient
}

// New wires the adapter onto the generated client.
func New(client identityv1.OIDCLoginClient) *Authorizer {
	return &Authorizer{client: client}
}

// ExchangeCode forwards the browser-produced artifacts and returns the
// tenant-scoped principal. An empty response is the one coarse denial shape.
func (a *Authorizer) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, nonce string) (*identityv1.Principal, error) {
	response, err := a.client.ExchangeCode(ctx, &identityv1.ExchangeCodeRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectUri:  redirectURI,
		Nonce:        nonce,
	})
	if err != nil {
		return nil, err
	}
	return response.GetPrincipal(), nil
}
