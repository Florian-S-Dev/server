package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

type oAuth struct {
	Email    string
	Username string
	Name     string
	*oauth2.Token
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func exchangeOAuth(r *http.Request) (*oAuth, error) {
	code := r.URL.Query().Get("code")
	log.Info().Msg("Code: "+code)

	provider, err := oidc.NewProvider(r.Context(), "https://keycloak.brickfire.eu/auth/realms/develop")
	if err != nil {
		log.Error().Msg("OpenID provider is not working")
		return nil, err
	}
	oauth2Config := oauth2.Config{
		ClientID:     "screego_dev",
		ClientSecret: "2b135b90-5712-4d05-bd7c-bec0517e3c43",
		RedirectURL:  "http://localhost:3000/oauth",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "address"},
	}
	state, err := randString(16)

	log.Info().Msg(oauth2Config.AuthCodeURL(state))

	verifier := provider.Verifier(&oidc.Config{ClientID: "screego_dev"})

	log.Info().Msg("Config: "+  oauth2Config.RedirectURL)

	oauth2Token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Error().Msg("No OAuth2 Token Exchange")
		return nil, err
	}
	log.Info().Msg("Token: "+oauth2Token.AccessToken)

	if !oauth2Token.Valid() {
		return nil, errors.New("oauth token is not valid")
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Error().Msg("No OAuth2 Token ID readable")
		return nil, errors.New("oauth token has no id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Error().Msg("No OAuth2 Token ID is not verified")
		return nil, err
	}

	log.Info().Msg("RawIDToken: " + rawIDToken)

	var claims struct {
		Username string `json:"preferred_username"`
		Name 	 string `json:"name"`
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Error().Msg("OpenID Claims not possible")
		return nil, err
	}

	log.Info().Msg("Email: " + claims.Email + " Username: " + claims.Username + " Name: " + claims.Name)


	return &oAuth{
		Token:    oauth2Token,
		Username: claims.Username,
		Email: claims.Email,
		Name: claims.Name,
	}, nil
}

func (u *Users) OauthHandler(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("Fine +1")
	var err error
	var oauth *oAuth

	oauth, err = exchangeOAuth(r)

	if err != nil {
		log.Fatal().Err(err)
		return
	}

	log.Info().Msg(fmt.Sprintf("OAuth %s User %s logged in from IP %s", oauth.Type(), oauth.Username, r.RemoteAddr))

	u.SaveUser(w, r, oauth.Username)

	http.Redirect(w, r, "http://localhost:3000/", http.StatusPermanentRedirect)
}
