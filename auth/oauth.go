package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"github.com/screego/server/config"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
)

type oAuth struct {
	Email    string
	Username string
	Name     string
	*oauth2.Token
}

var (
	oauth2Config = oauth2.Config{}
	provider *oidc.Provider
)

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func exchangeTokenOAuth(r *http.Request, conf config.Config) (*oAuth, error) {
	code := r.URL.Query().Get("code")
	log.Info().Msg("Code: "+code)

	log.Info().Msg("Config: "+  oauth2Config.RedirectURL)

	oauth2Token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Error().Err(err).Msg("No OAuth2 Token Exchange")
		return nil, err
	}
	log.Info().Msg("Token: "+oauth2Token.AccessToken)

	if !oauth2Token.Valid() {
		return nil, errors.New("oauth token is not valid")
	}

	client := http.DefaultClient

	req, err := http.NewRequest("GET", conf.UserApiUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "token " + oauth2Token.AccessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Unable to read response body: ")
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Error().Msgf("%s: %s", resp.Status, body)
		return nil, errors.New(resp.Status)
	}
	var data struct {
		Username string `json:"preferred_username" json:"username" json:"login"`
		Name 	 string `json:"name"`
		Email    string `json:"email"`
	}

	err = json.Unmarshal(body, &data)

	if err != nil {
		log.Error().Err(err).Msg("User data not readable from API")
		return nil, err
	}

	log.Info().Msg("Email: " + data.Email + " Username: " + data.Username + " Name: " + data.Name)

	return &oAuth{
		Token:    oauth2Token,
		Username: data.Username,
		Email: data.Email,
		Name: data.Name,
	}, nil
}

func exchangeTokenOpenID(r *http.Request, conf config.Config) (*oAuth, error) {
	code := r.URL.Query().Get("code")
	log.Info().Msg("Code: "+code)

	log.Info().Msg("Provider: " + provider.Endpoint().AuthURL)

	if &provider == nil {
		log.Error().Msg("OpenID provider is not set")
		return nil, errors.New("OpenID provider is not set")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: conf.OAuthClientId})

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
		log.Error().Err(err).Msg("No OAuth2 Token ID is not verified")
		return nil, err
	}

	log.Info().Msg("RawIDToken: " + rawIDToken)

	var claims struct {
		Username string `json:"preferred_username"`
		Name 	 string `json:"name"`
		Email    string `json:"email"`
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


func (u *Users) OauthLoginHandler(w http.ResponseWriter, r *http.Request, conf config.Config) {

	if conf.UseOpenId {
		var err error
		provider, err = oidc.NewProvider(r.Context(), conf.OpenIdProviderUrl)
		if err != nil {
			log.Error().Msg("OpenID provider is not working")
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(&Response{
				Message: err.Error(),
			})
			return
		}

		oauth2Config = oauth2.Config{
			ClientID:     conf.OAuthClientId,
			ClientSecret: conf.OAuthClientSecret,
			RedirectURL:  conf.OAuthRedirectUrl,

			// Discovery returns the OAuth2 endpoints.
			Endpoint: provider.Endpoint(),

			// "openid" is a required scope for OpenID Connect flows.
			Scopes: []string{oidc.ScopeOpenID, "profile", "email", "address"},
		}
	}else{
		oauth2Config = oauth2.Config{
			ClientID:     conf.OAuthClientId,
			ClientSecret: conf.OAuthClientSecret,
			RedirectURL:  conf.OAuthRedirectUrl,

			// Discovery returns the OAuth2 endpoints.
			Endpoint: oauth2.Endpoint{
				AuthURL:  conf.OAuthAuthorizeUrl,
				TokenURL: conf.OAuthTokenUrl,
			},

			// "openid" is a required scope for OpenID Connect flows.
			Scopes: []string{"profile", "email", "address"},
		}
	}

	state, err := randString(16)
	if err != nil {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: err.Error(),
		})
		return
	}
	log.Info().Msg("Response now")
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(&Response{
		Message: oauth2Config.AuthCodeURL(state),
	})
	return
}

func (u *Users) OauthHandler(w http.ResponseWriter, r *http.Request, conf config.Config) {
	log.Info().Msg("Fine +1")
	var err error
	var oauth *oAuth
	if conf.UseOpenId {
		oauth, err = exchangeTokenOpenID(r, conf)
	}else{
		oauth, err = exchangeTokenOAuth(r, conf)
	}

	if err != nil {
		log.Fatal().Err(err)
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: err.Error(),
		})
		return
	}

	log.Info().Msg(fmt.Sprintf("OAuth type: %s User: %s", oauth.Type(), oauth.Name))

	u.SaveUser(w, r, oauth.Name)

	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(&Response{
		Message: "authenticated",
	})
}
