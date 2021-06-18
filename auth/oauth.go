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
	"strings"
	"time"
)

type oAuth struct {
	Email string
	Name  string
	*oauth2.Token
}

var (
	oauth2Config = oauth2.Config{}
	provider     *oidc.Provider
	states       []oAuthState
)

type oAuthState struct {
	time  time.Time
	state string
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func exchangeTokenOAuth(r *http.Request, conf config.Config) (*oAuth, error) {
	code := r.URL.Query().Get("code")

	oauth2Token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Error().Err(err).Msg("No OAuth2 Token Exchange")
		return nil, err
	}

	if !oauth2Token.Valid() {
		return nil, errors.New("oauth token is not valid")
	}

	client := http.DefaultClient

	req, err := http.NewRequest("GET", conf.UserApiUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "token "+oauth2Token.AccessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error().Err(err).Msg("Unable to read response body: ")
		}
	}(resp.Body)

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
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	err = json.Unmarshal(body, &data)

	if err != nil {
		log.Error().Err(err).Msg("User data not readable from API")
		return nil, err
	}

	log.Debug().Msg("Email: " + data.Email + " Name: " + data.Name)

	return &oAuth{
		Token: oauth2Token,
		Email: data.Email,
		Name:  data.Name,
	}, nil
}

func exchangeTokenOpenID(r *http.Request, conf config.Config) (*oAuth, error) {
	code := r.URL.Query().Get("code")

	if nil == provider {
		log.Error().Msg("OpenID provider is not set")
		return nil, errors.New("OpenID provider is not set")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: conf.OAuthClientId})

	oauth2Token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Error().Msg("No OAuth2 Token Exchange")
		return nil, err
	}

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

	var claims struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Error().Msg("OpenID Claims not possible")
		return nil, err
	}

	log.Debug().Msg("Email: " + claims.Email + " Name: " + claims.Name)

	return &oAuth{
		Token: oauth2Token,
		Email: claims.Email,
		Name:  claims.Name,
	}, nil
}

func (u *Users) OauthUrlCreateHandler(w http.ResponseWriter, r *http.Request, conf config.Config) {

	// create "oauth2Config" for OpenID Connect or only OAuth2
	if conf.UseOpenId {
		var err error
		provider, err = oidc.NewProvider(r.Context(), conf.OpenIdProviderUrl)
		if err != nil {
			log.Error().Err(err).Msg("OpenID provider is not working")
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(&Response{
				Message: err.Error(),
			})
			return
		}

		oauth2Config = oauth2.Config{
			ClientID:     conf.OAuthClientId,
			ClientSecret: conf.OAuthClientSecret,
			RedirectURL:  conf.OAuthRedirectUrl + "/oauth",

			// Discovery returns the OAuth2 endpoints
			Endpoint: provider.Endpoint(),

			// "openid" is a required scope for OpenID Connect flows
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		}
	} else {
		oauth2Config = oauth2.Config{
			ClientID:     conf.OAuthClientId,
			ClientSecret: conf.OAuthClientSecret,
			RedirectURL:  conf.OAuthRedirectUrl + "/oauth",

			// OAuth2 endpoints from config.
			Endpoint: oauth2.Endpoint{
				AuthURL:  conf.OAuthAuthorizeUrl,
				TokenURL: conf.OAuthTokenUrl,
			},

			// no "openid": service is not expected to be capable of OpenID Connect flows
			Scopes: []string{"profile", "email"},
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
	states = append(states, oAuthState{state: state, time: time.Now()})
}

func (u *Users) OAuthCodeHandler(w http.ResponseWriter, r *http.Request, conf config.Config) {

	if !ValidateOAuthState(r.URL.Query().Get("state"), states) {
		log.Error().Msg("State mismatch response rejected")
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: "response rejected (maybe you took too long to login?)",
		})
		return
	}

	var (
		err   error
		oauth *oAuth
	)
	if conf.UseOpenId {
		oauth, err = exchangeTokenOpenID(r, conf)
	} else {
		oauth, err = exchangeTokenOAuth(r, conf)
	}

	if err != nil {
		log.Error().Err(err)
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: err.Error(),
		})
		return
	}

	// Check if email is on the possible whitelist
	if len(conf.EmailWhitelist) > 0 {
		if !ValidateWhitelist(oauth.Email, conf.EmailWhitelist) {
			log.Info().Msg(fmt.Sprintf("OAuth User: %s(%s) is not whitelisted but tried to login", oauth.Name, oauth.Email))
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(&Response{
				Message: "You are not allowed to login",
			})
			return
		}
	}

	// Log user access
	log.Info().Msg(fmt.Sprintf("OAuth Login: %s(%s)", oauth.Name, oauth.Email))

	// Save user to the cookies - user save is the same aus Basic auth
	u.SaveUser(w, r, oauth.Name)
	
	http.Redirect(w, r, conf.OAuthRedirectUrl, http.StatusPermanentRedirect)

	//w.WriteHeader(200)
	//_ = json.NewEncoder(w).Encode(&Response{
	//	Message: "authenticated",
	//})
}

// ValidateWhitelist checks if the email is whitelisted.
// Two cases are possible the exact email is present or
// a address starts with *@domain.td every @domain.td is accepted
func ValidateWhitelist(email string, whitelist []string) bool {
	for _, whitelist := range whitelist {
		if strings.HasPrefix(whitelist, "*") {
			if strings.HasSuffix(email, strings.Split(whitelist, "*")[1]) {
				return true
			}
		}
		if email == whitelist {
			return true
		}
	}
	return false
}

func ValidateOAuthState(state string, states []oAuthState) bool {
	for _, authState := range states {
		if authState.state == state {
			RemoveOldOAuthStates(state)
			return true
		}
	}
	RemoveOldOAuthStates(state)
	return false
}

func RemoveOldOAuthStates(state string) {
	var newStates []oAuthState
	for _, authState := range states {
		if time.Since(authState.time) < time.Minute*20 && authState.state != state {
			newStates = append(newStates, authState)
		}
	}
	states = newStates
}
