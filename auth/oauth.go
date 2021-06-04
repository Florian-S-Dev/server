package auth

import (
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"net/http"
)

type oAuth struct {
	Email    string
	Username string
	*oauth2.Token
}

func exchangeOAuth(r *http.Request) (*oAuth, error) {
	code := r.URL.Query().Get("code")
	log.Info().Msg("Code: "+code)

	config := &oauth2.Config{
		ClientID:     "screego_dev",
		ClientSecret: "2b135b90-5712-4d05-bd7c-bec0517e3c43",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://keycloak.brickfire.eu/auth/realms/develop/protocol/openid-connect/auth",
			TokenURL: "https://keycloak.brickfire.eu/auth/realms/develop/protocol/openid-connect/token",
		},
		RedirectURL: "http://localhost:5050/oauth",
	}
	log.Info().Msg("Config: "+config.RedirectURL)

	token, err := config.Exchange(r.Context(), code)
	if err != nil {
		log.Info().Msg("No token")
		return nil, err
	}
	log.Info().Msg("Token: "+token.AccessToken)

	if !token.Valid() {
		return nil, errors.New("oauth token is not valid")
	}

	return &oAuth{
		Token:    token,
		Username: token.Extra("preferred_username").(string),
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

	oauthLogin(oauth, w, r)
}

func oauthLogin(oauth *oAuth, w http.ResponseWriter, r *http.Request) {

	log.Info().Msg(fmt.Sprintf("OAuth %s User %s logged in from IP %s", oauth.Type(), oauth.Username, r.RemoteAddr))
	//setJwtToken(user, w) todo SAVE USER
	http.Redirect(w, r, "http://localhost:3000/", http.StatusPermanentRedirect)
}
