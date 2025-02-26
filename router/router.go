package router

import (
	"encoding/json"
	"github.com/rs/zerolog/hlog"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"github.com/screego/server/auth"
	"github.com/screego/server/config"
	"github.com/screego/server/ui"
	"github.com/screego/server/ws"
)

type UIConfig struct {
	AuthMode                 string `json:"authMode"`
	User                     string `json:"user"`
	LoggedIn                 bool   `json:"loggedIn"`
	Version                  string `json:"version"`
	CloseRoomWhenOwnerLeaves bool   `json:"closeRoomWhenOwnerLeaves"`
	ShowLogin                bool   `json:"showLogin"`
	ShowOauth                bool   `json:"showOauth"`
}

func Router(conf config.Config, rooms *ws.Rooms, users *auth.Users, version string) *mux.Router {
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// https://github.com/gorilla/mux/issues/416
		accessLogger(r, 404, 0, 0)
	})
	router.Use(hlog.AccessHandler(accessLogger))
	router.Use(handlers.CORS(handlers.AllowedMethods([]string{"GET", "POST"}), handlers.AllowedOriginValidator(conf.CheckOrigin)))
	router.HandleFunc("/stream", rooms.Upgrade)
	if conf.LoginModeBasicAuth() {
		router.Methods("POST").Path("/login").HandlerFunc(users.Authenticate)
	}
	router.Methods("POST").Path("/logout").HandlerFunc(users.Logout)
	if conf.LoginModeOAuth() {
		router.Methods("GET").Path("/oauth").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			users.OAuthCodeHandler(w, r, conf)
		})
		router.Methods("GET").Path("/loginoauth").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			users.OauthUrlCreateHandler(w, r, conf)
		})
	}
	router.Methods("GET").Path("/config").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, loggedIn := users.CurrentUser(r)
		_ = json.NewEncoder(w).Encode(&UIConfig{
			AuthMode:                 conf.AuthMode,
			LoggedIn:                 loggedIn,
			User:                     user,
			Version:                  version,
			CloseRoomWhenOwnerLeaves: conf.CloseRoomWhenOwnerLeaves,
			ShowLogin:                conf.LoginModeBasicAuth(),
			ShowOauth:                conf.LoginModeOAuth(),
		})
	})
	if conf.Prometheus {
		log.Info().Msg("Prometheus enabled")
		router.Methods("GET").Path("/metrics").Handler(basicAuth(promhttp.Handler(), users))
	}

	ui.Register(router)

	return router
}

func accessLogger(r *http.Request, status, size int, dur time.Duration) {
	log.Debug().
		Str("host", r.Host).
		Int("status", status).
		Int("size", size).
		Str("ip", r.RemoteAddr).
		Str("path", r.URL.Path).
		Str("duration", dur.String()).
		Msg("HTTP")
}

func basicAuth(handler http.Handler, users *auth.Users) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		user, pass, ok := r.BasicAuth()

		if !ok || !users.Validate(user, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="screego"`)
			w.WriteHeader(401)
			_, _ = w.Write([]byte("Unauthorised.\n"))
			return
		}

		handler.ServeHTTP(w, r)
	}
}
