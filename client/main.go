package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = "app"
	clientSecret = "e11d32d4-4bca-4b11-90e9-474d5f507245"
)

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://localhost:8085/auth/realms/demo")

	if err != nil {
		log.Fatal(err)
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8086/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := "magica"

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Query().Get("state") != state {
			http.Error(w, "State did not match.", http.StatusBadGateway)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))

		if err != nil {
			http.Error(w, "Failed to exchange token.", http.StatusBadRequest)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

		if !ok {
			http.Error(w, "No id_token.", http.StatusBadRequest)
			return
		}

		resp := struct {
			Oauth2Token *oauth2.Token
			RawIDToken  string
		}{
			oauth2Token, rawIDToken,
		}

		data, err := json.MarshalIndent(resp, "", "	")

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Write(data)
	})

	log.Fatal(http.ListenAndServe(":8086", nil))
}
