// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
//
// Created by jmargulis on 2026-05-28: Creating a fake OIDC provider for local
// development and testing.
//
// Usage:
//   go run ./cmd/oidctest              # listens on :9100 by default
//   go run ./cmd/oidctest -port 9101   # custom port
//
// Implements:
//   GET  /.well-known/openid-configuration
//   GET  /auth   — user-selector login page
//   POST /auth   — submit selected user, redirect with code
//   POST /token  — exchange code for access token
//   GET  /userinfo — return claims for access token
//
// Test users (each exercises a different claim-mapping path):
//   alice  — given_name + family_name + preferred_username   (clean path)
//   bob    — name only, no given_name/family_name            (name-splitting fallback)
//   carol  — no preferred_username                           (email-prefix username fallback)

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// testUser mirrors the standard OIDC userinfo claim set.
type testUser struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	EmailVerified     bool     `json:"email_verified"`
	Groups            []string `json:"groups,omitempty"`
}

// Three users, each able to trigger different paths when creating a user.
var users = map[string]testUser{
	"alice": {
		// Clean path: given_name + family_name + preferred_username all present.
		// Groups includes "system_admin" → alice gets system administrator role.
		Sub:               "user-001",
		PreferredUsername: "alice",
		Email:             "alice@testorg.local",
		Name:              "Alice Admin",
		GivenName:         "Alice",
		FamilyName:        "Admin",
		EmailVerified:     true,
		Groups:            []string{"system_admin"},
	},
	"bob": {
		// Name-splitting fallback: only the full "name" claim, no given/family.
		Sub:               "user-002",
		PreferredUsername: "bob",
		Email:             "bob@testorg.local",
		Name:              "Bob Builder",
		EmailVerified:     true,
	},
	"carol": {
		// Email-prefix username fallback: no preferred_username claim.
		Sub:           "user-003",
		Email:         "carol@testorg.local",
		Name:          "Carol Cruz",
		GivenName:     "Carol",
		FamilyName:    "Cruz",
		EmailVerified: true,
	},
}

type codeEntry struct {
	username    string
	redirectURI string
	state       string
}

var (
	mu     sync.Mutex
	codes  = map[string]codeEntry{}
	tokens = map[string]string{} // token → username
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	port := flag.String("port", "9100", "port to listen on")
	flag.Parse()

	issuer := fmt.Sprintf("http://localhost:%s", *port)

	mux := http.NewServeMux()

	// ── Discovery ──────────────────────────────────────────────────────────
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/auth",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		})
	})

	// ── Authorization ──────────────────────────────────────────────────────
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			username := r.FormValue("user")
			redirectURI := r.FormValue("redirect_uri")
			state := r.FormValue("state")

			if _, ok := users[username]; !ok {
				http.Error(w, "unknown user: "+username, http.StatusBadRequest)
				return
			}

			code := randHex(16)
			mu.Lock()
			codes[code] = codeEntry{username: username, redirectURI: redirectURI, state: state}
			mu.Unlock()

			log.Printf("auth: issued code for user=%s", username)

			redir, err := url.Parse(redirectURI)
			if err != nil {
				http.Error(w, "bad redirect_uri", http.StatusBadRequest)
				return
			}
			q := redir.Query()
			q.Set("code", code)
			q.Set("state", state)
			redir.RawQuery = q.Encode()
			http.Redirect(w, r, redir.String(), http.StatusFound)
			return
		}

		// GET — render user-selector page
		q := r.URL.Query()
		if err := loginTmpl.Execute(w, map[string]any{
			"RedirectURI": q.Get("redirect_uri"),
			"State":       q.Get("state"),
			"Users":       users,
		}); err != nil {
			log.Printf("template error: %v", err)
		}
	})

	// ── Token exchange ─────────────────────────────────────────────────────
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")

		mu.Lock()
		entry, ok := codes[code]
		if ok {
			delete(codes, code)
		}
		mu.Unlock()

		if !ok {
			log.Printf("token: unknown code %q", code)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}

		token := randHex(32)
		mu.Lock()
		tokens[token] = entry.username
		mu.Unlock()

		log.Printf("token: issued token for user=%s", entry.username)
		writeJSON(w, map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// ── Userinfo ───────────────────────────────────────────────────────────
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")

		mu.Lock()
		username, ok := tokens[token]
		mu.Unlock()

		if !ok {
			log.Printf("userinfo: unknown token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
			return
		}

		log.Printf("userinfo: serving claims for user=%s", username)
		writeJSON(w, users[username])
	})

	log.Printf("Fake OIDC server running at %s", issuer)
	log.Printf("")
	log.Printf("Test users:")
	log.Printf("  alice  — given_name + family_name + preferred_username (clean path)")
	log.Printf("  bob    — name only, no given/family (name-splitting fallback)")
	log.Printf("  carol  — no preferred_username (email-prefix username fallback)")
	log.Printf("")
	log.Printf("OIDCSettings for config.json:")
	log.Printf("  AuthEndpoint:    %s/auth", issuer)
	log.Printf("  TokenEndpoint:   %s/token", issuer)
	log.Printf("  UserAPIEndpoint: %s/userinfo", issuer)
	log.Printf("  DiscoveryEndpoint: %s/.well-known/openid-configuration", issuer)
	log.Fatal(http.ListenAndServe(":"+*port, mux))
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Fake OIDC — Select Test User</title>
  <style>
    body { font-family: sans-serif; max-width: 480px; margin: 80px auto; padding: 0 16px; }
    h2 { margin-bottom: 4px; }
    .subtitle { color: #666; margin-bottom: 32px; font-size: 14px; }
    .user-card {
      border: 1px solid #ddd; border-radius: 8px; padding: 16px 20px;
      margin-bottom: 12px; cursor: pointer;
      display: flex; align-items: center; gap: 16px;
    }
    .user-card:hover { border-color: #145DBF; background: #f0f4ff; }
    .avatar {
      width: 44px; height: 44px; border-radius: 50%;
      background: #145DBF; color: #fff;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px; font-weight: bold; flex-shrink: 0;
    }
    .user-info strong { display: block; }
    .user-info small { color: #666; font-size: 12px; }
    .badge {
      margin-left: auto; font-size: 11px; color: #888;
      border: 1px solid #ccc; border-radius: 4px; padding: 2px 6px;
    }
    form { display: contents; }
  </style>
</head>
<body>
  <h2>Fake OIDC Login</h2>
  <p class="subtitle">Select a test user to authenticate as</p>

  {{range $key, $u := .Users}}
  <form method="POST" action="/auth">
    <input type="hidden" name="user" value="{{$key}}">
    <input type="hidden" name="redirect_uri" value="{{$.RedirectURI}}">
    <input type="hidden" name="state" value="{{$.State}}">
    <button type="submit" style="all:unset;display:block;width:100%">
      <div class="user-card">
        <div class="avatar">{{slice $u.Name 0 1}}</div>
        <div class="user-info">
          <strong>{{$u.Name}}</strong>
          <small>{{$u.Email}}</small>
        </div>
        <span class="badge">{{$key}}</span>
      </div>
    </button>
  </form>
  {{end}}
</body>
</html>
`))
