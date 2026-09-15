// Copyright 2026
// SPDX-License-Identifier: MPL-2.0

// This test-only server implements only the two Vault API responses needed by
// the offline Agent auto-auth/template exercise. It is never copied into the
// hardened runtime image.
package main

import (
	"encoding/json"
	"net/http"
	"os"
)

type tokenReview struct {
	Spec struct {
		Token string `json:"token"`
	} `json:"spec"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
			"client_token": "synthetic-client-token", "lease_duration": 300, "renewable": false,
		}})
	})
	mux.HandleFunc("/v1/kv/data/synthetic", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != "synthetic-client-token" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"data": map[string]any{"value": "rendered-ok"},
		}})
	})
	mux.HandleFunc("/apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		var review tokenReview
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer synthetic-reviewer-token" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		expected := os.Getenv("SYNTHETIC_SERVICE_ACCOUNT_JWT")
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil || expected == "" || review.Spec.Token != expected {
			http.Error(w, "invalid token review", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "authentication.k8s.io/v1",
			"kind":       "TokenReview",
			"status": map[string]any{
				"authenticated": true,
				"audiences": []string{"vault"},
				"user": map[string]any{
					"username": "system:serviceaccount:hoodi:validator",
					"uid":      "synthetic-service-account-uid",
					"groups": []string{
						"system:serviceaccounts",
						"system:serviceaccounts:hoodi",
						"system:authenticated",
					},
				},
			},
		})
	})
	server := &http.Server{Addr: ":8200", Handler: mux, ReadHeaderTimeout: 2e9}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic("mock Vault server failed")
	}
}
