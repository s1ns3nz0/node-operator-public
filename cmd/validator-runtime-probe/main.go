// Temporary read-only diagnostics. No signing endpoint or secret writes exist.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
)

func main() {
	mode := flag.String("mode", "tls", "tls, vault-read, or engine-auth")
	set := flag.String("validator-set", "", "fixed validator set")
	key := flag.String("expected-public-key", "", "public validator key")
	scenario := flag.String("tls-case", "positive", "positive, bad-ca, no-client, untrusted-client")
	engineCase := flag.String("engine-case", "positive", "positive, missing, wrong")
	role := flag.String("workload", "", "nethermind, prysm, signer, client, db")
	flag.Parse()
	if flag.NArg() != 0 || !regexp.MustCompile(`^hoodi-[a-z0-9][a-z0-9-]{0,20}$`).MatchString(*set) {
		fmt.Fprintln(os.Stderr, "invalid probe identity")
		os.Exit(64)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var result map[string]any
	var err error
	switch *mode {
	case "tls":
		result, err = runTLSProbe(ctx, *set, *key, *scenario)
	case "vault-read":
		result, err = runVaultReadProbe(ctx, *set, *role)
	case "engine-auth":
		result, err = runEngineProbe(ctx, *set, *engineCase)
	case "engine-network-deny":
		result, err = runEngineNetworkDeny(ctx)
	default:
		err = errors.New("unsupported mode")
	}
	if result != nil && json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe failed:", err)
		os.Exit(1)
	}
}

type vaultProfile struct {
	role    string
	allowed map[string]bool
}

func profile(set, workload string) (vaultProfile, error) {
	p := vaultProfile{allowed: map[string]bool{}}
	switch workload {
	case "nethermind":
		p.role = "hoodi-engine-nethermind"
		p.allowed["engine-api-jwt"] = true
	case "prysm":
		p.role = "hoodi-engine-prysm"
		p.allowed["engine-api-jwt"] = true
	case "client":
		p.role = "hoodi-" + set + "-client-tls"
		p.allowed["client-tls"] = true
	case "db":
		p.role = "hoodi-" + set + "-slashing-db"
		p.allowed["slashing-db-password"] = true
	case "signer":
		p.role = "hoodi-" + set + "-runtime"
		for _, k := range []string{"keystore", "password", "slashing-db-password", "signer-tls"} {
			p.allowed[k] = true
		}
	default:
		return p, errors.New("unsupported workload")
	}
	return p, nil
}

func runVaultReadProbe(ctx context.Context, set, workload string) (map[string]any, error) {
	ca, err := os.ReadFile("/vault/tls/ca.crt")
	if err != nil {
		return nil, errors.New("Vault CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("Vault CA invalid")
	}
	jwt, err := os.ReadFile("/var/run/secrets/vault.hashicorp.com/serviceaccount/token")
	if err != nil || len(jwt) > 65536 {
		return nil, errors.New("projected identity unavailable")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "vault.vault.svc"}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	request := func(method, path, token string, body []byte) (*http.Response, error) {
		req, e := http.NewRequestWithContext(ctx, method, "https://vault.vault.svc:8200/v1/"+path, bytes.NewReader(body))
		if e != nil {
			return nil, errors.New("invalid fixed Vault request")
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}
		response, e := client.Do(req)
		if e != nil {
			return nil, errors.New("Vault request unavailable")
		}
		return response, nil
	}
	return checkVaultReadBoundary(set, workload, jwt, request)
}

type vaultRequest func(method, path, token string, body []byte) (*http.Response, error)

func checkVaultReadBoundary(set, workload string, jwt []byte, request vaultRequest) (result map[string]any, probeErr error) {
	p, err := profile(set, workload)
	if err != nil {
		return nil, err
	}
	result = map[string]any{"result": "FAIL", "workload": workload, "role": p.role, "secret_bodies_retained": false, "token_cleanup": "authentication_not_attempted"}
	payload, _ := json.Marshal(map[string]string{"role": p.role, "jwt": string(jwt)})
	result["token_cleanup"] = "authentication_attempted; issuance_unknown_if_response_lost"
	auth, err := request("POST", "auth/kubernetes/login", "", payload)
	if err != nil {
		return result, errors.New("workload authentication unavailable")
	}
	if auth.StatusCode != 200 {
		auth.Body.Close()
		result["token_cleanup"] = "authentication_rejected"
		return result, errors.New("workload authentication denied")
	}
	data, err := io.ReadAll(io.LimitReader(auth.Body, 65537))
	auth.Body.Close()
	if err != nil || len(data) > 65536 {
		return result, errors.New("authentication response invalid")
	}
	var login struct {
		Auth struct {
			Token    string `json:"client_token"`
			Duration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if json.Unmarshal(data, &login) != nil || login.Auth.Token == "" {
		return result, errors.New("authentication response missing token")
	}
	token := login.Auth.Token
	result["token_lease_seconds"] = login.Auth.Duration
	result["token_cleanup"] = "revocation_pending"
	if login.Auth.Duration > 0 && login.Auth.Duration <= 600 {
		result["token_expected_expiry_utc"] = time.Now().UTC().Add(time.Duration(login.Auth.Duration) * time.Second).Format(time.RFC3339)
	}
	// Existing policies can deny revoke-self. Never grant extra permissions for
	// diagnostics. In that case report expiry pending, including failure paths.
	defer func() {
		response, e := request("POST", "auth/token/revoke-self", token, nil)
		if e == nil {
			response.Body.Close()
			result["token_revoke_http_status"] = response.StatusCode
			if response.StatusCode == 204 {
				result["token_cleanup"] = "revoked"
				return
			}
		}
		if login.Auth.Duration > 0 && login.Auth.Duration <= 600 {
			result["token_cleanup"] = "expiry_pending; no renewal or persistence"
		} else {
			result["token_cleanup"] = "UNRESOLVED; invalid lease and revocation not confirmed"
		}
	}()
	if login.Auth.Duration <= 0 || login.Auth.Duration > 600 {
		return result, errors.New("workload token lease outside approved ten-minute bound")
	}
	rows := []map[string]any{}
	for _, name := range []string{"keystore", "password", "slashing-db-password", "signer-tls", "client-tls", "engine-api-jwt", "other-set"} {
		path := "node-operator-runtime/data/validators/hoodi/" + set + "/runtime/" + name
		if name == "engine-api-jwt" {
			path = "node-operator-runtime/data/nodes/hoodi/engine-api-jwt"
		}
		if name == "other-set" {
			path = "node-operator-runtime/data/validators/hoodi/hoodi-unauthorized/runtime/keystore"
		}
		response, e := request("GET", path, token, nil)
		if e != nil {
			return result, errors.New("workload read request unavailable")
		}
		status := response.StatusCode
		response.Body.Close() // do not decode or retain KV secret bodies
		expected := 403
		if p.allowed[name] {
			expected = 200
		}
		rows = append(rows, map[string]any{"resource": name, "http_status": status, "expected": expected})
		result["rows"] = rows
		if status != expected {
			return result, errors.New("workload read boundary mismatch; no secret response retained")
		}
	}
	response, err := request("LIST", "node-operator-runtime/metadata/validators/hoodi/"+set, token, nil)
	if err != nil {
		return result, errors.New("metadata list request unavailable")
	}
	status := response.StatusCode
	response.Body.Close()
	result["metadata_list_status"] = status
	if status != 403 {
		return result, errors.New("metadata list was not denied")
	}
	result["result"] = "READ_BOUNDARY_PASS"
	result["scope"] = "real workload login and GET/LIST status matrix; not effective write/delete capability proof"
	return result, nil
}
