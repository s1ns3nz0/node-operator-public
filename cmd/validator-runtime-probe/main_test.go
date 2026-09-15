package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestProfiles(t *testing.T) {
	for _, name := range []string{"nethermind", "prysm", "signer", "client", "db"} {
		p, e := profile("hoodi-example", name)
		if e != nil || p.role == "" {
			t.Fatal(name)
		}
		if p.allowed["other-set"] {
			t.Fatal("cross-set access")
		}
	}
	c, _ := profile("hoodi-example", "client")
	if len(c.allowed) != 1 || !c.allowed["client-tls"] {
		t.Fatal("client boundary")
	}
	s, _ := profile("hoodi-example", "signer")
	if len(s.allowed) != 4 || s.allowed["client-tls"] {
		t.Fatal("signer boundary")
	}
	if _, e := profile("hoodi-example", "root"); e == nil {
		t.Fatal("unexpected root profile")
	}
}

type closingBody struct {
	io.Reader
	closed bool
}

func (b *closingBody) Close() error { b.closed = true; return nil }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: &closingBody{Reader: strings.NewReader(body)}}
}
func authResponse(token string, ttl int) *http.Response {
	return response(200, `{"auth":{"client_token":"`+token+`","lease_duration":`+fmt.Sprint(ttl)+`}}`)
}

func TestVaultReadMatrixAndNoBodies(t *testing.T) {
	for _, workload := range []string{"nethermind", "prysm", "signer", "client", "db"} {
		t.Run(workload, func(t *testing.T) {
			p, _ := profile("hoodi-example", workload)
			var bodies []*closingBody
			revoked := false
			req := func(method, path, token string, body []byte) (*http.Response, error) {
				var r *http.Response
				if path == "auth/kubernetes/login" {
					r = authResponse("super-secret-token", 60)
				} else if path == "auth/token/revoke-self" {
					revoked = true
					r = response(204, "")
				} else if method == "LIST" {
					r = response(403, "secret")
				} else {
					name := path[strings.LastIndex(path, "/")+1:]
					if !strings.Contains(path, "hoodi-unauthorized") && p.allowed[name] {
						r = response(200, "secret-body")
					} else {
						r = response(403, "secret-body")
					}
				}
				bodies = append(bodies, r.Body.(*closingBody))
				return r, nil
			}
			result, err := checkVaultReadBoundary("hoodi-example", workload, []byte("jwt-secret"), req)
			if err != nil || result["result"] != "READ_BOUNDARY_PASS" || !revoked {
				t.Fatalf("%v %#v", err, result)
			}
			encoded, _ := json.Marshal(result)
			if bytes.Contains(encoded, []byte("super-secret-token")) || bytes.Contains(encoded, []byte("jwt-secret")) {
				t.Fatal("secret/token leaked")
			}
			for _, b := range bodies {
				if !b.closed {
					t.Fatal("body not closed")
				}
			}
		})
	}
}

func TestVaultCleanupAndFailures(t *testing.T) {
	cases := []struct {
		name        string
		ttl         int
		authCode    int
		revoke      int
		wantErr     bool
		requestFail bool
	}{{"revoke403", 60, 200, 403, false, false}, {"badttl", 0, 200, 403, true, false}, {"longttl", 601, 200, 403, true, false}, {"authdenied", 0, 403, 0, true, false}, {"requestfail", 0, 0, 0, true, true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			revoked := false
			req := func(method, path, token string, body []byte) (*http.Response, error) {
				if tc.requestFail {
					return nil, errors.New("network")
				}
				if path == "auth/kubernetes/login" {
					if tc.authCode != 200 {
						return response(tc.authCode, ""), nil
					}
					return authResponse("token", tc.ttl), nil
				}
				if path == "auth/token/revoke-self" {
					revoked = true
					return response(tc.revoke, ""), nil
				}
				if path == "node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/client-tls" {
					return response(200, ""), nil
				}
				return response(403, ""), nil
			}
			r, e := checkVaultReadBoundary("hoodi-example", "client", []byte("jwt"), req)
			if (e != nil) != tc.wantErr {
				t.Fatalf("err %v", e)
			}
			if (tc.ttl <= 0 || tc.ttl > 600) && tc.authCode == 200 && !revoked {
				t.Fatal("invalid ttl did not revoke")
			}
			if tc.ttl > 0 && tc.ttl <= 600 && tc.revoke == 403 && r["token_cleanup"] != "expiry_pending; no renewal or persistence" {
				t.Fatalf("cleanup %#v", r)
			}
		})
	}
}
