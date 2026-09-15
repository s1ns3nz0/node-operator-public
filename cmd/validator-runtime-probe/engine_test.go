package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEngineJWTAndNegativeControls(t *testing.T) {
	key := strings.Repeat("ab", 32)
	f := filepath.Join(t.TempDir(), "jwt")
	os.WriteFile(f, []byte(key), 0600)
	raw, _ := hex.DecodeString(key)
	now := time.Unix(1700000000, 0)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !valid(auth, raw, now) {
			w.WriteHeader(401)
			return
		}
		var q map[string]any
		json.NewDecoder(r.Body).Decode(&q)
		if r.Method != "POST" || q["method"] != "eth_chainId" {
			t.Error("non-fixed rpc")
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x88bb0"}`))
	}))
	defer s.Close()
	if r, e := runEngineProbeWith(context.Background(), "hoodi-example", s.URL, f, "positive", now); e != nil || r["chain_id"] != "0x88bb0" {
		t.Fatalf("%v %#v", e, r)
	}
	for _, c := range []string{"missing", "wrong"} {
		if r, e := runEngineProbeWith(context.Background(), "hoodi-example", s.URL, "/does/not/exist", c, now); e != nil || r["result"] != "PASS" {
			t.Fatalf("%s %v %#v", c, e, r)
		}
	}
}
func TestEngineSafetyFailures(t *testing.T) {
	key := strings.Repeat("ab", 32)
	f := filepath.Join(t.TempDir(), "jwt")
	os.WriteFile(f, []byte(key), 0600)
	now := time.Now()
	cases := map[string]string{
		"badchain":      `{"jsonrpc":"2.0","id":1,"result":"bad"}`,
		"missingprefix": `{"jsonrpc":"2.0","id":1,"result":"88bb0"}`,
		"leadingzero":   `{"jsonrpc":"2.0","id":1,"result":"0x088bb0"}`,
		"wronghoodihex": `{"jsonrpc":"2.0","id":1,"result":"0x560048"}`,
		"otherchain":    `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
		"rpcerror":      `{"jsonrpc":"2.0","id":1,"error":{"code":-1}}`,
		"oversize":      `{"jsonrpc":"2.0","id":1,"result":"` + strings.Repeat("a", 70000) + `"}`,
	}
	for n, b := range cases {
		t.Run(n, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(b)) }))
			defer s.Close()
			if _, e := runEngineProbeWith(context.Background(), "hoodi-example", s.URL, f, "positive", now); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("negative200", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
		defer s.Close()
		if _, e := runEngineProbeWith(context.Background(), "hoodi-example", s.URL, "/missing", "missing", now); e == nil {
			t.Fatal("negative 200 passed")
		}
	})
	t.Run("negative500", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
		defer s.Close()
		if _, e := runEngineProbeWith(context.Background(), "hoodi-example", s.URL, "/missing", "wrong", now); e == nil {
			t.Fatal("negative 500 passed")
		}
	})
	t.Run("redirect", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://example.invalid", http.StatusFound)
		}))
		defer s.Close()
		if _, e := runEngineProbeWith(context.Background(), "hoodi-example", s.URL, f, "positive", now); e == nil {
			t.Fatal("redirect accepted")
		}
	})
	t.Run("malformedkey", func(t *testing.T) {
		os.WriteFile(f, []byte("bad"), 0600)
		if _, e := runEngineProbeWith(context.Background(), "hoodi-example", "http://127.0.0.1:1", f, "positive", now); e == nil {
			t.Fatal("bad key passed")
		}
	})
}
func valid(auth string, key []byte, now time.Time) bool {
	p := strings.Fields(auth)
	if len(p) != 2 || p[0] != "Bearer" {
		return false
	}
	x := strings.Split(p[1], ".")
	if len(x) != 3 {
		return false
	}
	sig, _ := base64.RawURLEncoding.DecodeString(x[2])
	m := hmac.New(sha256.New, key)
	m.Write([]byte(x[0] + "." + x[1]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return false
	}
	payload, _ := base64.RawURLEncoding.DecodeString(x[1])
	var v struct {
		Iat int64 `json:"iat"`
	}
	return json.Unmarshal(payload, &v) == nil && v.Iat >= now.Unix()-60 && v.Iat <= now.Unix()+60
}
