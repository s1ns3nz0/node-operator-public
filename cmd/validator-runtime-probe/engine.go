package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const engineURL = "http://nethermind-engine.node-operator.svc:8551"

func runEngineProbe(ctx context.Context, set, scenario string) (map[string]any, error) {
	// Allow bounded CNI policy convergence after Pod admission. No connection,
	// JWT read, or token generation happens before this cancellable delay.
	select {
	case <-ctx.Done():
		return nil, errors.New("engine startup cancelled")
	case <-time.After(20 * time.Second):
	}
	return runEngineProbeWith(ctx, set, engineURL, "/engine/engine.jwt", scenario, time.Now())
}
func runEngineProbeWith(ctx context.Context, set, endpoint, keyPath, scenario string, now time.Time) (map[string]any, error) {
	if !regexp.MustCompile(`^hoodi-[a-z0-9][a-z0-9-]{0,35}$`).MatchString(set) || !map[string]bool{"positive": true, "missing": true, "wrong": true}[scenario] {
		return nil, errors.New("invalid engine probe input")
	}
	var key []byte
	var err error
	if scenario == "positive" {
		file, e := os.Open(keyPath)
		if e != nil {
			return nil, errors.New("engine JWT unavailable")
		}
		raw, e := io.ReadAll(io.LimitReader(file, 129))
		file.Close()
		if e != nil || len(raw) > 128 {
			return nil, errors.New("engine JWT malformed")
		}
		text := strings.TrimSpace(string(raw))
		if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(text) {
			return nil, errors.New("engine JWT malformed")
		}
		key, _ = hex.DecodeString(text)
	} else if scenario == "wrong" {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, errors.New("random JWT generation failed")
		}
	}
	reqBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.New("fixed engine request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	if scenario != "missing" {
		req.Header.Set("Authorization", "Bearer "+jwt(key, now))
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	c := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	r, err := c.Do(req)
	if err != nil {
		return nil, errors.New("INCONCLUSIVE engine transport failure")
	}
	defer r.Body.Close()
	status := r.StatusCode
	if scenario != "positive" {
		if status == 401 || status == 403 {
			return map[string]any{"case": scenario, "layer": "engine-auth", "result": "PASS", "http_status": status}, nil
		}
		return nil, errors.New("INCONCLUSIVE engine negative response")
	}
	if status != 200 {
		return nil, errors.New("INCONCLUSIVE engine positive HTTP response")
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || len(body) > 65536 {
		return nil, errors.New("INCONCLUSIVE engine response size")
	}
	var out struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  string `json:"result"`
		Error   any    `json:"error"`
	}
	if json.Unmarshal(body, &out) != nil || out.Error != nil || out.JSONRPC != "2.0" || out.ID != 1 {
		return nil, errors.New("INCONCLUSIVE engine RPC response")
	}
	// JSON-RPC quantities are lowercase-prefixed, minimal hexadecimal integers.
	if !regexp.MustCompile(`^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$`).MatchString(out.Result) {
		return nil, errors.New("INCONCLUSIVE engine RPC response")
	}
	chain, parseErr := strconv.ParseUint(out.Result[2:], 16, 64)
	if parseErr != nil || chain != 560048 {
		return nil, errors.New("INCONCLUSIVE engine RPC response")
	}
	return map[string]any{"case": "positive", "layer": "engine-auth", "result": "PASS", "chain_id": strings.ToLower(out.Result), "http_status": status}, nil
}
func jwt(key []byte, now time.Time) string {
	enc := base64.RawURLEncoding
	h := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p := enc.EncodeToString([]byte(`{"iat":` + strconv.FormatInt(now.Unix(), 10) + `}`))
	m := h + "." + p
	s := hmac.New(sha256.New, key)
	s.Write([]byte(m))
	return m + "." + enc.EncodeToString(s.Sum(nil))
}
