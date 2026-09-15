package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	clientCertificatePath = "/tls/tls.crt"
	clientKeyPath         = "/tls/tls.key"
	caCertificatePath     = "/tls/ca.crt"
	maximumResponseBytes  = 64 * 1024
)

var (
	validatorSetPattern = regexp.MustCompile(`^hoodi-[a-z0-9][a-z0-9-]{0,35}$`)
	publicKeyPattern    = regexp.MustCompile(`^0x[0-9a-f]{96}$`)
)

type probeConfig struct {
	validatorSet string
	expectedKey  string
	endpoint     string
	clientCert   string
	clientKey    string
	caCert       string
	serverName   string
	hostHeader   string
}

type evidence struct {
	SchemaVersion      int    `json:"schema_version"`
	EventType          string `json:"event_type"`
	Network            string `json:"network"`
	ValidatorSet       string `json:"validator_set"`
	Source             string `json:"source"`
	ValidatorPublicKey string `json:"validator_public_key"`
	CollectedAtUTC     string `json:"collected_at_utc"`
	TLSVerified        bool   `json:"tls_verified"`
	PublicKeyCount     int    `json:"public_key_count"`
	PublicKeyMatch     bool   `json:"public_key_match"`
}

func main() {
	validatorSet := flag.String("validator-set", "", "validator set (hoodi-*)")
	expectedKey := flag.String("expected-public-key", "", "expected 0x-prefixed 96-hex BLS public key")
	flag.Parse()
	if flag.NArg() != 0 || !validatorSetPattern.MatchString(*validatorSet) {
		fail("invalid validator set")
	}
	normalizedKey := strings.ToLower(*expectedKey)
	if !publicKeyPattern.MatchString(normalizedKey) {
		fail("invalid expected public key")
	}
	config := productionConfig(*validatorSet, normalizedKey)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := runProbe(ctx, config)
	if err != nil {
		fail(err.Error())
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(result); err != nil {
		fail("could not write evidence")
	}
}

func productionConfig(validatorSet, expectedKey string) probeConfig {
	canonicalSignerName := fmt.Sprintf("validator-%s-remote-signer.validator-operations.svc", validatorSet)
	directSignerName := fmt.Sprintf("validator-%s-remote-signer-direct.validator-operations.svc", validatorSet)
	return probeConfig{
		validatorSet: validatorSet,
		expectedKey:  expectedKey,
		endpoint:     "https://" + directSignerName + ":9000/api/v1/eth2/publicKeys",
		clientCert:   clientCertificatePath,
		clientKey:    clientKeyPath,
		caCert:       caCertificatePath,
		serverName:   canonicalSignerName,
		hostHeader:   canonicalSignerName,
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "signer identity probe failed:", message)
	os.Exit(1)
}

func runProbe(ctx context.Context, config probeConfig) (evidence, error) {
	client, err := newHTTPClient(config)
	if err != nil {
		return evidence{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.endpoint, nil)
	if err != nil {
		return evidence{}, errors.New("could not construct fixed signer request")
	}
	request.Header.Set("Accept", "application/json")
	request.Host = config.hostHeader
	response, err := client.Do(request)
	if err != nil {
		return evidence{}, errors.New("mutual TLS signer request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return evidence{}, errors.New("signer returned a non-success status")
	}
	limited := io.LimitReader(response.Body, maximumResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return evidence{}, errors.New("could not read bounded signer response")
	}
	if len(body) > maximumResponseBytes {
		return evidence{}, errors.New("signer response exceeded size limit")
	}
	var keys []string
	if err := json.Unmarshal(body, &keys); err != nil {
		return evidence{}, errors.New("signer response was not a public-key array")
	}
	if len(keys) != 1 {
		return evidence{}, errors.New("signer did not return exactly one public key")
	}
	observedKey := strings.ToLower(keys[0])
	if !publicKeyPattern.MatchString(observedKey) || observedKey != config.expectedKey {
		return evidence{}, errors.New("signer public key did not match expected identity")
	}
	return evidence{
		SchemaVersion:      1,
		EventType:          "signer-public-key",
		Network:            "hoodi",
		ValidatorSet:       config.validatorSet,
		Source:             "web3signer-tls",
		ValidatorPublicKey: observedKey,
		CollectedAtUTC:     time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		TLSVerified:        true,
		PublicKeyCount:     1,
		PublicKeyMatch:     true,
	}, nil
}

func newHTTPClient(config probeConfig) (*http.Client, error) {
	clientCertificate, err := tls.LoadX509KeyPair(config.clientCert, config.clientKey)
	if err != nil {
		return nil, errors.New("client certificate is unavailable")
	}
	caPEM, err := os.ReadFile(config.caCert)
	if err != nil {
		return nil, errors.New("signer CA is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("signer CA is invalid")
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      roots,
			Certificates: []tls.Certificate{clientCertificate},
			ServerName:   config.serverName,
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect refused")
		},
	}, nil
}
