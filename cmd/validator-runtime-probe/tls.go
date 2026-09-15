package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const tlsProbeLimit = 64 * 1024

var tlsKey = regexp.MustCompile(`^0x[0-9a-f]{96}$`)

type tlsProbeConfig struct {
	endpoint, serverName, host string
	cert, key, ca              string
}

func runTLSProbe(ctx context.Context, set, key, tlsCase string) (map[string]any, error) {
	if !regexp.MustCompile(`^hoodi-[a-z0-9][a-z0-9-]{0,35}$`).MatchString(set) || !tlsKey.MatchString(strings.ToLower(key)) {
		return nil, errors.New("invalid fixed validator identity")
	}
	canonical := fmt.Sprintf("validator-%s-remote-signer.validator-operations.svc", set)
	config := tlsProbeConfig{endpoint: "https://validator-" + set + "-remote-signer-direct.validator-operations.svc:9000/api/v1/eth2/publicKeys", serverName: canonical, host: canonical, cert: "/tls/tls.crt", key: "/tls/tls.key", ca: "/tls/ca.crt"}
	return runTLSProbeWithConfig(ctx, config, strings.ToLower(key), tlsCase)
}
func runTLSProbeWithConfig(ctx context.Context, c tlsProbeConfig, expected, which string) (map[string]any, error) {
	tr, err := tlsTransport(c, which)
	if err != nil {
		return nil, err
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, errors.New("fixed request construction failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Host = c.host
	response, err := client.Do(req)
	if which != "positive" {
		if err != nil {
			if isTLSAuth(err, which) {
				return map[string]any{"case": which, "layer": "tls", "result": "PASS"}, nil
			}
			return nil, errors.New("INCONCLUSIVE TLS negative transport failure")
		}
		defer response.Body.Close()
		return nil, fmt.Errorf("INCONCLUSIVE TLS negative: HTTP %d", response.StatusCode)
	}
	if err != nil {
		return nil, errors.New("positive TLS GET failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("positive GET returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, tlsProbeLimit+1))
	if err != nil || len(body) > tlsProbeLimit {
		return nil, errors.New("bounded public-key response failed")
	}
	var keys []string
	if json.Unmarshal(body, &keys) != nil || len(keys) != 1 || !tlsKey.MatchString(strings.ToLower(keys[0])) || strings.ToLower(keys[0]) != expected {
		return nil, errors.New("public-key response mismatch")
	}
	return map[string]any{"case": "positive", "layer": "tls+http", "result": "PASS", "validator_public_key": strings.ToLower(keys[0])}, nil
}
func tlsTransport(c tlsProbeConfig, which string) (*http.Transport, error) {
	roots := x509.NewCertPool()
	var certs []tls.Certificate
	if which == "bad-ca" {
		bad, err := syntheticCA()
		if err != nil {
			return nil, err
		}
		roots.AddCert(bad)
	} else {
		pem, err := os.ReadFile(c.ca)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("TLS CA unavailable or invalid")
		}
	}
	switch which {
	case "positive", "bad-ca":
		cert, err := tls.LoadX509KeyPair(c.cert, c.key)
		if err != nil {
			return nil, errors.New("TLS client certificate unavailable")
		}
		certs = []tls.Certificate{cert}
	case "no-client":
	case "untrusted-client":
		cert, err := syntheticClient()
		if err != nil {
			return nil, err
		}
		certs = []tls.Certificate{cert}
	default:
		return nil, errors.New("unsupported TLS case")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: certs, ServerName: c.serverName}
	if which == "untrusted-client" {
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certs[0], nil }
	}
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, TLSClientConfig: config}, nil
}
func syntheticCA() (*x509.Certificate, error) {
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, e
	}
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	t := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "synthetic-untrusted-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	d, e := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if e != nil {
		return nil, e
	}
	return x509.ParseCertificate(d)
}
func syntheticClient() (tls.Certificate, error) {
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return tls.Certificate{}, e
	}
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	t := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "synthetic-untrusted-client"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	d, e := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if e != nil {
		return tls.Certificate{}, e
	}
	return tls.X509KeyPair(pemCert(d), pemKey(k))
}
func pemCert(d []byte) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(d) + "\n-----END CERTIFICATE-----\n")
}
func pemKey(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}
func isTLSAuth(err error, which string) bool {
	if which == "bad-ca" {
		var authority x509.UnknownAuthorityError
		return errors.As(err, &authority)
	}
	if which != "no-client" && which != "untrusted-client" {
		return false
	}
	for current := err; current != nil; current = errors.Unwrap(current) {
		switch current.Error() {
		case "remote error: tls: certificate required", "remote error: tls: bad certificate", "remote error: tls: unknown certificate authority", "remote error: tls: access denied", "remote error: tls: unknown certificate":
			return true
		}
	}
	return false
}
