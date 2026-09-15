package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testPublicKey = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type testIdentity struct {
	certificate tls.Certificate
	certPath    string
	keyPath     string
}

type testPKI struct {
	ca         *x509.Certificate
	caKey      *rsa.PrivateKey
	caPath     string
	server     testIdentity
	client     testIdentity
	serverPool *x509.CertPool
}

func TestRunProbeMutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	server := newMutualTLSServer(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/eth2/publicKeys" || r.URL.RawQuery != "" || r.Host != "localhost" {
			t.Fatalf("unexpected request target: %s %s", r.Method, r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`["` + testPublicKey + `"]`))
	}))
	result, err := runProbe(context.Background(), probeConfigForServer(t, pki, server, testPublicKey))
	if err != nil {
		t.Fatalf("runProbe failed: %v", err)
	}
	if result.SchemaVersion != 1 || result.EventType != "signer-public-key" || result.Network != "hoodi" || result.ValidatorSet != "hoodi-test-001" || result.Source != "web3signer-tls" {
		t.Fatalf("unexpected evidence identity: %#v", result)
	}
	if result.ValidatorPublicKey != testPublicKey || !result.TLSVerified || result.PublicKeyCount != 1 || !result.PublicKeyMatch {
		t.Fatalf("unexpected signer evidence: %#v", result)
	}
	if _, err := time.Parse(time.RFC3339, result.CollectedAtUTC); err != nil {
		t.Fatalf("invalid evidence timestamp: %v", err)
	}
}

func TestProductionConfigBindsDirectRouteToCanonicalTLSAudience(t *testing.T) {
	config := productionConfig("hoodi-example", testPublicKey)
	if config.endpoint != "https://validator-hoodi-example-remote-signer-direct.validator-operations.svc:9000/api/v1/eth2/publicKeys" {
		t.Fatalf("unexpected fixed endpoint: %s", config.endpoint)
	}
	if config.serverName != "validator-hoodi-example-remote-signer.validator-operations.svc" {
		t.Fatalf("unexpected TLS audience: %s", config.serverName)
	}
	if config.hostHeader != config.serverName {
		t.Fatalf("HTTP Host is not bound to the TLS audience: %#v", config)
	}
	if config.clientCert != "/tls/tls.crt" || config.clientKey != "/tls/tls.key" || config.caCert != "/tls/ca.crt" {
		t.Fatalf("unexpected credential paths: %#v", config)
	}
}

func TestRunProbeRejectsWrongCA(t *testing.T) {
	pki := newTestPKI(t)
	server := newMutualTLSServer(t, pki, keyHandler(testPublicKey))
	wrongPKI := newTestPKI(t)
	config := probeConfigForServer(t, pki, server, testPublicKey)
	config.caCert = wrongPKI.caPath
	if _, err := runProbe(context.Background(), config); err == nil {
		t.Fatal("wrong server CA was accepted")
	}
}

func TestRunProbeRejectsHostnameMismatch(t *testing.T) {
	pki := newTestPKI(t)
	server := newMutualTLSServer(t, pki, keyHandler(testPublicKey))
	config := probeConfigForServer(t, pki, server, testPublicKey)
	config.serverName = "wrong.example"
	if _, err := runProbe(context.Background(), config); err == nil {
		t.Fatal("hostname mismatch was accepted")
	}
}

func TestRunProbeRejectsMissingClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	server := newMutualTLSServer(t, pki, keyHandler(testPublicKey))
	config := probeConfigForServer(t, pki, server, testPublicKey)
	config.clientCert = filepath.Join(t.TempDir(), "missing-client.crt")
	config.clientKey = filepath.Join(t.TempDir(), "missing-client.key")
	if _, err := runProbe(context.Background(), config); err == nil {
		t.Fatal("missing client certificate was accepted")
	}
}

func TestRunProbeRejectsRedirectWithoutContactingDestination(t *testing.T) {
	pki := newTestPKI(t)
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(destination.Close)
	redirector := newMutualTLSServer(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	if _, err := runProbe(context.Background(), probeConfigForServer(t, pki, redirector, testPublicKey)); err == nil {
		t.Fatal("redirect was accepted")
	}
	if destinationRequests.Load() != 0 {
		t.Fatalf("redirect destination received %d requests", destinationRequests.Load())
	}
}

func TestRunProbeRejectsUnexpectedKeysAndOversize(t *testing.T) {
	tests := map[string]string{
		"key mismatch":  `["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]`,
		"multiple keys": `["` + testPublicKey + `","` + testPublicKey + `"]`,
		"oversize body": `{"padding":"` + strings.Repeat("x", maximumResponseBytes) + `"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			pki := newTestPKI(t)
			server := newMutualTLSServer(t, pki, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			if _, err := runProbe(context.Background(), probeConfigForServer(t, pki, server, testPublicKey)); err == nil {
				t.Fatal("unexpected response was accepted")
			}
		})
	}
}

func keyHandler(key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`["` + key + `"]`))
	})
}

func probeConfigForServer(t *testing.T, pki *testPKI, server *httptest.Server, expectedKey string) probeConfig {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	serverURL.Host = "localhost:" + serverURL.Port()
	serverURL.Path = "/api/v1/eth2/publicKeys"
	return probeConfig{validatorSet: "hoodi-test-001", expectedKey: expectedKey, endpoint: serverURL.String(), clientCert: pki.client.certPath, clientKey: pki.client.keyPath, caCert: pki.caPath, serverName: "localhost", hostHeader: "localhost"}
}

func newMutualTLSServer(t *testing.T, pki *testPKI, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.server.certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.serverPool}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	directory := t.TempDir()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.crt")
	writePEM(t, caPath, "CERTIFICATE", caDER)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mustRead(t, caPath)) {
		t.Fatal("could not append test CA")
	}
	return &testPKI{ca: ca, caKey: caKey, caPath: caPath, server: issueIdentity(t, directory, ca, caKey, "localhost", true), client: issueIdentity(t, directory, ca, caKey, "client", false), serverPool: pool}
}

func issueIdentity(t *testing.T, directory string, ca *x509.Certificate, caKey *rsa.PrivateKey, name string, server bool) testIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		template.DNSNames = []string{name}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(directory, name+".crt")
	keyPath := filepath.Join(directory, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{certificate: certificate, certPath: certPath, keyPath: keyPath}
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
