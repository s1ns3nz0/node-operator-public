package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testKey = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestTLSPositiveAndMismatch(t *testing.T) {
	ca, cert, key, serverCert, _, _ := pki(t)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/eth2/publicKeys" {
			t.Error("not fixed GET")
		}
		w.Write([]byte(`["` + testKey + `"]`))
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	s.StartTLS()
	defer s.Close()
	u, _ := url.Parse(s.URL)
	c := tlsProbeConfig{endpoint: "https://localhost:" + u.Port() + "/api/v1/eth2/publicKeys", serverName: "localhost", host: "localhost", ca: ca, cert: cert, key: key}
	if _, e := runTLSProbeWithConfig(context.Background(), c, testKey, "positive"); e != nil {
		t.Fatal(e)
	}
	if _, e := runTLSProbeWithConfig(context.Background(), c, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "positive"); e == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestTLSHandshakeNegativeCases(t *testing.T) {
	ca, cert, key, serverCert, root, _ := pki(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "client" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`["` + testKey + `"]`))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: root}
	server.StartTLS()
	defer server.Close()
	u, _ := url.Parse(server.URL)
	c := tlsProbeConfig{endpoint: "https://localhost:" + u.Port() + "/api/v1/eth2/publicKeys", serverName: "localhost", host: "localhost", ca: ca, cert: cert, key: key}
	if _, err := runTLSProbeWithConfig(context.Background(), c, testKey, "positive"); err != nil {
		t.Fatalf("positive mTLS failed: %v", err)
	}
	for _, scenario := range []string{"bad-ca", "no-client", "untrusted-client"} {
		result, err := runTLSProbeWithConfig(context.Background(), c, testKey, scenario)
		if err != nil || result["result"] != "PASS" || result["layer"] != "tls" {
			t.Fatalf("%s rejection not proved: %v %v", scenario, result, err)
		}
	}
}
func TestTLSUnreachableIsInconclusive(t *testing.T) {
	ca, cert, key, _, _, _ := pki(t)
	c := tlsProbeConfig{endpoint: "https://127.0.0.1:1/api/v1/eth2/publicKeys", serverName: "localhost", host: "localhost", ca: ca, cert: cert, key: key}
	if _, e := runTLSProbeWithConfig(context.Background(), c, testKey, "bad-ca"); e == nil {
		t.Fatal("unreachable negative passed")
	}
}
func TestAmbiguousTLSErrorsNotAuthenticationProof(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, context.DeadlineExceeded, errors.New("remote error: tls: bad record MAC"), errors.New("tls: first record does not look like a TLS handshake"), errors.New("connection reset by peer"), errors.New("certificate hostname in a DNS timeout")} {
		for _, scenario := range []string{"bad-ca", "no-client", "untrusted-client"} {
			if isTLSAuth(err, scenario) {
				t.Fatalf("false auth proof %s %v", scenario, err)
			}
		}
	}
}
func TestTLSCaseValidation(t *testing.T) {
	if _, e := runTLSProbeWithConfig(context.Background(), tlsProbeConfig{}, testKey, "wrong"); e == nil {
		t.Fatal("unknown case accepted")
	}
}
func TestHTTPDenialIsNotTLSRejection(t *testing.T) {
	ca, cert, key, serverCert, _, _ := pki(t)
	for _, status := range []int{200, 401, 403} {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
		server.StartTLS()
		u, _ := url.Parse(server.URL)
		c := tlsProbeConfig{endpoint: "https://localhost:" + u.Port() + "/api/v1/eth2/publicKeys", serverName: "localhost", host: "localhost", ca: ca, cert: cert, key: key}
		for _, scenario := range []string{"no-client", "untrusted-client"} {
			if _, err := runTLSProbeWithConfig(context.Background(), c, testKey, scenario); err == nil {
				t.Fatalf("HTTP %d falsely passed %s", status, scenario)
			}
		}
		server.Close()
	}
}
func pki(t *testing.T) (string, string, string, tls.Certificate, *x509.CertPool, *rsa.PrivateKey) {
	t.Helper()
	d := t.TempDir()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &k.PublicKey, k)
	caP := filepath.Join(d, "ca")
	os.WriteFile(caP, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600)
	leafK, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, ca, &leafK.PublicKey, k)
	certP, keyP := filepath.Join(d, "c"), filepath.Join(d, "k")
	os.WriteFile(certP, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyP, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafK)}), 0600)
	tc, e := tls.LoadX509KeyPair(certP, keyP)
	if e != nil {
		t.Fatal(e)
	}
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientLeaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "client"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientLeaf, ca, &clientKey.PublicKey, k)
	clientCertP, clientKeyP := filepath.Join(d, "client.crt"), filepath.Join(d, "client.key")
	os.WriteFile(clientCertP, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0600)
	os.WriteFile(clientKeyP, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}), 0600)
	pool := x509.NewCertPool()
	parsedCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsedCA)
	return caP, clientCertP, clientKeyP, tc, pool, k
}
