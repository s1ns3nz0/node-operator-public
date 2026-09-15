// Self-contained loopback black-box DAST for validator-signing-fence.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const holder = "blackbox-fence-pod"

type material struct {
	pem  []byte
	cert tls.Certificate
	pool *x509.CertPool
}

func newMaterial() (material, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return material{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "fence-dast"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return material{}, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate, err := tls.X509KeyPair(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		return material{}, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certificatePEM)
	return material{certificatePEM, certificate, pool}, nil
}

type fakeAPI struct {
	sync.Mutex
	leaseHolder, renewTime string
	podIP                  string
	malformed, fail        bool
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	a.Lock()
	if a.fail {
		a.Unlock()
		http.Error(w, "synthetic outage", http.StatusServiceUnavailable)
		return
	}
	if a.malformed {
		a.Unlock()
		fmt.Fprint(w, `{}`)
		return
	}
	podIP := a.podIP
	a.Unlock()
	if r.Header.Get("Authorization") != "Bearer synthetic-token" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if strings.Contains(r.URL.Path, "/pods/") {
		fmt.Fprintf(w, `{"metadata":{"uid":"client","labels":{"app.kubernetes.io/component":"validator-client","node-operator.io/validator-set":"alpha"}},"status":{"phase":"Running","podIP":%q}}`, podIP)
		return
	}
	a.Lock()
	defer a.Unlock()
	if r.Method == http.MethodPatch {
		var patches []map[string]string
		_ = json.NewDecoder(r.Body).Decode(&patches)
		for _, patch := range patches {
			if patch["path"] == "/spec/holderIdentity" {
				a.leaseHolder = patch["value"]
			}
			if patch["path"] == "/spec/renewTime" {
				a.renewTime = patch["value"]
			}
		}
	}
	if a.renewTime == "" {
		a.renewTime = time.Now().UTC().Add(-time.Second).Format("2006-01-02T15:04:05.000000Z07:00")
	}
	fmt.Fprintf(w, `{"metadata":{"resourceVersion":"1"},"spec":{"holderIdentity":%q,"leaseDurationSeconds":30,"renewTime":%q}}`, a.leaseHolder, a.renewTime)
}

func freeAddress() string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func start(binary, apiURL, caPath, tokenPath, upstream, listen, health string) *exec.Cmd {
	command := exec.Command(binary, "-listen", listen, "-health-listen", health, "-upstream", upstream, "-kube-api", apiURL, "-namespace", "validator-operations", "-lease-name", "validator-alpha", "-holder", holder, "-validator-set", "alpha", "-client-pod-name", "validator-alpha-client-0", "-token-path", tokenPath, "-ca-path", caPath, "-poll-interval", "1s", "-request-timeout", "1s", "-safety-margin", "1s", "-max-connection-age", "3s")
	command.Stdout, command.Stderr = os.Stderr, os.Stderr
	if err := command.Start(); err != nil {
		panic(err)
	}
	return command
}

func ready(address string) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get("http://" + address)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func main() {
	binary := flag.String("binary", "", "compiled validator-signing-fence binary")
	targetFile := flag.String("target-file", "", "write live health target then wait for scan marker")
	scanDone := flag.String("scan-done", "", "marker written by isolated scanner wrapper")
	flag.Parse()
	if *binary == "" {
		panic("-binary required")
	}
	material, err := newMaterial()
	if err != nil {
		panic(err)
	}
	directory, err := os.MkdirTemp("", "fence-dast-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(directory)
	caPath, tokenPath := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "token")
	if err := os.WriteFile(caPath, material.pem, 0600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(tokenPath, []byte("synthetic-token\n"), 0600); err != nil {
		panic(err)
	}
	api := &fakeAPI{podIP: "127.0.0.1"}
	server := httptest.NewUnstartedServer(http.HandlerFunc(api.serve))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{material.cert}}
	server.StartTLS()
	defer server.Close()
	upstream, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{material.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: material.pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		panic(err)
	}
	defer upstream.Close()
	go func() {
		for {
			connection, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	listen, health := freeAddress(), freeAddress()
	process := start(*binary, server.URL, caPath, tokenPath, upstream.Addr().String(), listen, health)
	defer process.Process.Kill()
	if !ready(health) {
		panic("fence did not become healthy")
	}
	if *targetFile != "" {
		if *scanDone == "" {
			panic("-scan-done is required with -target-file")
		}
		if err := os.WriteFile(*targetFile, []byte("http://"+health+"\n"), 0644); err != nil {
			panic(err)
		}
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(*scanDone); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if _, err := os.Stat(*scanDone); err != nil {
			panic("scanner completion marker timed out")
		}
	}
	client, err := tls.Dial("tcp", listen, &tls.Config{Certificates: []tls.Certificate{material.cert}, RootCAs: material.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		panic(err)
	}
	_, err = client.Write([]byte("synthetic"))
	if err != nil {
		panic(err)
	}
	received := make([]byte, len("synthetic"))
	_, err = io.ReadFull(client, received)
	_ = client.Close()
	if err != nil || string(received) != "synthetic" {
		panic("synthetic mTLS signer passthrough failed")
	}
	// A Pod identity whose IP is not the TCP peer must not receive a forwarded
	// signer connection, even when it presents a valid mTLS client certificate.
	// Negative scenarios must not mutate the API observed by the original
	// fence: its renewal loop continues while this second process runs.
	mismatchAPI := &fakeAPI{podIP: "127.0.0.2"}
	mismatchServer := httptest.NewUnstartedServer(http.HandlerFunc(mismatchAPI.serve))
	mismatchServer.TLS = &tls.Config{Certificates: []tls.Certificate{material.cert}}
	mismatchServer.StartTLS()
	defer mismatchServer.Close()
	mismatchListen, mismatchHealth := freeAddress(), freeAddress()
	mismatch := start(*binary, mismatchServer.URL, caPath, tokenPath, upstream.Addr().String(), mismatchListen, mismatchHealth)
	defer mismatch.Process.Kill()
	if !ready(mismatchHealth) {
		panic("source-mismatch fence did not start")
	}
	wrongSource, err := tls.Dial("tcp", mismatchListen, &tls.Config{Certificates: []tls.Certificate{material.cert}, RootCAs: material.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err == nil {
		_ = wrongSource.SetReadDeadline(time.Now().Add(time.Second))
		_, err = wrongSource.Read(make([]byte, 1))
		_ = wrongSource.Close()
	}
	if err == nil {
		panic("source IP mismatch was forwarded")
	}
	// Keep the negative case alive across renewal ticks: it must not revoke
	// the independent positive-control fence used by the outage scenario.
	time.Sleep(2 * time.Second)
	if !ready(health) {
		panic("source mismatch scenario disrupted the independent fence")
	}
	_ = mismatch.Process.Kill()
	_, _ = mismatch.Process.Wait()
	// A synthetic Kubernetes API outage on renewal must close an active TLS
	// stream and terminate the fence; it cannot retain cached authority.
	active, err := tls.Dial("tcp", listen, &tls.Config{Certificates: []tls.Certificate{material.cert}, RootCAs: material.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		panic(err)
	}
	api.Lock()
	api.fail = true
	api.Unlock()
	_ = active.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, err = active.Read(make([]byte, 1))
	_ = active.Close()
	if err == nil {
		panic("active connection survived Kubernetes API outage")
	}
	if err := process.Wait(); err == nil {
		panic("fence did not fail closed on Kubernetes API outage")
	}
	if response, err := http.Get("http://" + health); err == nil && response.StatusCode == http.StatusOK {
		response.Body.Close()
		panic("health remained 200 after lease-loss exit")
	} else if response != nil {
		response.Body.Close()
	}
	api.Lock()
	api.fail = false
	api.malformed = true
	api.Unlock()
	malformed := start(*binary, server.URL, caPath, tokenPath, upstream.Addr().String(), freeAddress(), freeAddress())
	if err := malformed.Wait(); err == nil {
		panic("malformed Lease response was admitted")
	}
	api.Lock()
	api.malformed = false
	api.leaseHolder = "another-live-pod"
	api.renewTime = time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00")
	api.Unlock()
	blocked := start(*binary, server.URL, caPath, tokenPath, upstream.Addr().String(), freeAddress(), freeAddress())
	if err := blocked.Wait(); err == nil {
		panic("competing live lease was admitted")
	}
	fmt.Println("PASS real fence: synthetic mTLS passthrough; competing lease denied")
}
