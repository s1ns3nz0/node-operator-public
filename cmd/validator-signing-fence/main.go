// validator-signing-fence is a TLS-passthrough sidecar for Web3Signer. It
// admits TCP connections only while this Pod UID holds an exact Kubernetes
// Lease. It does not inspect, terminate, or log TLS traffic.
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	ErrLeaseHeld     = errors.New("lease is held by another live pod")
	ErrLeaseConflict = errors.New("lease compare-and-swap conflict")
	ErrInvalidLease  = errors.New("lease is malformed, stale, or future-dated")
)

type leaseDocument struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string `json:"holderIdentity"`
		LeaseDurationSeconds *int64 `json:"leaseDurationSeconds"`
		RenewTime            string `json:"renewTime"`
	} `json:"spec"`
}

type leaseState struct {
	resourceVersion string
	holder          string
	duration        time.Duration
	renewed         time.Time
	hasRenewed      bool
}

type leaseAuthority struct {
	// deadline is derived from the local monotonic clock at the exact renewal
	// timestamp sent in the successful CAS patch. It is never extended merely
	// because a connection was accepted later.
	deadline time.Time
}

// connectionAudit writes a deliberately small, line-oriented connection
// interval receipt to the container log.  It is not a TLS or per-request
// audit: the fence cannot inspect either without terminating passthrough TLS.
// A result of "closed" means only that the upstream TCP dial succeeded and
// the resulting tunnel later closed.
type connectionAudit struct {
	writer io.Writer
	now    func() time.Time
	mu     sync.Mutex
	nextID atomic.Uint64
}

type connectionInterval struct {
	audit        *connectionAudit
	validatorSet string
	holder       string
	lease        string
	id           string
	opened       time.Time
}

func newConnectionAudit(writer io.Writer, now func() time.Time) *connectionAudit {
	return &connectionAudit{writer: writer, now: now}
}

func (a *connectionAudit) begin(validatorSet, holder, lease string) *connectionInterval {
	if a == nil || a.writer == nil || a.now == nil {
		return nil
	}
	return &connectionInterval{
		audit: a, validatorSet: validatorSet, holder: holder, lease: lease,
		id: fmt.Sprintf("%016x", a.nextID.Add(1)), opened: a.now().UTC(),
	}
}

func (i *connectionInterval) close(result string) {
	if i == nil {
		return
	}
	closed := i.audit.now().UTC()
	// Keep each receipt as one CRI log line even while several passthrough
	// goroutines finish concurrently. Values originate from validated startup
	// configuration or this process's counter; no connection metadata is logged.
	i.audit.mu.Lock()
	_, _ = fmt.Fprintf(i.audit.writer, "fence_connection validator_set=%s holder=%s lease=%s connection_id=%s opened_at_utc=%s closed_at_utc=%s opened_at_ms=%d closed_at_ms=%d result=%s\n",
		i.validatorSet, i.holder, i.lease, i.id,
		i.opened.Format(time.RFC3339Nano), closed.Format(time.RFC3339Nano),
		i.opened.UnixMilli(), closed.UnixMilli(), result)
	i.audit.mu.Unlock()
}

type leaseClient struct {
	apiBase        string
	namespace      string
	name           string
	holder         string
	validatorSet   string
	clientPodName  string
	pollInterval   time.Duration
	safetyMargin   time.Duration
	requestTimeout time.Duration
	httpClient     *http.Client
	token          func() ([]byte, error)
	now            func() time.Time
}

func (c *leaseClient) resourceEndpoint(resource, name string) (string, error) {
	if c.apiBase == "" || c.namespace == "" || resource == "" || name == "" {
		return "", errors.New("Kubernetes API, namespace, resource, and name are required")
	}
	base, err := url.Parse(c.apiBase)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", errors.New("invalid Kubernetes API URL")
	}
	if resource == "leases" {
		base.Path = strings.TrimRight(base.Path, "/") + "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(c.namespace) + "/leases/" + url.PathEscape(name)
	} else if resource == "pods" {
		base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/namespaces/" + url.PathEscape(c.namespace) + "/pods/" + url.PathEscape(name)
	} else {
		return "", errors.New("unsupported Kubernetes resource")
	}
	return base.String(), nil
}

func (c *leaseClient) leaseEndpoint() (string, error) {
	if c.name == "" || c.holder == "" {
		return "", errors.New("Lease name and holder are required")
	}
	return c.resourceEndpoint("leases", c.name)
}

func (c *leaseClient) podEndpoint() (string, error) {
	if c.clientPodName == "" || c.validatorSet == "" {
		return "", errors.New("validator set and client Pod name are required")
	}
	return c.resourceEndpoint("pods", c.clientPodName)
}

func (c *leaseClient) request(ctx context.Context, method, endpoint string, body []byte, contentType string) (*http.Response, error) {
	token, err := c.token()
	if err != nil || len(token) == 0 {
		return nil, errors.New("read projected service-account token")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return c.httpClient.Do(request)
}

func decodeLease(response io.Reader) (leaseState, error) {
	var document leaseDocument
	if err := json.NewDecoder(io.LimitReader(response, 1024*1024)).Decode(&document); err != nil {
		return leaseState{}, ErrInvalidLease
	}
	if document.Metadata.ResourceVersion == "" || document.Spec.LeaseDurationSeconds == nil || *document.Spec.LeaseDurationSeconds <= 0 {
		return leaseState{}, ErrInvalidLease
	}
	state := leaseState{
		resourceVersion: document.Metadata.ResourceVersion,
		holder:          document.Spec.HolderIdentity,
		duration:        time.Duration(*document.Spec.LeaseDurationSeconds) * time.Second,
	}
	if document.Spec.RenewTime != "" {
		renewed, err := time.Parse(time.RFC3339Nano, document.Spec.RenewTime)
		if err != nil {
			return leaseState{}, ErrInvalidLease
		}
		state.renewed, state.hasRenewed = renewed, true
	}
	return state, nil
}

func (c *leaseClient) get(ctx context.Context) (leaseState, error) {
	endpoint, err := c.leaseEndpoint()
	if err != nil {
		return leaseState{}, err
	}
	response, err := c.request(ctx, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return leaseState{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return leaseState{}, fmt.Errorf("lease GET returned HTTP %d", response.StatusCode)
	}
	return decodeLease(response.Body)
}

type podDocument struct {
	Metadata struct {
		UID               string            `json:"uid"`
		Labels            map[string]string `json:"labels"`
		DeletionTimestamp *string           `json:"deletionTimestamp"`
	} `json:"metadata"`
	Status struct {
		Phase string `json:"phase"`
		PodIP string `json:"podIP"`
	} `json:"status"`
}

type clientIdentity struct {
	uid string
	ip  string
}

func (c *leaseClient) getClientPod(ctx context.Context) (clientIdentity, error) {
	endpoint, err := c.podEndpoint()
	if err != nil {
		return clientIdentity{}, err
	}
	response, err := c.request(ctx, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return clientIdentity{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return clientIdentity{}, fmt.Errorf("client Pod GET returned HTTP %d", response.StatusCode)
	}
	var pod podDocument
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&pod); err != nil {
		return clientIdentity{}, ErrInvalidLease
	}
	if pod.Metadata.UID == "" || pod.Metadata.DeletionTimestamp != nil || pod.Metadata.Labels["app.kubernetes.io/component"] != "validator-client" || pod.Metadata.Labels["node-operator.io/validator-set"] != c.validatorSet || pod.Status.Phase != "Running" {
		return clientIdentity{}, ErrInvalidLease
	}
	ip := net.ParseIP(pod.Status.PodIP)
	if ip == nil {
		return clientIdentity{}, ErrInvalidLease
	}
	return clientIdentity{uid: pod.Metadata.UID, ip: ip.String()}, nil
}

func (c *leaseClient) validDuration(state leaseState) error {
	// Client Pod GET, Lease GET, and Lease PATCH each have hard deadlines.
	// Reserve all three plus one polling interval before expiry so a slow API
	// cannot make a stale authority look usable merely because renewal was
	// delayed.
	if state.duration <= c.pollInterval+3*c.requestTimeout+c.safetyMargin {
		return ErrInvalidLease
	}
	return nil
}

func (c *leaseClient) acquireOrRenew(ctx context.Context) (leaseAuthority, error) {
	getContext, cancelGet := context.WithTimeout(ctx, c.requestTimeout)
	state, err := c.get(getContext)
	cancelGet()
	if err != nil {
		return leaseAuthority{}, err
	}
	if err := c.validDuration(state); err != nil {
		return leaseAuthority{}, err
	}
	// Capture the local monotonic time immediately before PATCH. The resulting absolute
	// deadline includes elapsed GET time and continues to run while PATCH is
	// in flight; a late response cannot manufacture a fresh full-duration lease.
	now := c.now()
	// coordination.k8s.io Lease renewTime is metav1.MicroTime. Send and compare
	// the same microsecond precision Kubernetes preserves on round-trip.
	nowUTC := now.UTC().Truncate(time.Microsecond)
	expired := false
	if state.holder != "" {
		if !state.hasRenewed || state.renewed.After(nowUTC.Add(c.safetyMargin)) {
			return leaseAuthority{}, ErrInvalidLease
		}
		expired = !nowUTC.Before(state.renewed.Add(state.duration))
	}
	if state.holder == c.holder && expired {
		// A holder that allowed its own authority to expire must use explicit
		// recovery rather than silently resuming a cached signer path.
		return leaseAuthority{}, ErrInvalidLease
	}
	if state.holder != "" && state.holder != c.holder && !expired {
		return leaseAuthority{}, ErrLeaseHeld
	}

	patch := []map[string]string{
		{"op": "test", "path": "/metadata/resourceVersion", "value": state.resourceVersion},
		{"op": "test", "path": "/spec/holderIdentity", "value": state.holder},
	}
	if state.holder != c.holder {
		// Bootstrap only an empty Lease or a demonstrably expired prior holder.
		patch = append(patch, map[string]string{"op": "replace", "path": "/spec/holderIdentity", "value": c.holder})
	}
	// MicroTime requires exactly six fractional digits, even when they end in
	// zero. RFC3339Nano trims zeroes and intermittently causes API HTTP 422.
	patch = append(patch, map[string]string{"op": "add", "path": "/spec/renewTime", "value": nowUTC.Format("2006-01-02T15:04:05.000000Z07:00")})
	body, err := json.Marshal(patch)
	if err != nil {
		return leaseAuthority{}, err
	}
	patchContext, cancelPatch := context.WithTimeout(ctx, c.requestTimeout)
	endpoint, err := c.leaseEndpoint()
	if err != nil {
		cancelPatch()
		return leaseAuthority{}, err
	}
	response, err := c.request(patchContext, http.MethodPatch, endpoint, body, "application/json-patch+json")
	if err != nil {
		cancelPatch()
		return leaseAuthority{}, err
	}
	defer response.Body.Close()
	defer cancelPatch()
	if response.StatusCode == http.StatusConflict {
		return leaseAuthority{}, ErrLeaseConflict
	}
	if response.StatusCode != http.StatusOK {
		return leaseAuthority{}, fmt.Errorf("lease PATCH returned HTTP %d", response.StatusCode)
	}
	updated, err := decodeLease(response.Body)
	if err != nil || updated.holder != c.holder || !updated.hasRenewed || !updated.renewed.Equal(nowUTC) {
		return leaseAuthority{}, ErrInvalidLease
	}
	if err := c.validDuration(updated); err != nil {
		return leaseAuthority{}, err
	}
	return leaseAuthority{deadline: now.Add(updated.duration - c.safetyMargin)}, nil
}

type fenceProxy struct {
	lease             *leaseClient
	listenAddress     string
	upstreamAddress   string
	maxConnectionAge  time.Duration
	dialTimeout       time.Duration
	mu                sync.Mutex
	listener          net.Listener
	connections       map[net.Conn]struct{}
	downstreamIP      string
	clientUID         string
	clientIP          string
	authorityDeadline time.Time
	deadlineVersion   uint64
	fenced            bool
	done              chan struct{}
	doneOnce          sync.Once
	audit             *connectionAudit
}

func newFenceProxy(lease *leaseClient, listenAddress, upstreamAddress string, maxConnectionAge, dialTimeout time.Duration) *fenceProxy {
	return &fenceProxy{lease: lease, listenAddress: listenAddress, upstreamAddress: upstreamAddress, maxConnectionAge: maxConnectionAge, dialTimeout: dialTimeout, connections: make(map[net.Conn]struct{}), done: make(chan struct{}), audit: newConnectionAudit(os.Stdout, time.Now)}
}

func (p *fenceProxy) start(ctx context.Context) error {
	authority, err := p.renewAuthority(ctx)
	if err != nil {
		return err
	}
	leaseLimit := time.Until(authority.deadline)
	if leaseLimit <= 0 {
		return ErrInvalidLease
	}
	if p.maxConnectionAge <= 0 || p.maxConnectionAge > leaseLimit {
		p.maxConnectionAge = leaseLimit
	}
	listener, err := net.Listen("tcp", p.listenAddress)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.listener = listener
	p.mu.Unlock()
	p.setAuthorityDeadline(authority.deadline)
	go p.acceptLoop()
	go p.renewLoop(ctx)
	return nil
}

func (p *fenceProxy) renewAuthority(ctx context.Context) (leaseAuthority, error) {
	podContext, cancelPod := context.WithTimeout(ctx, p.lease.requestTimeout)
	identity, err := p.lease.getClientPod(podContext)
	cancelPod()
	if err != nil {
		return leaseAuthority{}, err
	}
	p.mu.Lock()
	if p.clientUID == "" {
		p.clientUID, p.clientIP = identity.uid, identity.ip
	} else if p.clientUID != identity.uid || p.clientIP != identity.ip {
		p.mu.Unlock()
		return leaseAuthority{}, ErrInvalidLease
	}
	p.mu.Unlock()
	return p.lease.acquireOrRenew(ctx)
}

func (p *fenceProxy) address() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

func (p *fenceProxy) healthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.fenced && p.listener != nil
}

func (p *fenceProxy) setAuthorityDeadline(deadline time.Time) {
	p.mu.Lock()
	p.authorityDeadline = deadline
	p.deadlineVersion++
	version := p.deadlineVersion
	p.mu.Unlock()
	// deadline is derived from a local time.Time with monotonic data when the
	// production clock is used. This watchdog is independent of the renewal
	// ticker: a scheduler delay or a slow API cannot keep forwarding past it.
	go func() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-p.done:
			return
		case <-timer.C:
			p.mu.Lock()
			expired := !p.fenced && p.deadlineVersion == version && !time.Now().Before(p.authorityDeadline)
			p.mu.Unlock()
			if expired {
				p.trip()
			}
		}
	}()
}

func (p *fenceProxy) admitSource(remote net.Addr) bool {
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil || host == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fenced {
		return false
	}
	if p.clientIP == "" || host != p.clientIP {
		return false
	}
	if p.downstreamIP == "" {
		p.downstreamIP = host
		return true
	}
	return p.downstreamIP == host
}

func (p *fenceProxy) acceptLoop() {
	for {
		connection, err := p.listener.Accept()
		if err != nil {
			return
		}
		if !p.admitSource(connection.RemoteAddr()) {
			_ = connection.Close()
			continue
		}
		p.mu.Lock()
		if p.fenced {
			p.mu.Unlock()
			_ = connection.Close()
			continue
		}
		p.connections[connection] = struct{}{}
		p.mu.Unlock()
		go p.proxy(connection)
	}
}

func (p *fenceProxy) proxy(client net.Conn) {
	defer func() {
		p.mu.Lock()
		delete(p.connections, client)
		p.mu.Unlock()
		_ = client.Close()
	}()
	var interval *connectionInterval
	if p.lease != nil {
		interval = p.audit.begin(p.lease.validatorSet, p.lease.holder, p.lease.name)
	}
	result := "authority-expired"
	defer func() { interval.close(result) }()
	deadline, valid := p.connectionDeadline(time.Now())
	if !valid {
		return
	}
	_ = client.SetDeadline(deadline)
	upstream, err := (&net.Dialer{Timeout: p.dialTimeout}).Dial("tcp", p.upstreamAddress)
	if err != nil {
		result = "upstream-dial-failed"
		return
	}
	result = "closed"
	defer upstream.Close()
	_ = upstream.SetDeadline(deadline)
	copyDone := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); copyDone <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); copyDone <- struct{}{} }()
	<-copyDone
}

func (p *fenceProxy) connectionDeadline(now time.Time) (time.Time, bool) {
	p.mu.Lock()
	authorityDeadline := p.authorityDeadline
	p.mu.Unlock()
	deadline := now.Add(p.maxConnectionAge)
	if authorityDeadline.Before(deadline) {
		deadline = authorityDeadline
	}
	return deadline, now.Before(deadline)
}

func (p *fenceProxy) renewLoop(ctx context.Context) {
	ticker := time.NewTicker(p.lease.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.trip()
			return
		case <-ticker.C:
			authority, err := p.renewAuthority(ctx)
			if err != nil {
				p.trip()
				return
			}
			p.setAuthorityDeadline(authority.deadline)
		}
	}
}

func (p *fenceProxy) trip() {
	p.mu.Lock()
	if p.fenced {
		p.mu.Unlock()
		return
	}
	p.fenced = true
	listener := p.listener
	connections := make([]net.Conn, 0, len(p.connections))
	for connection := range p.connections {
		connections = append(connections, connection)
	}
	p.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	p.doneOnce.Do(func() { close(p.done) })
}

func (p *fenceProxy) close() { p.trip() }

func readToken(path string) func() ([]byte, error) {
	return func() ([]byte, error) {
		token, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimSpace(string(token))), nil
	}
}

func kubeHTTPClient(caPath string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caPath != "" {
		certificate, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certificate) {
			return nil, errors.New("invalid Kubernetes CA certificate")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &http.Client{Transport: transport}, nil
}

func validAuditField(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == ':') {
			return false
		}
	}
	return true
}

func main() {
	listen := flag.String("listen", ":9001", "TCP listen address for TLS passthrough")
	healthListen := flag.String("health-listen", ":9002", "HTTP health listen address")
	upstream := flag.String("upstream", "127.0.0.1:9000", "local Web3Signer TCP address")
	api := flag.String("kube-api", kubernetesAPIURL(), "Kubernetes HTTPS API base URL")
	namespace := flag.String("namespace", getenv("POD_NAMESPACE", "validator-operations"), "Lease namespace")
	leaseName := flag.String("lease-name", os.Getenv("FENCE_LEASE_NAME"), "exact Lease name")
	holder := flag.String("holder", os.Getenv("POD_UID"), "this Pod UID")
	validatorSet := flag.String("validator-set", os.Getenv("VALIDATOR_SET"), "validator set used to identify the one client Pod")
	clientPodName := flag.String("client-pod-name", os.Getenv("CLIENT_POD_NAME"), "exact validator client Pod name")
	tokenPath := flag.String("token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "projected service-account token")
	caPath := flag.String("ca-path", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "Kubernetes service CA")
	poll := flag.Duration("poll-interval", 10*time.Second, "Lease renewal interval")
	timeout := flag.Duration("request-timeout", 2*time.Second, "hard Kubernetes request deadline")
	safety := flag.Duration("safety-margin", 5*time.Second, "time reserved before Lease expiry")
	maxAge := flag.Duration("max-connection-age", 15*time.Second, "maximum accepted TCP connection lifetime")
	flag.Parse()
	expectedClientPodName := "validator-" + *validatorSet + "-client-0"
	if *leaseName == "" || *holder == "" || *validatorSet == "" || !validAuditField(*leaseName) || !validAuditField(*holder) || !validAuditField(*validatorSet) || *clientPodName != expectedClientPodName || *poll <= 0 || *timeout <= 0 || *safety <= 0 || *maxAge <= 0 {
		fatal(errors.New("lease name, Pod UID, validator set, exact client Pod name, and positive time bounds are required"))
	}
	if !strings.HasPrefix(*api, "https://") {
		fatal(errors.New("Kubernetes Lease API must use HTTPS"))
	}
	client, err := kubeHTTPClient(*caPath)
	if err != nil {
		fatal(fmt.Errorf("Kubernetes TLS client: %w", err))
	}
	lease := &leaseClient{apiBase: *api, namespace: *namespace, name: *leaseName, holder: *holder, validatorSet: *validatorSet, clientPodName: *clientPodName, pollInterval: *poll, safetyMargin: *safety, requestTimeout: *timeout, httpClient: client, token: readToken(*tokenPath), now: time.Now}
	proxy := newFenceProxy(lease, *listen, *upstream, *maxAge, *timeout)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := proxy.start(ctx); err != nil {
		fatal(fmt.Errorf("acquire signing fence: %w", err))
	}
	healthServer := &http.Server{Addr: *healthListen, ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if !proxy.healthy() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})}
	go func() {
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			proxy.trip()
		}
	}()
	defer healthServer.Close()
	select {
	case <-ctx.Done():
		proxy.close()
	case <-proxy.done:
		// The TCP listener has already closed, so a TCP readiness probe fails
		// immediately. Exit nonzero to force Pod replacement instead of waiting
		// for an unrelated process signal after a lease-fence loss.
		fmt.Fprintln(os.Stderr, "signing fence lost")
		os.Exit(1)
	}
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func kubernetesAPIURL() string {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return "https://kubernetes.default.svc"
	}
	return "https://" + net.JoinHostPort(host, getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443"))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
