package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLeaseAPI struct {
	mu         sync.Mutex
	lease      leaseDocument
	patches    [][]map[string]string
	conflict   bool
	hang       bool
	podHang    bool
	race       bool
	pod        podDocument
	podPath    string
	patchCount int
}

func testLease(holder string, renewed time.Time) leaseDocument {
	var lease leaseDocument
	lease.Metadata.ResourceVersion = "7"
	lease.Spec.HolderIdentity = holder
	duration := int64(30)
	lease.Spec.LeaseDurationSeconds = &duration
	if !renewed.IsZero() {
		lease.Spec.RenewTime = renewed.UTC().Format(time.RFC3339Nano)
	}
	return lease
}

func testClientPod(uid, ip string) podDocument {
	var pod podDocument
	pod.Metadata.UID = uid
	pod.Metadata.Labels = map[string]string{
		"app.kubernetes.io/component":    "validator-client",
		"node-operator.io/validator-set": "hoodi-example",
	}
	pod.Status.Phase = "Running"
	pod.Status.PodIP = ip
	return pod
}

func (f *fakeLeaseAPI) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.Contains(request.URL.Path, "/pods/") {
		if f.podHang {
			<-request.Context().Done()
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.podPath = request.URL.Path
		_ = json.NewEncoder(writer).Encode(f.pod)
		return
	}
	if f.hang {
		<-request.Context().Done()
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch request.Method {
	case http.MethodGet:
		_ = json.NewEncoder(writer).Encode(f.lease)
	case http.MethodPatch:
		if f.conflict {
			writer.WriteHeader(http.StatusConflict)
			return
		}
		var patch []map[string]string
		if err := json.NewDecoder(request.Body).Decode(&patch); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if f.race {
			f.lease.Metadata.ResourceVersion = "raced"
			f.race = false
		}
		for _, operation := range patch {
			if operation["op"] != "test" {
				continue
			}
			matches := false
			switch operation["path"] {
			case "/metadata/resourceVersion":
				matches = operation["value"] == f.lease.Metadata.ResourceVersion
			case "/spec/holderIdentity":
				matches = operation["value"] == f.lease.Spec.HolderIdentity
			}
			if !matches {
				writer.WriteHeader(http.StatusConflict)
				return
			}
		}
		f.patches = append(f.patches, patch)
		// Match Kubernetes MicroTime decoding, not permissive RFC3339Nano.
		for _, operation := range patch {
			if operation["path"] == "/spec/renewTime" {
				if _, err := time.Parse("2006-01-02T15:04:05.000000Z07:00", operation["value"]); err != nil {
					writer.WriteHeader(http.StatusUnprocessableEntity)
					return
				}
			}
		}
		for _, operation := range patch {
			switch operation["path"] {
			case "/spec/holderIdentity":
				if operation["op"] == "replace" {
					f.lease.Spec.HolderIdentity = operation["value"]
				}
			case "/spec/renewTime":
				if operation["op"] == "add" {
					f.lease.Spec.RenewTime = operation["value"]
				}
			}
		}
		f.patchCount++
		f.lease.Metadata.ResourceVersion = string(rune('8' + f.patchCount - 1))
		_ = json.NewEncoder(writer).Encode(f.lease)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newTestClient(server *httptest.Server, now time.Time) *leaseClient {
	return &leaseClient{
		apiBase: server.URL, namespace: "validator-operations", name: "validator-hoodi-example-primary", holder: "pod-uid-1", validatorSet: "hoodi-example", clientPodName: "validator-hoodi-example-client-0",
		pollInterval: 5 * time.Second, safetyMargin: 2 * time.Second, requestTimeout: 100 * time.Millisecond,
		httpClient: server.Client(), token: func() ([]byte, error) { return []byte("synthetic-token"), nil }, now: func() time.Time { return now },
	}
}

func TestEmptyLeaseBootstrapsWithCAS(t *testing.T) {
	now := time.Date(2026, 9, 8, 5, 0, 0, 123456789, time.UTC)
	fake := &fakeLeaseAPI{lease: testLease("", time.Time{})}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	if _, err := newTestClient(server, now).acquireOrRenew(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if fake.lease.Spec.HolderIdentity != "pod-uid-1" || fake.patchCount != 1 {
		t.Fatal("empty Lease was not acquired exactly once")
	}
	if len(fake.patches[0]) < 4 || fake.patches[0][0]["op"] != "test" || fake.patches[0][1]["value"] != "" {
		t.Fatal("bootstrap patch lacks resourceVersion and empty-holder CAS tests")
	}
	if got := fake.lease.Spec.RenewTime; got != "2026-09-08T05:00:00.123456Z" {
		t.Fatalf("renewTime is not canonical Kubernetes MicroTime: %q", got)
	}
}

func TestRenewTimePreservesAllTrailingMicrosecondZeroes(t *testing.T) {
	for _, nanos := range []int{0, 100000000, 120000000, 123000000, 123400000, 123450000, 101150000, 123456000, 123456789} {
		now := time.Date(2026, 9, 9, 14, 26, 33, nanos, time.UTC)
		fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now)}
		server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
		_, err := newTestClient(server, now).acquireOrRenew(context.Background())
		server.Close()
		if err != nil {
			t.Fatalf("nanos=%d renewal rejected: %v", nanos, err)
		}
		want := now.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z07:00")
		if fake.lease.Spec.RenewTime != want {
			t.Fatalf("nanos=%d expected %s got %s", nanos, want, fake.lease.Spec.RenewTime)
		}
	}
}

func TestCurrentHolderRenewsWithoutTakeover(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-pod-uid", "127.0.0.1")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	if _, err := newTestClient(server, now).acquireOrRenew(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	for _, operation := range fake.patches[0] {
		if operation["path"] == "/spec/holderIdentity" && operation["op"] == "replace" {
			t.Fatal("current holder should not replace holder identity")
		}
	}
}

func TestExpiredPriorHolderMayBeAcquiredButLiveHolderMayNot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expired := &fakeLeaseAPI{lease: testLease("prior-pod", now.Add(-31*time.Second))}
	expiredServer := httptest.NewServer(http.HandlerFunc(expired.serveHTTP))
	defer expiredServer.Close()
	if _, err := newTestClient(expiredServer, now).acquireOrRenew(context.Background()); err != nil {
		t.Fatalf("expired holder should be safely acquired: %v", err)
	}
	live := &fakeLeaseAPI{lease: testLease("other-live-pod", now)}
	liveServer := httptest.NewServer(http.HandlerFunc(live.serveHTTP))
	defer liveServer.Close()
	if _, err := newTestClient(liveServer, now).acquireOrRenew(context.Background()); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("live second holder error = %v", err)
	}
	if live.patchCount != 0 {
		t.Fatal("live holder must not be patched")
	}
}

func TestFutureLeaseAndConflictFailClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	future := &fakeLeaseAPI{lease: testLease("pod-uid-1", now.Add(time.Minute))}
	futureServer := httptest.NewServer(http.HandlerFunc(future.serveHTTP))
	defer futureServer.Close()
	if _, err := newTestClient(futureServer, now).acquireOrRenew(context.Background()); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("future lease error = %v", err)
	}
	conflict := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), conflict: true}
	conflictServer := httptest.NewServer(http.HandlerFunc(conflict.serveHTTP))
	defer conflictServer.Close()
	if _, err := newTestClient(conflictServer, now).acquireOrRenew(context.Background()); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestRacingResourceVersionCASFailsClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), race: true}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	if _, err := newTestClient(server, now).acquireOrRenew(context.Background()); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("racing resourceVersion error = %v", err)
	}
}

func TestOwnExpiredHolderCannotSilentlyResume(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now.Add(-31*time.Second))}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	if _, err := newTestClient(server, now).acquireOrRenew(context.Background()); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("own expired holder error = %v", err)
	}
	if fake.patchCount != 0 {
		t.Fatal("expired own holder must not be renewed")
	}
}

func TestKubernetesAPIHangHonorsDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{hang: true}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	client := newTestClient(server, now)
	client.requestTimeout = 25 * time.Millisecond
	started := time.Now()
	if _, err := client.acquireOrRenew(context.Background()); err == nil {
		t.Fatal("hung API unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("hung API exceeded hard deadline: %s", elapsed)
	}
}

func TestClientPodIdentityIsPinnedToTheExactSetScopedPod(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-uid-a", "192.0.2.10")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	proxy := newFenceProxy(newTestClient(server, now), "", "", time.Second, time.Second)
	if _, err := proxy.renewAuthority(context.Background()); err != nil {
		t.Fatalf("initial client Pod proof: %v", err)
	}
	fake.mu.Lock()
	path := fake.podPath
	fake.mu.Unlock()
	if path != "/api/v1/namespaces/validator-operations/pods/validator-hoodi-example-client-0" {
		t.Fatalf("client Pod endpoint = %q", path)
	}
	if proxy.clientUID != "client-uid-a" || proxy.clientIP != "192.0.2.10" {
		t.Fatal("validated client identity was not pinned")
	}
}

func TestClientPodUIDChangeWithReusedIPFailsClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-uid-a", "192.0.2.10")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	proxy := newFenceProxy(newTestClient(server, now), "", "", time.Second, time.Second)
	if _, err := proxy.renewAuthority(context.Background()); err != nil {
		t.Fatalf("initial client Pod proof: %v", err)
	}
	fake.mu.Lock()
	fake.pod.Metadata.UID = "client-uid-b" // An IP reused by a new Pod is not the pinned client.
	fake.mu.Unlock()
	if _, err := proxy.renewAuthority(context.Background()); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("reused IP with changed UID error = %v", err)
	}
}

func TestClientPodIPChangeFailsClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-uid-a", "192.0.2.10")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	proxy := newFenceProxy(newTestClient(server, now), "", "", time.Second, time.Second)
	if _, err := proxy.renewAuthority(context.Background()); err != nil {
		t.Fatalf("initial client Pod proof: %v", err)
	}
	fake.mu.Lock()
	fake.pod.Status.PodIP = "192.0.2.11"
	fake.mu.Unlock()
	if _, err := proxy.renewAuthority(context.Background()); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("changed client IP error = %v", err)
	}
}

func TestInvalidClientPodStateBlocksLeaseRenewal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deletion := time.Now().UTC().Format(time.RFC3339Nano)
	cases := []struct {
		name   string
		mutate func(*podDocument)
	}{
		{"deleting", func(pod *podDocument) { pod.Metadata.DeletionTimestamp = &deletion }},
		{"wrong-label", func(pod *podDocument) { pod.Metadata.Labels["node-operator.io/validator-set"] = "other" }},
		{"not-running", func(pod *podDocument) { pod.Status.Phase = "Pending" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			pod := testClientPod("client-uid-a", "192.0.2.10")
			test.mutate(&pod)
			fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: pod}
			server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
			defer server.Close()
			proxy := newFenceProxy(newTestClient(server, now), "", "", time.Second, time.Second)
			if _, err := proxy.renewAuthority(context.Background()); !errors.Is(err, ErrInvalidLease) {
				t.Fatalf("invalid client Pod error = %v", err)
			}
			fake.mu.Lock()
			patchCount := fake.patchCount
			fake.mu.Unlock()
			if patchCount != 0 {
				t.Fatal("invalid client Pod must block Lease PATCH")
			}
		})
	}
}

func TestClientPodAPIHangHonorsDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-uid-a", "192.0.2.10"), podHang: true}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	lease := newTestClient(server, now)
	lease.requestTimeout = 25 * time.Millisecond
	proxy := newFenceProxy(lease, "", "", time.Second, time.Second)
	started := time.Now()
	if _, err := proxy.renewAuthority(context.Background()); err == nil {
		t.Fatal("hung client Pod API unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("hung client Pod API exceeded hard deadline: %s", elapsed)
	}
}

func TestClientPodChangeTripsFenceDuringRenewal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-uid-a", "127.0.0.1")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	lease := newTestClient(server, now)
	lease.pollInterval = 20 * time.Millisecond
	lease.requestTimeout = 50 * time.Millisecond
	proxy := newFenceProxy(lease, "127.0.0.1:0", "127.0.0.1:1", time.Second, time.Second)
	if err := proxy.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	fake.mu.Lock()
	fake.pod.Status.PodIP = "127.0.0.2"
	fake.mu.Unlock()
	select {
	case <-proxy.done:
	case <-time.After(time.Second):
		t.Fatal("client Pod identity change did not trip the fence")
	}
}

func TestFenceLossClosesActiveTLSStream(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-pod-uid", "127.0.0.1")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamAccepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := upstream.Accept()
		if acceptErr == nil {
			upstreamAccepted <- connection
		}
	}()
	lease := newTestClient(server, now)
	lease.pollInterval = 20 * time.Millisecond
	lease.requestTimeout = 50 * time.Millisecond
	proxy := newFenceProxy(lease, "127.0.0.1:0", upstream.Addr().String(), time.Second, 50*time.Millisecond)
	if err := proxy.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	client, err := net.Dial("tcp", proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case connection := <-upstreamAccepted:
		defer connection.Close()
	case <-time.After(time.Second):
		t.Fatal("proxy did not connect to upstream")
	}
	fake.mu.Lock()
	fake.conflict = true
	fake.mu.Unlock()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("active passthrough connection remained open after fence loss")
	}
	select {
	case <-proxy.done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not trip after renewal conflict")
	}
}

func TestConnectionAgeIsCappedByLeaseSafetyWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-pod-uid", "127.0.0.1")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	lease := newTestClient(server, now)
	proxy := newFenceProxy(lease, "127.0.0.1:0", "127.0.0.1:1", time.Hour, 50*time.Millisecond)
	if err := proxy.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	if limit := 30*time.Second - lease.safetyMargin; proxy.maxConnectionAge > limit {
		t.Fatalf("connection age %s exceeds lease safety window %s", proxy.maxConnectionAge, limit)
	}
}

func TestConnectionDeadlineUsesRemainingLeaseAuthority(t *testing.T) {
	now := time.Now()
	p := newFenceProxy(nil, "", "", time.Hour, time.Second)
	p.authorityDeadline = now.Add(100 * time.Millisecond)
	deadline, valid := p.connectionDeadline(now)
	if !valid || !deadline.Equal(p.authorityDeadline) {
		t.Fatal("connection was granted a full lifetime instead of remaining Lease authority")
	}
}

func TestAuthorityWatchdogTripsWithoutRenewalTick(t *testing.T) {
	p := newFenceProxy(nil, "", "", time.Second, time.Second)
	p.setAuthorityDeadline(time.Now().Add(25 * time.Millisecond))
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("absolute authority watchdog did not trip independently of renewal")
	}
}

func TestOnlyOneDownstreamSourceIPIsAdmitted(t *testing.T) {
	p := newFenceProxy(nil, "", "", time.Second, time.Second)
	p.clientIP = "192.0.2.10"
	first := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9000}
	sameIP := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9001}
	second := &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 9000}
	if !p.admitSource(first) || !p.admitSource(sameIP) {
		t.Fatal("multiple connections from the first source IP must be admitted")
	}
	if p.admitSource(second) {
		t.Fatal("a second downstream source IP was admitted")
	}
}

func waitForFenceReceipts(t *testing.T, output *bytes.Buffer, count int) []string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		lines := strings.FieldsFunc(strings.TrimSpace(output.String()), func(r rune) bool { return r == '\n' })
		if len(lines) >= count {
			return lines
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected %d fence connection receipts, got %q", count, output.String())
	return nil
}

func receiptFields(t *testing.T, line string) map[string]string {
	t.Helper()
	parts := strings.Fields(line)
	if len(parts) != 10 || parts[0] != "fence_connection" {
		t.Fatalf("unexpected fence receipt: %q", line)
	}
	fields := make(map[string]string, len(parts)-1)
	for _, part := range parts[1:] {
		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 || pair[0] == "" || pair[1] == "" {
			t.Fatalf("malformed fence receipt token %q", part)
		}
		if _, exists := fields[pair[0]]; exists {
			t.Fatalf("duplicate fence receipt token %q", pair[0])
		}
		fields[pair[0]] = pair[1]
	}
	return fields
}

func TestFenceConnectionReceiptCapturesOnlySuccessfulUpstreamInterval(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-pod-uid", "127.0.0.1")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	output := &bytes.Buffer{}
	upstream := echoUpstream(t)
	lease := newTestClient(server, now)
	proxy := newFenceProxy(lease, "127.0.0.1:0", upstream.Addr().String(), time.Second, 50*time.Millisecond)
	proxy.audit = newConnectionAudit(output, time.Now)
	if err := proxy.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	client := openProvenStream(t, proxy.address())
	_ = client.Close()
	fields := receiptFields(t, waitForFenceReceipts(t, output, 1)[0])
	if fields["validator_set"] != "hoodi-example" || fields["holder"] != "pod-uid-1" || fields["lease"] != "validator-hoodi-example-primary" || fields["result"] != "closed" {
		t.Fatalf("receipt omitted accepted lease identity or upstream success: %#v", fields)
	}
	if fields["connection_id"] == "" || strings.Contains(output.String(), "127.0.0.1") || strings.Contains(output.String(), "payload=") || strings.Contains(output.String(), "certificate=") {
		t.Fatalf("receipt leaked connection metadata or omitted connection identity: %q", output.String())
	}
	opened, openErr := time.Parse(time.RFC3339Nano, fields["opened_at_utc"])
	closed, closeErr := time.Parse(time.RFC3339Nano, fields["closed_at_utc"])
	if openErr != nil || closeErr != nil || closed.Before(opened) || fields["opened_at_ms"] == "" || fields["closed_at_ms"] == "" {
		t.Fatalf("receipt interval is not valid UTC timing: %#v", fields)
	}
}

func TestFenceConnectionReceiptMarksDialFailureWithoutClaimingClosure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-pod-uid", "127.0.0.1")}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	output := &bytes.Buffer{}
	lease := newTestClient(server, now)
	proxy := newFenceProxy(lease, "127.0.0.1:0", "127.0.0.1:1", time.Second, 50*time.Millisecond)
	proxy.audit = newConnectionAudit(output, time.Now)
	if err := proxy.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	client, err := net.DialTimeout("tcp", proxy.address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	fields := receiptFields(t, waitForFenceReceipts(t, output, 1)[0])
	if fields["result"] != "upstream-dial-failed" {
		t.Fatalf("failed upstream dial was falsely usable for temporal correlation: %#v", fields)
	}
}

func TestFenceConnectionReceiptWritesAreConcurrentAndLineAtomic(t *testing.T) {
	output := &bytes.Buffer{}
	audit := newConnectionAudit(output, time.Now)
	const connections = 32
	var group sync.WaitGroup
	group.Add(connections)
	for range connections {
		go func() {
			defer group.Done()
			audit.begin("hoodi-example", "pod-uid-1", "validator-hoodi-example-primary").close("closed")
		}()
	}
	group.Wait()
	lines := waitForFenceReceipts(t, output, connections)
	if len(lines) != connections {
		t.Fatalf("interleaved or missing concurrent receipts: %q", output.String())
	}
	ids := map[string]bool{}
	for _, line := range lines {
		fields := receiptFields(t, line)
		if fields["result"] != "closed" || ids[fields["connection_id"]] {
			t.Fatalf("concurrent receipt lost result or identity uniqueness: %#v", fields)
		}
		ids[fields["connection_id"]] = true
	}
}

// A timeout on the test's own socket is not evidence of fence closure.
func requirePeerClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("connection still forwarded data")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("observation timed out instead of observing peer closure")
	}
}

func echoUpstream(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l
}

func openProvenStream(t *testing.T, address string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("positive passthrough failed: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	return c
}

func TestAuthorityExpiryClosesProvenActiveStream(t *testing.T) {
	u := echoUpstream(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newFenceProxy(nil, "", u.Addr().String(), time.Hour, time.Second)
	p.listener = l
	p.clientIP = "127.0.0.1"
	p.setAuthorityDeadline(time.Now().Add(250 * time.Millisecond))
	defer p.close()
	go p.acceptLoop()
	c := openProvenStream(t, l.Addr().String())
	requirePeerClosed(t, c)
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("expiry did not trip authority watchdog")
	}
	if p.healthy() {
		t.Fatal("expired fence remained healthy")
	}
	newConn, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err == nil {
		newConn.Close()
		t.Fatal("expired listener accepted new connection")
	}
}

func TestAPIEOFAndResetCloseProvenActiveStream(t *testing.T) {
	for _, reset := range []bool{false, true} {
		name := "EOF"
		if reset {
			name = "RST"
		}
		t.Run(name, func(t *testing.T) {
			var fault atomic.Bool
			now := time.Now().UTC()
			fake := &fakeLeaseAPI{lease: testLease("pod-uid-1", now), pod: testClientPod("client-pod-uid", "127.0.0.1")}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !fault.Load() {
					fake.serveHTTP(w, r)
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				if reset {
					_ = conn.(*net.TCPConn).SetLinger(0)
				}
				_ = conn.Close()
			}))
			defer server.Close()
			lease := newTestClient(server, now)
			lease.pollInterval = 20 * time.Millisecond
			u := echoUpstream(t)
			p := newFenceProxy(lease, "127.0.0.1:0", u.Addr().String(), time.Hour, time.Second)
			if err := p.start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer p.close()
			c := openProvenStream(t, p.address())
			fault.Store(true)
			requirePeerClosed(t, c)
			select {
			case <-p.done:
			case <-time.After(time.Second):
				t.Fatal("API transport loss did not trip fence")
			}
			if p.healthy() {
				t.Fatal("fence remained healthy after API transport loss")
			}
		})
	}
}
