package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidatePaths(t *testing.T) {
	for _, test := range []struct {
		file, socket string
		valid        bool
	}{
		{"/vault/audit/audit.json", "/vault/audit/audit.sock", true},
		{"relative/audit.json", "/vault/audit/audit.sock", false},
		{"/vault/audit/audit.json", "/other/audit.sock", false},
	} {
		if got := validatePaths(test.file, test.socket) == nil; got != test.valid {
			t.Fatalf("validatePaths(%q, %q) valid=%v, want %v", test.file, test.socket, got, test.valid)
		}
	}
}

func TestRemoveStaleSocketAndRejectRegularFile(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "audit-relay-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socketPath := filepath.Join(directory, "audit.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSocket(socketPath); err != nil {
		t.Fatalf("remove stale socket: %v", err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("stale socket still exists or cannot be checked: %v", err)
	}
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSocket(socketPath); err == nil {
		t.Fatal("removeStaleSocket accepted a regular file")
	}
}

func TestEmitRecordRejectsNonJSONAndCopiesValidJSON(t *testing.T) {
	records := make(chan []byte, 1)
	emitRecord([]byte("not-json"), "socket", records)
	select {
	case record := <-records:
		t.Fatalf("non-JSON record emitted: %q", record)
	default:
	}
	input := []byte(`{"type":"audit","request":{"id":"safe"}}`)
	emitRecord(input, "socket", records)
	for index := range input {
		input[index] = 'x'
	}
	select {
	case record := <-records:
		var envelope struct {
			SchemaVersion int    `json:"schema_version"`
			AuditSource   string `json:"audit_source"`
			Log           string `json:"log"`
		}
		if err := json.Unmarshal(record, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.SchemaVersion != 1 || envelope.AuditSource != "socket" || envelope.Log != `{"type":"audit","request":{"id":"safe"}}` {
			t.Fatalf("valid JSON was not copied before enqueue: %q", record)
		}
	case <-time.After(time.Second):
		t.Fatal("valid JSON was not emitted")
	}
}

func TestProvenanceCannotBeSuppliedByRecord(t *testing.T) {
	for _, source := range []string{"file", "socket"} {
		records := make(chan []byte, 1)
		emitRecord([]byte(`{"audit_source":"spoofed","type":"request"}`), source, records)
		var envelope map[string]interface{}
		if err := json.Unmarshal(<-records, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope["audit_source"] != source {
			t.Fatal("input changed provenance")
		}
	}
	records := make(chan []byte, 1)
	emitRecord([]byte(`{}`), "unknown", records)
	if len(records) != 0 {
		t.Fatal("unknown provenance accepted")
	}
}

func TestSocketReaderLabelsActualInput(t *testing.T) {
	records := make(chan []byte, 1)
	readRecords(io.NopCloser(strings.NewReader("{\"type\":\"request\"}\n")), records)
	var envelope map[string]interface{}
	if err := json.Unmarshal(<-records, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["audit_source"] != "socket" {
		t.Fatal("socket input mislabeled")
	}
}

func TestFileFollowerLabelsActualInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(path, []byte("{\"type\":\"request\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records := make(chan []byte, 1)
	done := make(chan struct{})
	go func() { followFile(file, records); close(done) }()
	select {
	case record := <-records:
		var envelope map[string]interface{}
		if err := json.Unmarshal(record, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope["audit_source"] != "file" {
			t.Fatal("file input mislabeled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("file record unavailable")
	}
	file.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("file follower did not stop after close")
	}
}
