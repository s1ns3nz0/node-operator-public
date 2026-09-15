// vault-audit-relay is a deliberately small, non-privileged sidecar for the
// Vault audit PVC. It forwards newline-delimited JSON from both the durable
// file device and the local Unix socket device to stdout for the existing node
// log collector. It never writes received audit records to stderr.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	maxAuditRecordBytes = 1024 * 1024
	retryDelay          = time.Second
)

func main() {
	filePath := flag.String("file-path", "/vault/audit/validator-audit.json", "Vault file audit device path")
	socketPath := flag.String("socket-path", "/vault/audit/validator-audit.sock", "Vault socket audit device path")
	flag.Parse()

	if err := validatePaths(*filePath, *socketPath); err != nil {
		fatal(err)
	}
	if err := removeStaleSocket(*socketPath); err != nil {
		fatal(err)
	}
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		fatal(fmt.Errorf("bind audit socket: %w", err))
	}
	defer func() { _ = listener.Close(); _ = os.Remove(*socketPath) }()
	if err := os.Chmod(*socketPath, 0o660); err != nil {
		fatal(fmt.Errorf("set audit socket mode: %w", err))
	}

	records := make(chan []byte, 128)
	go writeRecords(records)
	go tailFile(*filePath, records)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "audit socket accept failed: %v\n", err)
			time.Sleep(retryDelay)
			continue
		}
		go readRecords(connection, records)
	}
}

func validatePaths(filePath, socketPath string) error {
	if !filepath.IsAbs(filePath) || !filepath.IsAbs(socketPath) {
		return errors.New("audit paths must be absolute")
	}
	if filepath.Dir(filePath) != filepath.Dir(socketPath) {
		return errors.New("audit file and socket must share the dedicated audit directory")
	}
	return nil
}

func removeStaleSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect audit socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %q", socketPath)
	}
	return os.Remove(socketPath)
}

func tailFile(filePath string, records chan<- []byte) {
	for {
		file, err := os.Open(filePath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "audit file open failed: %v\n", err)
			}
			time.Sleep(retryDelay)
			continue
		}
		// Existing file records were already delivered before the relay restart.
		// Start at EOF; newly appended audit records are the only file input.
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			_ = file.Close()
			fmt.Fprintf(os.Stderr, "audit file seek failed: %v\n", err)
			time.Sleep(retryDelay)
			continue
		}
		followFile(file, records)
		_ = file.Close()
	}
}

func followFile(file *os.File, records chan<- []byte) {
	reader := bufio.NewReaderSize(file, maxAuditRecordBytes)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			fmt.Fprintln(os.Stderr, "discarded oversized Vault audit record")
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = reader.ReadSlice('\n')
			}
			continue
		}
		if len(line) > 0 && err == nil {
			emitRecord(line[:len(line)-1], "file", records)
		}
		if errors.Is(err, io.EOF) {
			// Keep this descriptor open. Closing and seeking EOF again can miss a
			// record appended between the two operations.
			time.Sleep(retryDelay)
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit file read failed: %v\n", err)
		}
		return
	}
}

func readRecords(reader io.ReadCloser, records chan<- []byte) {
	defer func() { _ = reader.Close() }()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxAuditRecordBytes)
	for scanner.Scan() {
		emitRecord(scanner.Bytes(), "socket", records)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "audit record read failed: %v\n", err)
	}
}

func emitRecord(line []byte, source string, records chan<- []byte) {
	if source != "socket" && source != "file" {
		fmt.Fprintln(os.Stderr, "discarded unknown Vault audit source")
		return
	}
	if !json.Valid(line) {
		fmt.Fprintln(os.Stderr, "discarded non-JSON Vault audit record")
		return
	}
	// Provenance belongs to the input path, never to a field supplied by Vault.
	// Distinct devices have distinct HMAC salts for the same request ID.
	// Preserve both streams, but let consumers select one device for pairing.
	envelope := struct {
		SchemaVersion int    `json:"schema_version"`
		AuditSource   string `json:"audit_source"`
		Log           string `json:"log"`
	}{1, source, string(line)}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "discarded unencodable Vault audit envelope")
		return
	}
	records <- encoded
}

func writeRecords(records <-chan []byte) {
	for record := range records {
		// A single writer prevents concurrent socket connections from interleaving
		// JSON lines. Vault's configured devices keep fields HMAC-redacted.
		_, _ = os.Stdout.Write(append(record, '\n'))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
