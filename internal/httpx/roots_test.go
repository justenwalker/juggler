//     ▄▄ ▄▄ ▄▄  ▄▄▄▄  ▄▄▄▄ ▄▄    ▄▄▄▄▄ ▄▄▄▄
//     ██ ██ ██ ██ ▄▄ ██ ▄▄ ██    ██▄▄  ██▄█▄   Copyright (c) 2026 Julian Storer
//   ▄▄█▀ ▀███▀ ▀███▀ ▀███▀ ██▄▄▄ ██▄▄▄ ██ ██   AGPL-3.0-or-later - see LICENSE

package httpx

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeServerCA writes srv's self-signed certificate as PEM to dir/name.
func writeServerCA(t *testing.T, srv *httptest.Server, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return path
}

// TestEnvRootsGovernVerification: SSL_CERT_FILE and SSL_CERT_DIR name the only
// roots trusted, and a set variable that loads nothing fails verification
// rather than falling back to the system store.
func TestEnvRootsGovernVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	caDir := t.TempDir()
	caFile := writeServerCA(t, srv, caDir, "ca.pem")
	emptyFile := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	tests := []struct {
		name   string
		env    map[string]string
		wantOK bool
	}{
		{name: "unset uses system store", env: nil, wantOK: false},
		{name: "file trusts its CA", env: map[string]string{"SSL_CERT_FILE": caFile}, wantOK: true},
		{name: "dir list trusts its CA", env: map[string]string{"SSL_CERT_DIR": filepath.Join(t.TempDir(), "missing") + string(filepath.ListSeparator) + caDir}, wantOK: true},
		{name: "empty file fails", env: map[string]string{"SSL_CERT_FILE": emptyFile}, wantOK: false},
		{name: "missing dir fails", env: map[string]string{"SSL_CERT_DIR": filepath.Join(t.TempDir(), "missing")}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roots := loadRootsFromEnv(func(k string) string { return tt.env[k] })
			if (roots == nil) != (tt.env == nil) {
				t.Fatalf("roots nil = %v, want %v", roots == nil, tt.env == nil)
			}
			client := &http.Client{Transport: transportWithRoots(roots)}
			resp, err := client.Get(srv.URL)
			if err == nil {
				_ = resp.Body.Close()
			}
			if tt.wantOK && err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !tt.wantOK && (err == nil || !strings.Contains(err.Error(), "certificate")) {
				t.Fatalf("Get err = %v, want a certificate verification failure", err)
			}
		})
	}
}
