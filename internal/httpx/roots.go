//     ▄▄ ▄▄ ▄▄  ▄▄▄▄  ▄▄▄▄ ▄▄    ▄▄▄▄▄ ▄▄▄▄
//     ██ ██ ██ ██ ▄▄ ██ ▄▄ ██    ██▄▄  ██▄█▄   Copyright (c) 2026 Julian Storer
//   ▄▄█▀ ▀███▀ ▀███▀ ▀███▀ ██▄▄▄ ██▄▄▄ ██ ██   AGPL-3.0-or-later - see LICENSE

package httpx

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
)

// envRoots is the trust store named by SSL_CERT_FILE and SSL_CERT_DIR, read once
// per process. Nil means neither is set and the system store applies.
var envRoots = sync.OnceValue(func() *x509.CertPool { return loadRootsFromEnv(os.Getenv) })

// loadRootsFromEnv builds a pool from the PEM file in SSL_CERT_FILE and every
// file in each SSL_CERT_DIR entry. It returns nil when both are unset. When
// either is set the pool replaces the system store even if nothing loads, so a
// bad path fails verification instead of silently trusting the system roots.
func loadRootsFromEnv(getenv func(string) string) *x509.CertPool {
	file, dirs := getenv("SSL_CERT_FILE"), getenv("SSL_CERT_DIR")
	if file == "" && dirs == "" {
		return nil
	}
	pool := x509.NewCertPool()
	if file != "" {
		appendPEMFile(pool, file)
	}
	for _, dir := range filepath.SplitList(dirs) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				appendPEMFile(pool, filepath.Join(dir, e.Name()))
			}
		}
	}
	return pool
}

func appendPEMFile(pool *x509.CertPool, path string) {
	if data, err := os.ReadFile(path); err == nil {
		pool.AppendCertsFromPEM(data)
	}
}
