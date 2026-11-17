package push

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestsPreserveKeysAcrossAttemptsAndResubmit(t *testing.T) {
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]string
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			t.Error(err)
		}
		b, _ := json.Marshal(v)
		bodies = append(bodies, b)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m := RequestManager{Root: t.TempDir(), URL: srv.URL}
	a, err := m.Create("operator@example.org", "US", "")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := m.Directory(a.ID)
	key, err := os.ReadFile(filepath.Join(dir, "push.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Submit(context.Background(), a.ID); err == nil {
		t.Fatal("503 accepted")
	}
	b, err := m.Create("operator@example.org", "US", "")
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == a.ID {
		t.Fatal("request identity reused")
	}
	// A new manager models process restart; it reuses the same persisted material.
	m2 := RequestManager{Root: m.Root, URL: srv.URL}
	if err = m2.Submit(context.Background(), a.ID); err == nil {
		t.Fatal("503 accepted")
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("resubmit changed CSR/encryption identity")
	}
	after, err := os.ReadFile(filepath.Join(dir, "push.key"))
	if err != nil || !bytes.Equal(after, key) {
		t.Fatal("original key overwritten")
	}
	for _, name := range []string{"push.key", "encrypt.key", "encrypt.crt", "push.csr", "request.json"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("%s permissions %o", name, fi.Mode().Perm())
		}
	}
	if _, err = m.Directory("../../escape"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestRequestTimeoutRetainsDecryptMaterial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(50 * time.Millisecond) }))
	defer srv.Close()
	m := RequestManager{Root: t.TempDir(), URL: srv.URL, Client: &http.Client{Timeout: time.Millisecond}}
	r, err := m.Create("operator@example.org", "US", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Submit(context.Background(), r.ID); err == nil {
		t.Fatal("timeout not surfaced")
	}
	if _, err = m.Load(r.ID); err != nil {
		t.Fatal("timed-out request lost")
	}
	dir, _ := m.Directory(r.ID)
	if _, _, err = loadEncryptionIdentity(dir); err != nil {
		t.Fatal("decryption material lost")
	}
}
