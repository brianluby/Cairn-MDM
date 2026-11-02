package ldap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/config"
)

func TestStalledDirectoryHonorsLoginDeadline(t *testing.T) {
	for _, scheme := range []string{"ldaps", "ldap"} {
		t.Run(scheme, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					_, _ = io.Copy(io.Discard, conn)
				}
			}()
			p, err := New(config.LDAPCfg{Servers: []string{scheme + "://" + listener.Addr().String()}, StartTLS: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			start := time.Now()
			if _, err = p.Authenticate(ctx, "user", "password"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline: %v", err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("login exceeded cancellation budget")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("directory connection not closed")
			}
		})
	}
}

func TestProviderRefusesPlaintextWithoutStartTLS(t *testing.T) {
	p, err := New(config.LDAPCfg{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := p.dial(context.Background(), "ldap://127.0.0.1:389"); err == nil {
		conn.Close()
		t.Fatal("plaintext allowed")
	}
}
