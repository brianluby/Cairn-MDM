package main

import (
	"context"
	"testing"
)

func TestRenewRequiresSelectedTopic(t *testing.T) {
	if err := runPushcert(context.Background(), []string{"renew", "-cert", "missing", "-key", "missing"}); err == nil {
		t.Fatal("renew without topic accepted")
	}
}

func TestDecryptRequiresRequestSelection(t *testing.T) {
	if err := runPushcertDecrypt(context.Background(), []string{"-in", "missing"}); err == nil {
		t.Fatal("decrypt without request selection accepted")
	}
}
