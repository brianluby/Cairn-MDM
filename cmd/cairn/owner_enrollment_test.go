package main

import (
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/config"
)

func TestEnrollmentLinksNeedACAThatAsksCairn(t *testing.T) {
	external := config.CA{Mode: config.CAExternal}
	if ownerEnrollment(external) {
		t.Fatal("links are on for an external CA with a shared challenge")
	}
	external.External.Lookup.Enabled = true
	if !ownerEnrollment(external) {
		t.Fatal("links are off for an external CA that looks up one-time challenges")
	}
	if !ownerEnrollment(config.CA{Mode: config.CABroker}) {
		t.Fatal("links are off in broker mode")
	}
}
