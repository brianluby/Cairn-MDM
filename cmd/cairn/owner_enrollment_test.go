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

// A restore needs every secret file the config names, or the restored server
// does not start.
func TestBackupCarriesTheLookupSecretAndIngestToken(t *testing.T) {
	var cfg config.Config
	cfg.CA.External.Lookup.SecretFile = "/etc/cairn/scep-lookup-secret"
	cfg.RADIUS.IngestTokenFile = "/etc/cairn/radius-ingest-token"
	got := map[string]bool{}
	for _, f := range referencedFiles(cfg) {
		got[f] = true
	}
	for _, want := range []string{cfg.CA.External.Lookup.SecretFile, cfg.RADIUS.IngestTokenFile} {
		if !got[want] {
			t.Errorf("backup leaves out %s", want)
		}
	}
}
