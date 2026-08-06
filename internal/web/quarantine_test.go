package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func TestQuarantineListsHeldIssuances(t *testing.T) {
	app, _, db := testApp(t)
	m := mux(app)
	cookies := login(t, m)

	// Seed a quarantined issuance.
	ctx := context.Background()
	_, hash := sqlite.NewGrantToken()
	gid, err := db.CreateGrant(ctx, sqlite.Grant{
		Label: "t", Platform: "macos", Owner: "u@x",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.BeginIssuance(ctx, gid, "txnZ", "spkiZ", "reqZ"); err != nil {
		t.Fatal(err)
	}
	if err := db.QuarantineIssuance(ctx, gid, "txnZ", "spkiZ", "reqZ", "ambiguous-ca-response", "external-scep", "catx"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/quarantine", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"ambiguous-ca-response", "txnZ", "external-scep"} {
		if !strings.Contains(body, want) {
			t.Errorf("quarantine page missing %q", want)
		}
	}
}
