package enroll

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/micromdm/plist"
)

type fakeTopics map[string]string

func (f fakeTopics) GetSetting(_ context.Context, key string) (string, error) {
	return f[key], nil
}

// fakeRedeemer accepts one token and returns a fixed redemption.
type fakeRedeemer struct {
	token string
	red   Redemption
}

func (f fakeRedeemer) RedeemGrant(_ context.Context, raw string) (Redemption, error) {
	if raw == f.token {
		return f.red, nil
	}
	return Redemption{}, errors.New("invalid")
}

func testHandler(topics fakeTopics, open bool, redeemer Redeemer) *Handler {
	return New(Config{
		Organization:  "cairn.example.com",
		CAAnchorsDER:  [][]byte{[]byte("der")},
		SCEPURL:       "https://mdm.example.com/scep",
		MDMServerURL:  "https://mdm.example.com/mdm",
		SubjectPrefix: "devices.example.com",
		AllowOpen:     open,
	}, topics, redeemer, "apns_topic", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestBareEnrollDeniedByDefault(t *testing.T) {
	h := testHandler(fakeTopics{"apns_topic": "com.apple.mgmt.External.abc"}, false, nil)
	rr := httptest.NewRecorder()
	h.ServeOpen(rr, httptest.NewRequest(http.MethodGet, "/enroll", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("bare /enroll = %d, want 404 when not opened", rr.Code)
	}
}

func TestBareEnrollWhenOpen(t *testing.T) {
	// No topic → 503.
	h := testHandler(fakeTopics{}, true, nil)
	rr := httptest.NewRecorder()
	h.ServeOpen(rr, httptest.NewRequest(http.MethodGet, "/enroll", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("open /enroll no cert = %d, want 503", rr.Code)
	}

	// With topic → 200, per-device CN, no owner SAN.
	h = testHandler(fakeTopics{"apns_topic": "com.apple.mgmt.External.abc"}, true, nil)
	rr = httptest.NewRecorder()
	h.ServeOpen(rr, httptest.NewRequest(http.MethodGet, "/enroll", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("open /enroll = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "%SerialNumber%.devices.example.com") {
		t.Error("profile missing per-device %SerialNumber% CN")
	}
	if strings.Contains(body, "rfc822Name") {
		t.Error("unbound profile should have no owner SAN")
	}
}

func TestGrantRoute(t *testing.T) {
	topic := "com.apple.mgmt.External.abc"
	rd := fakeRedeemer{token: "good-token", red: Redemption{Owner: "nick@dzsec.net", Platform: "macos"}}
	h := testHandler(fakeTopics{"apns_topic": topic}, false, rd)

	// Valid grant → 200 with the owner bound as a SAN.
	req := httptest.NewRequest(http.MethodPost, "/e/good-token", nil)
	req.SetPathValue("token", "good-token")
	rr := httptest.NewRecorder()
	h.ServeGrant(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid grant = %d, want 200", rr.Code)
	}
	var prof map[string]any
	if err := plist.Unmarshal(rr.Body.Bytes(), &prof); err != nil {
		t.Fatalf("body not a valid plist: %v", err)
	}
	body := rr.Body.String()
	if !strings.Contains(body, topic) {
		t.Error("profile missing APNs topic")
	}
	if !strings.Contains(body, "nick@dzsec.net") || !strings.Contains(body, "rfc822Name") {
		t.Error("profile missing owner rfc822 SAN")
	}

	// Invalid/used token → 410 Gone.
	req = httptest.NewRequest(http.MethodPost, "/e/bad", nil)
	req.SetPathValue("token", "bad")
	rr = httptest.NewRecorder()
	h.ServeGrant(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("invalid grant = %d, want 410", rr.Code)
	}
}

type countedRedeemer struct{ calls int }

func (c *countedRedeemer) RedeemGrant(context.Context, string) (Redemption, error) {
	c.calls++
	return Redemption{Owner: "person@example.org"}, nil
}
func TestInvitationPreviewDoesNotConsumeGrant(t *testing.T) {
	rd := &countedRedeemer{}
	h := testHandler(fakeTopics{}, false, rd)
	req := httptest.NewRequest("GET", "/e/token", nil)
	req.SetPathValue("token", "token")
	rr := httptest.NewRecorder()
	h.ServeGrant(rr, req)
	if rr.Code != 200 || rd.calls != 0 || !strings.Contains(rr.Body.String(), "Download enrollment profile") || rr.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("GET spent grant or missed instructions")
	}
	req = httptest.NewRequest("POST", "/e/token", nil)
	req.SetPathValue("token", "token")
	rr = httptest.NewRecorder()
	h.ServeGrant(rr, req)
	if rr.Code != 503 || rd.calls != 0 {
		t.Fatal("unready server spent grant")
	}
	h = testHandler(fakeTopics{"apns_topic": "topic"}, false, rd)
	rr = httptest.NewRecorder()
	h.ServeGrant(rr, req)
	if rr.Code != 200 || rd.calls != 1 || !strings.Contains(rr.Header().Get("Content-Type"), "apple-aspen") {
		t.Fatal("explicit download failed")
	}
}

// With a challenge minter, each profile carries its own challenge and the
// static one is not used. A grant that fixes the serial number fixes the
// certificate name the challenge is good for.
func TestProfileCarriesAMintedChallenge(t *testing.T) {
	for _, c := range []struct{ serial, wantName string }{
		{"", ""},
		{"C02ABC", "C02ABC.devices.example.com"},
	} {
		var gotName, gotSuffix, gotOwner string
		h := New(Config{
			Organization: "cairn.example.com", CAAnchorsDER: [][]byte{[]byte("der")}, SCEPURL: "https://ca.example.com/scep",
			Challenge: "static-challenge", MDMServerURL: "https://mdm.example.com/mdm", SubjectPrefix: "devices.example.com",
			MintChallenge: func(_ context.Context, name, suffix, owner string) (string, error) {
				gotName, gotSuffix, gotOwner = name, suffix, owner
				return "one-time-challenge", nil
			},
		}, fakeTopics{"apns_topic": "com.apple.mgmt.External.abc"},
			fakeRedeemer{token: "good-token", red: Redemption{Owner: "alice@example.com", ExpectedSerial: c.serial}},
			"apns_topic", slog.New(slog.NewTextHandler(io.Discard, nil)))
		req := httptest.NewRequest(http.MethodPost, "/e/good-token", nil)
		req.SetPathValue("token", "good-token")
		rr := httptest.NewRecorder()
		h.ServeGrant(rr, req)
		body := rr.Body.String()
		if rr.Code != http.StatusOK || !strings.Contains(body, "one-time-challenge") || strings.Contains(body, "static-challenge") {
			t.Fatalf("serial %q: status %d, minted challenge missing or static one present", c.serial, rr.Code)
		}
		if gotName != c.wantName || gotSuffix != "devices.example.com" || gotOwner != "alice@example.com" {
			t.Fatalf("serial %q: minted for name=%q suffix=%q owner=%q", c.serial, gotName, gotSuffix, gotOwner)
		}
	}
}
