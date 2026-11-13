package alert

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

type observedList []sqlite.ObservedCertificate

func (o observedList) ObservedDeviceCertificates(context.Context) ([]sqlite.ObservedCertificate, error) {
	return o, nil
}

func TestIdentityConditions(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	conds, err := identityConditions(context.Background(), observedList{
		{DeviceName: "phone", NotAfter: now.Add(-24 * time.Hour)},
		{DeviceName: "laptop", NotAfter: now.Add(5 * 24 * time.Hour)},
		{DeviceName: "desktop", NotAfter: now.Add(200 * 24 * time.Hour)},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range conds {
		got[c.Key] = c.Priority + "|" + c.Message
	}
	if !strings.HasPrefix(got["identity.expired"], "urgent|") || !strings.Contains(got["identity.expired"], "phone") {
		t.Errorf("expired = %q", got["identity.expired"])
	}
	if !strings.Contains(got["identity.expiring"], "laptop (2026-11-18)") || strings.Contains(got["identity.expiring"], "desktop") {
		t.Errorf("expiring = %q", got["identity.expiring"])
	}
	if len(conds) != 2 {
		t.Errorf("conditions = %d", len(conds))
	}
}
