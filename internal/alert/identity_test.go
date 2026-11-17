package alert

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

type candidateList []sqlite.RenewalCandidate

func (c candidateList) RenewalCandidates(context.Context) ([]sqlite.RenewalCandidate, error) {
	return c, nil
}

func identityAlerts(t *testing.T, list candidateList, policy IdentityPolicy, now time.Time) map[string]string {
	t.Helper()
	conds, err := identityConditions(context.Background(), list, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range conds {
		got[c.Key] = c.Priority + "|" + c.Message
	}
	return got
}

func TestIdentityConditions(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	list := candidateList{
		{DeviceName: "phone", NotAfter: now.Add(-24 * time.Hour)},
		{DeviceName: "laptop", NotAfter: now.Add(5 * 24 * time.Hour)},
		{DeviceName: "desktop", NotAfter: now.Add(200 * 24 * time.Hour)},
	}
	got := identityAlerts(t, list, IdentityPolicy{}, now)
	if !strings.HasPrefix(got["identity.expired"], "urgent|") || !strings.Contains(got["identity.expired"], "phone") {
		t.Errorf("expired = %q", got["identity.expired"])
	}
	if !strings.Contains(got["identity.expiring"], "laptop (2026-11-18)") || strings.Contains(got["identity.expiring"], "desktop") {
		t.Errorf("expiring = %q", got["identity.expiring"])
	}
	if len(got) != 2 {
		t.Errorf("conditions = %d", len(got))
	}
}

// Inside the grace period an expired device is still reachable, so it is not
// reported as refused; past it, it is.
func TestIdentityConditionsWithGrace(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	list := candidateList{
		{DeviceName: "mac", NotAfter: now.Add(-87 * 24 * time.Hour)},
		{DeviceName: "old-phone", NotAfter: now.Add(-200 * 24 * time.Hour)},
		{DeviceName: "tablet", NotAfter: now.Add(-24 * time.Hour), Last: sqlite.Renewal{State: "failed", Error: "The device did not answer within 7 days."}},
		{DeviceName: "moved", NotAfter: now.Add(10 * 24 * time.Hour)},
	}
	policy := IdentityPolicy{Renewing: true, ExpiredGrace: 180 * 24 * time.Hour, Blocked: func(c sqlite.RenewalCandidate) string {
		if c.DeviceName == "moved" {
			return "checks in through another name"
		}
		return ""
	}}
	got := identityAlerts(t, list, policy, now)
	if !strings.Contains(got["identity.grace"], "mac (until 2027-02-14)") || strings.Contains(got["identity.grace"], "old-phone") {
		t.Errorf("grace = %q", got["identity.grace"])
	}
	if !strings.Contains(got["identity.expired"], "old-phone") || strings.Contains(got["identity.expired"], "mac") {
		t.Errorf("expired = %q", got["identity.expired"])
	}
	failed := got["identity.renewal-failed"]
	if !strings.Contains(failed, "tablet: The device did not answer") || !strings.Contains(failed, "moved: checks in through another name") {
		t.Errorf("failed = %q", failed)
	}
}
