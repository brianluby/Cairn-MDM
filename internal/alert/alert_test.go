package alert

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

type received struct {
	title, body, priority string
}

func webhook(t *testing.T, fail *bool) (*httptest.Server, func() []received) {
	t.Helper()
	var mu sync.Mutex
	var got []received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *fail {
			w.WriteHeader(503)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, received{r.Header.Get("Title"), string(body), r.Header.Get("Priority")})
		mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []received {
		mu.Lock()
		defer mu.Unlock()
		return append([]received(nil), got...)
	}
}

func TestCheckerAnnouncesRemindsResolvesAndHeartbeats(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir()+"/a.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fail := false
	srv, got := webhook(t, &fail)
	backups := t.TempDir()
	cfg := config.Alerts{WebhookURL: srv.URL, BackupDir: backups, APNSWarnDays: 30, BackupMaxAgeHours: 36, HeartbeatHours: 24}
	c := New(db, NewNotifier(srv.URL), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	// No APNs, no backups: two conditions plus a heartbeat.
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := got()
	if len(msgs) != 3 || msgs[0].title != "Cairn: no APNs push certificate" || msgs[1].title != "Cairn: no backup found" || msgs[2].title != "Cairn heartbeat" {
		t.Fatalf("first run %+v", msgs)
	}
	// Same state an hour later: silence.
	// (alert_state timestamps come from SQLite's clock, so advance our clock only
	// by less than the reminder window relative to real time.)
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(got()) != 3 {
		t.Fatalf("repeat run re-sent: %+v", got())
	}

	// A backup appears and an expiring APNs certificate is loaded.
	if err := os.WriteFile(backups+"/cairn-1.tar.gz", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.t", time.Now().Add(10*24*time.Hour).UTC().Format(time.RFC3339), "", "test"); err != nil {
		t.Fatal(err)
	}
	c.now = time.Now
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	msgs = got()
	titles := map[string]int{}
	for _, m := range msgs[3:] {
		titles[m.title]++
	}
	if titles["Cairn: APNs certificate expires soon"] != 1 || titles["Cairn: resolved"] != 2 {
		t.Fatalf("transition run %+v", msgs[3:])
	}
	states, _ := db.ListAlertStates(ctx)
	activeKeys := map[string]bool{}
	for _, s := range states {
		if s.Active {
			activeKeys[s.Key] = true
		}
	}
	if !activeKeys["apns.expiring:com.apple.mgmt.External.t"] || activeKeys["apns.missing"] || activeKeys["backup.missing"] {
		t.Fatalf("states %+v", states)
	}

	// Delivery failure keeps the condition unnotified so the next run retries.
	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.old", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "", "test"); err != nil {
		t.Fatal(err)
	}
	fail = true
	before := len(got())
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	fail = false
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	msgs = got()
	if len(msgs) != before+1 || msgs[before].title != "Cairn: APNs certificate EXPIRED" || msgs[before].priority != "urgent" {
		t.Fatalf("retry after failed delivery %+v", msgs[before:])
	}

	// Stale backup is detected by file age.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(backups+"/cairn-1.tar.gz", old, old); err != nil {
		t.Fatal(err)
	}
	conds, err := c.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cnd := range conds {
		if cnd.Key == "backup.stale" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale backup not detected: %+v", conds)
	}
}

func TestCheckerWithoutNotifierRecordsOnly(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir()+"/b.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := New(db, nil, config.Alerts{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	states, _ := db.ListAlertStates(ctx)
	if len(states) < 2 {
		t.Fatalf("states %+v", states)
	}
	for _, s := range states {
		if s.NotifiedAt.Valid {
			t.Fatalf("recorded as notified without a webhook: %+v", s)
		}
	}
}
