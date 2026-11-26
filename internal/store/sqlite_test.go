package store

import (
	"context"
	"testing"
)

func TestStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	now := NowUnix()
	rec, ev, err := st.UpsertBan(ctx, BanRecord{
		IP:        "203.0.113.10",
		Jail:      "http-404-scan",
		Reason:    "scan detected",
		LogPath:   "/var/log/nginx/access.log",
		HitCount:  15,
		BannedAt:  now,
		ExpiresAt: now + 3600,
		CreatedBy: "system",
	}, true)
	if err != nil {
		t.Fatalf("UpsertBan #1: %v", err)
	}
	if rec.OffenseCount != 1 || ev.Action != "ban" || ev.ID == 0 {
		t.Fatalf("unexpected ban #1 result: rec=%+v ev=%+v", rec, ev)
	}

	// Second offense should increment recidive count.
	rec2, _, err := st.UpsertBan(ctx, BanRecord{
		IP:        "203.0.113.10",
		Jail:      "http-sensitive-probe",
		Reason:    "env probe",
		HitCount:  3,
		BannedAt:  now + 10,
		ExpiresAt: now + 86410,
		CreatedBy: "system",
	}, true)
	if err != nil {
		t.Fatalf("UpsertBan #2: %v", err)
	}
	if rec2.OffenseCount != 2 {
		t.Fatalf("expected offense_count=2, got %d", rec2.OffenseCount)
	}

	// Extend ban.
	ext, _, found, err := st.ExtendBan(ctx, "203.0.113.10", 3600, "alice")
	if err != nil || !found {
		t.Fatalf("ExtendBan: found=%v err=%v", found, err)
	}
	if ext.ExpiresAt != now+86410+3600 {
		t.Fatalf("unexpected extended expires_at: %d", ext.ExpiresAt)
	}

	// Expire test with a short-lived ban.
	_, _, err = st.UpsertBan(ctx, BanRecord{
		IP:        "198.51.100.5",
		Jail:      "http-bad-bot",
		Reason:    "nikto",
		BannedAt:  now - 100,
		ExpiresAt: now - 10,
		CreatedBy: "system",
	}, false)
	if err != nil {
		t.Fatalf("UpsertBan expired: %v", err)
	}

	expired, err := st.ExpireBans(ctx, now)
	if err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}
	if len(expired) != 1 || expired[0].IP != "198.51.100.5" {
		t.Fatalf("expected 1 expired ban, got %+v", expired)
	}

	// Whitelist CRUD.
	if err := st.AddWhitelist(ctx, WhitelistEntry{CIDR: "10.0.0.0/8", Note: "internal", CreatedBy: "alice"}); err != nil {
		t.Fatalf("AddWhitelist: %v", err)
	}
	wl, err := st.ListWhitelist(ctx)
	if err != nil || len(wl) != 1 {
		t.Fatalf("ListWhitelist: len=%d err=%v", len(wl), err)
	}

	// Remove ban.
	removed, _, err := st.RemoveBan(ctx, "203.0.113.10", "alice", "unban", "false positive")
	if err != nil || !removed {
		t.Fatalf("RemoveBan: removed=%v err=%v", removed, err)
	}
	active, err := st.CountActiveBans(ctx)
	if err != nil || active != 0 {
		t.Fatalf("expected 0 active bans, got %d (err=%v)", active, err)
	}
}
