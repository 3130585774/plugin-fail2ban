package enforcer

import (
	"context"
	"net/netip"
	"testing"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

func TestBlocklistFeedFetch(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	now := time.Now().Unix()
	ctx := context.Background()

	_, _, err = st.UpsertBan(ctx, store.BanRecord{
		IP:        "203.0.113.10",
		Jail:      "http-404-scan",
		Reason:    "404 scan",
		BannedAt:  now,
		ExpiresAt: now + 3600,
	}, false)
	if err != nil {
		t.Fatalf("record ban 1: %v", err)
	}
	_, _, err = st.UpsertBan(ctx, store.BanRecord{
		IP:        "2001:db8::42",
		Jail:      "http-bad-bot",
		Reason:    "bad bot",
		BannedAt:  now,
		ExpiresAt: now + 3600,
	}, false)
	if err != nil {
		t.Fatalf("record ban 2: %v", err)
	}
	_, _, err = st.UpsertBan(ctx, store.BanRecord{
		IP:        "198.51.100.5",
		Jail:      "http-404-scan",
		Reason:    "whitelisted",
		BannedAt:  now,
		ExpiresAt: now + 3600,
	}, false)
	if err != nil {
		t.Fatalf("record ban 3: %v", err)
	}

	wl := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	feed := NewBlocklistFeed(st, func() []netip.Prefix { return wl })

	res, err := feed.Fetch(ctx, sdk.BlocklistRequest{Source: BlocklistSourceCode})
	if err != nil {
		t.Fatalf("fetch all: %v", err)
	}
	if res.TTLSeconds != 60 {
		t.Fatalf("TTLSeconds = %d, want 60", res.TTLSeconds)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(res.Entries), res.Entries)
	}

	// Filter by jail
	filtered, err := feed.Fetch(ctx, sdk.BlocklistRequest{
		Source: BlocklistSourceCode,
		Config: map[string]string{"jail": "http-bad-bot"},
	})
	if err != nil {
		t.Fatalf("fetch filtered: %v", err)
	}
	if len(filtered.Entries) != 1 || filtered.Entries[0].CIDR != "2001:db8::42/128" {
		t.Fatalf("unexpected filtered entries: %+v", filtered.Entries)
	}
}
