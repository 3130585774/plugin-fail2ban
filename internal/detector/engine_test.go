package detector

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"
	"github.com/nginxui/plugin-sdk-go/protocol"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

type mockDirty struct {
	count atomic.Int32
}

func (m *mockDirty) MarkDirty() {
	m.count.Add(1)
}

func TestShardedWindowBoundedLRU(t *testing.T) {
	sw := NewShardedWindow(256)
	now := int64(1700000000)

	// Flood with 2,000 unique IPs; total size must stay bounded <= 256.
	for i := 0; i < 2000; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		sw.Record(ip, JailHTTP404Scan, now, 60, true, fmt.Sprintf("/p/%d", i))
	}
	if sz := sw.Size(); sz > 256 {
		t.Fatalf("expected bounded size <= 256, got %d", sz)
	}
}

func TestShardedWindowURIDeduplication(t *testing.T) {
	sw := NewShardedWindow(1024)
	now := int64(1700000000)

	// Repeating the same URI path should only count once.
	for i := 0; i < 10; i++ {
		c := sw.Record("203.0.113.5", JailHTTP404Scan, now+int64(i), 60, true, "/missing-page")
		if c != 1 {
			t.Fatalf("expected dedup count=1 on repeat URI, got %d", c)
		}
	}

	// Distinct URI paths should increment the counter.
	c2 := sw.Record("203.0.113.5", JailHTTP404Scan, now+11, 60, true, "/other-page")
	if c2 != 2 {
		t.Fatalf("expected count=2 for second unique URI, got %d", c2)
	}
}

func TestEngineJailsAndRecidive(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	dirty := &mockDirty{}
	eng, err := NewEngine(st, dirty, nil, nil, store.DefaultGlobalConfig())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// 1. Static asset 404s (.ico, .png) must NOT trigger http-404-scan.
	for i := 0; i < 20; i++ {
		eng.processLogEntry(ctx, sdk.LogEntry{
			LogPath: "/var/log/nginx/site.log",
			LogEntry: protocol.LogEntry{
				RemoteAddr:    "203.0.113.42",
				Status:        404,
				RequestMethod: "GET",
				RequestURI:    fmt.Sprintf("/img/missing-%d.png", i),
			},
		})
	}
	if n, _ := st.CountActiveBans(ctx); n != 0 {
		t.Fatalf("expected 0 bans for excluded static asset 404s, got %d", n)
	}

	// 2. 15 unique 404 paths MUST trigger http-404-scan.
	for i := 0; i < 15; i++ {
		eng.processLogEntry(ctx, sdk.LogEntry{
			LogPath: "/var/log/nginx/site.log",
			LogEntry: protocol.LogEntry{
				RemoteAddr:    "203.0.113.42",
				Status:        404,
				RequestMethod: "GET",
				RequestURI:    fmt.Sprintf("/admin-scan-%d?rand=%d", i, i),
			},
		})
	}
	bans, total, err := st.ListBans(ctx, store.BanQuery{})
	if err != nil || total != 1 || bans[0].Jail != JailHTTP404Scan {
		t.Fatalf("expected 1 http-404-scan ban, got total=%d bans=%+v err=%v", total, bans, err)
	}
	firstDur := bans[0].ExpiresAt - bans[0].BannedAt
	if firstDur != 3600 {
		t.Fatalf("expected first ban duration 3600s, got %d", firstDur)
	}

	// 3. Unban and trigger again -> recidive-escalation should bump duration to 86400s (24h).
	_, _, _ = st.RemoveBan(ctx, "203.0.113.42", "test", "unban", "test")
	eng.MarkUnbanned("203.0.113.42")
	for i := 0; i < 15; i++ {
		eng.processLogEntry(ctx, sdk.LogEntry{
			LogPath: "/var/log/nginx/site.log",
			LogEntry: protocol.LogEntry{
				RemoteAddr:    "203.0.113.42",
				Status:        404,
				RequestMethod: "GET",
				RequestURI:    fmt.Sprintf("/second-scan-%d", i),
			},
		})
	}
	bans, total, _ = st.ListBans(ctx, store.BanQuery{})
	if total != 1 || bans[0].OffenseCount != 2 {
		t.Fatalf("expected recidive offense_count=2, got %+v", bans)
	}
	if dur := bans[0].ExpiresAt - bans[0].BannedAt; dur != 86400 {
		t.Fatalf("expected escalated duration 86400s, got %d", dur)
	}

	// 4. Sensitive probe (/.env) triggers in 3 hits.
	for i := 0; i < 3; i++ {
		eng.processLogEntry(ctx, sdk.LogEntry{
			LogEntry: protocol.LogEntry{
				RemoteAddr: "198.51.100.77",
				Status:     404,
				RequestURI: "/.env",
			},
		})
	}
	// 5. Bad bot (sqlmap) triggers in 2 hits.
	for i := 0; i < 2; i++ {
		eng.processLogEntry(ctx, sdk.LogEntry{
			LogEntry: protocol.LogEntry{
				RemoteAddr: "198.51.100.88",
				Status:     200,
				RequestURI: "/",
				UserAgent:  "sqlmap/1.7.2#stable",
			},
		})
	}
	// 6. Loopback IP (127.0.0.1) must NEVER be banned even on sensitive probe.
	for i := 0; i < 10; i++ {
		eng.processLogEntry(ctx, sdk.LogEntry{
			LogEntry: protocol.LogEntry{
				RemoteAddr: "127.0.0.1",
				Status:     404,
				RequestURI: "/.env",
			},
		})
	}
	// 7. Nginx UI login guard triggers in 5 failed logins.
	for i := 0; i < 5; i++ {
		eng.HandleLoginFailed(ctx, "198.51.100.99")
	}

	active, _ := st.CountActiveBans(ctx)
	if active != 4 {
		t.Fatalf("expected 4 active bans (404-scan, sensitive-probe, bad-bot, login-guard), got %d", active)
	}
	if dirty.count.Load() < 4 {
		t.Fatalf("expected enforcer MarkDirty called >= 4 times, got %d", dirty.count.Load())
	}
}

func TestEngineAsyncPushFastAck(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	eng, err := NewEngine(st, &mockDirty{}, nil, nil, store.DefaultGlobalConfig())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.Start()
	defer eng.Stop()

	batch := make([]sdk.LogEntry, 512)
	for i := range batch {
		batch[i] = sdk.LogEntry{
			LogEntry: protocol.LogEntry{
				RemoteAddr: fmt.Sprintf("203.0.113.%d", (i%250)+1),
				Status:     200,
				RequestURI: "/ok",
			},
		}
	}
	start := time.Now()
	accepted, err := eng.Push(context.Background(), batch)
	if err != nil || accepted != 512 {
		t.Fatalf("Push: accepted=%d err=%v", accepted, err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Push took too long (%v), must ack promptly", elapsed)
	}
}

func BenchmarkDetector5000RPS(b *testing.B) {
	st, err := store.Open(":memory:")
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	eng, err := NewEngine(st, &mockDirty{}, nil, nil, store.DefaultGlobalConfig())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	ctx := context.Background()

	entries := make([]sdk.LogEntry, 1024)
	for i := range entries {
		entries[i] = sdk.LogEntry{
			LogPath: "/var/log/nginx/access.log",
			LogEntry: protocol.LogEntry{
				RemoteAddr:    fmt.Sprintf("198.51.%d.%d", (i/250)%250, (i%250)+1),
				Status:        404,
				RequestMethod: "GET",
				RequestURI:    fmt.Sprintf("/probe/%d", i%10),
				UserAgent:     "Mozilla/5.0",
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.processLogEntry(ctx, entries[i%len(entries)])
	}
}
