package enforcer

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"
	"github.com/nginxui/plugin-sdk-go/protocol"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

type mockSnippetHost struct {
	mu       sync.Mutex
	snippets map[string]string
	putCalls int
	delCalls int
	notifies int
}

func newMockSnippetHost() *mockSnippetHost {
	return &mockSnippetHost{snippets: make(map[string]string)}
}

func (m *mockSnippetHost) Ready() bool { return true }
func (m *mockSnippetHost) Info() sdk.Info {
	return sdk.Info{PluginID: "io.github.3130585774.fail2ban"}
}
func (m *mockSnippetHost) NginxSnippetPut(_ context.Context, name, content string) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.putCalls++
	prev, ok := m.snippets[name]
	m.snippets[name] = content
	return !ok || prev != content, fmt.Sprintf("include snippets/plugins/io.github.3130585774.fail2ban/%s.conf;", name), nil
}
func (m *mockSnippetHost) NginxSnippetDelete(_ context.Context, name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delCalls++
	_, ok := m.snippets[name]
	delete(m.snippets, name)
	return ok, nil
}
func (m *mockSnippetHost) NginxSnippetList(_ context.Context) ([]protocol.HostNginxSnippet, error) {
	return nil, nil
}
func (m *mockSnippetHost) Notify(_ context.Context, _, _, _ string, _ any) error {
	m.mu.Lock()
	m.notifies++
	m.mu.Unlock()
	return nil
}

func TestFilterSafeBanIPsAntiLockout(t *testing.T) {
	wl := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	raw := []string{
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"::",
		"10.1.2.3",
		"not-an-ip",
		"203.0.113.10",
		"203.0.113.10", // duplicate
		"::ffff:203.0.113.11",
		"2001:db8::1",
	}
	safe := FilterSafeBanIPs(raw, wl)
	if len(safe) != 3 {
		t.Fatalf("expected 3 safe IPs, got %v", safe)
	}
}

func TestSnippetEnforcerDebounceAndHashDedup(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	host := newMockSnippetHost()
	enf := NewSnippetEnforcer(st, host, nil, "io.github.3130585774.fail2ban", 80*time.Millisecond, 250*time.Millisecond)
	enf.Start()

	// Insert 5 bans rapidly and mark dirty each time -> should coalesce into 1 NginxSnippetPut.
	for i := 1; i <= 5; i++ {
		_, _, _ = st.UpsertBan(ctx, store.BanRecord{
			IP:        fmt.Sprintf("203.0.113.%d", i),
			Jail:      "http-404-scan",
			BannedAt:  store.NowUnix(),
			ExpiresAt: store.NowUnix() + 3600,
		}, false)
		enf.MarkDirty()
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(180 * time.Millisecond)
	enf.Stop(ctx)

	host.mu.Lock()
	puts := host.putCalls
	content := host.snippets[mainSnippetName]
	host.mu.Unlock()

	if puts != 1 {
		t.Fatalf("expected debounced coalescing into 1 put call, got %d", puts)
	}
	for i := 1; i <= 5; i++ {
		want := fmt.Sprintf("deny 203.0.113.%d;", i)
		if !strings.Contains(content, want) {
			t.Fatalf("expected snippet to contain %q, got:\n%s", want, content)
		}
	}

	// Second FlushNow with unchanged bans should skip host call via SHA-256 dedup.
	if err := enf.FlushNow(ctx); err != nil {
		t.Fatalf("FlushNow #2: %v", err)
	}
	host.mu.Lock()
	puts2 := host.putCalls
	host.mu.Unlock()
	if puts2 != 1 {
		t.Fatalf("expected hash dedup to skip unchanged put, got %d calls", puts2)
	}
}

func TestSnippetEnforcerShardingUnder256KiB(t *testing.T) {
	enf := NewSnippetEnforcer(nil, newMockSnippetHost(), nil, "io.github.3130585774.fail2ban", time.Second, 3*time.Second)

	// 15,000 IPs * ~20 bytes = ~300 KiB -> must split into 2 shards + 1 main index snippet.
	ips := make([]string, 15000)
	for i := range ips {
		ips[i] = fmt.Sprintf("198.51.%d.%d", (i/250)+1, (i%250)+1)
	}

	snippets := enf.buildSnippets(ips)
	if len(snippets) < 3 {
		t.Fatalf("expected sharded output (>= 3 snippets), got %d", len(snippets))
	}
	for name, body := range snippets {
		if len(body) > 256*1024 {
			t.Fatalf("snippet %s exceeds 256 KiB (%d bytes)", name, len(body))
		}
	}
	if !strings.Contains(snippets[mainSnippetName], "include snippets/plugins/io.github.3130585774.fail2ban/fail2ban-bans-01.conf;") {
		t.Fatalf("main snippet missing shard include:\n%s", snippets[mainSnippetName])
	}
}
