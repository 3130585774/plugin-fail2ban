package enforcer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

const (
	mainSnippetName    = "fail2ban-bans"
	shardSnippetPrefix = "fail2ban-bans-"
	maxSnippetBytes    = 240 * 1024 // Stay safely below the 256 KiB host limit
	maxTotalSnippets   = 32         // Host limit: 32 snippets per plugin
	maxDataShards      = maxTotalSnippets - 1
)

// WhitelistProvider supplies current admin whitelist prefixes.
type WhitelistProvider func() []netip.Prefix

// SnippetEnforcer writes debounced, sharded Nginx deny snippets via host.nginx.snippet.put.
type SnippetEnforcer struct {
	store     *store.Store
	host      SnippetHost
	whitelist WhitelistProvider
	pluginID  string

	debounce time.Duration
	maxWait  time.Duration

	dirtyCh chan struct{}
	stopCh  chan struct{}
	doneCh  chan struct{}
	once    sync.Once

	flushMu sync.Mutex

	mu               sync.RWMutex
	lastHash         string
	lastShardCount   int
	includeDirective string
	activeRuleCount  int
	lastSyncAt       int64
	lastSyncChanged  bool
	lastError        string
	pendingDirty     bool
}

// NewSnippetEnforcer creates a debounced Nginx snippet enforcer.
func NewSnippetEnforcer(
	st *store.Store,
	host SnippetHost,
	whitelist WhitelistProvider,
	pluginID string,
	debounce time.Duration,
	maxWait time.Duration,
) *SnippetEnforcer {
	if debounce <= 0 {
		debounce = 3 * time.Second
	}
	if maxWait < debounce {
		maxWait = 10 * time.Second
	}
	if pluginID == "" {
		pluginID = "io.github.3130585774.fail2ban"
	}
	return &SnippetEnforcer{
		store:            st,
		host:             host,
		whitelist:        whitelist,
		pluginID:         pluginID,
		debounce:         debounce,
		maxWait:          maxWait,
		dirtyCh:          make(chan struct{}, 1),
		stopCh:           make(chan struct{}),
		doneCh:           make(chan struct{}),
		includeDirective: fmt.Sprintf("include snippets/plugins/%s/%s.conf;", pluginID, mainSnippetName),
	}
}

// UpdateTiming updates debounce and maxWait durations dynamically.
func (e *SnippetEnforcer) UpdateTiming(debounce, maxWait time.Duration) {
	if debounce <= 0 {
		debounce = 3 * time.Second
	}
	if maxWait < debounce {
		maxWait = 10 * time.Second
	}
	e.mu.Lock()
	e.debounce = debounce
	e.maxWait = maxWait
	e.mu.Unlock()
}

// Start launches the debounce coalescer loop.
func (e *SnippetEnforcer) Start() {
	go e.loop()
}

// Stop halts the loop and performs a final flush if dirty.
func (e *SnippetEnforcer) Stop(ctx context.Context) {
	e.once.Do(func() {
		close(e.stopCh)
		<-e.doneCh
		e.mu.RLock()
		dirty := e.pendingDirty
		e.mu.RUnlock()
		if dirty {
			_ = e.FlushNow(ctx)
		}
	})
}

// MarkDirty schedules a debounced snippet synchronization.
func (e *SnippetEnforcer) MarkDirty() {
	e.mu.Lock()
	e.pendingDirty = true
	e.mu.Unlock()
	select {
	case e.dirtyCh <- struct{}{}:
	default:
	}
}

func (e *SnippetEnforcer) loop() {
	defer close(e.doneCh)

	var debounceTimer *time.Timer
	var maxWaitTimer *time.Timer
	var debounceC <-chan time.Time
	var maxWaitC <-chan time.Time

	stopTimers := func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
			debounceTimer = nil
			debounceC = nil
		}
		if maxWaitTimer != nil {
			maxWaitTimer.Stop()
			maxWaitTimer = nil
			maxWaitC = nil
		}
	}

	for {
		select {
		case <-e.dirtyCh:
			e.mu.RLock()
			d := e.debounce
			mw := e.maxWait
			e.mu.RUnlock()

			if debounceTimer == nil {
				debounceTimer = time.NewTimer(d)
				debounceC = debounceTimer.C
			} else {
				if !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}
				debounceTimer.Reset(d)
			}
			if maxWaitTimer == nil {
				maxWaitTimer = time.NewTimer(mw)
				maxWaitC = maxWaitTimer.C
			}

		case <-debounceC:
			stopTimers()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			_ = e.FlushNow(ctx)
			cancel()

		case <-maxWaitC:
			stopTimers()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			_ = e.FlushNow(ctx)
			cancel()

		case <-e.stopCh:
			stopTimers()
			return
		}
	}
}

// FlushNow immediately synchronizes active bans to Nginx snippets.
func (e *SnippetEnforcer) FlushNow(ctx context.Context) error {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()

	if e.host == nil || !e.host.Ready() {
		return nil
	}

	rawIPs, err := e.store.ListActiveBanIPs(ctx)
	if err != nil {
		e.recordError(ctx, fmt.Errorf("list active bans: %w", err))
		return err
	}

	var wl []netip.Prefix
	if e.whitelist != nil {
		wl = e.whitelist()
	}
	safeIPs := FilterSafeBanIPs(rawIPs, wl)
	sort.Strings(safeIPs)

	snippets := e.buildSnippets(safeIPs)
	combinedHash := hashSnippets(snippets)

	e.mu.RLock()
	prevHash := e.lastHash
	prevShards := e.lastShardCount
	e.mu.RUnlock()

	if combinedHash == prevHash {
		e.mu.Lock()
		e.pendingDirty = false
		e.activeRuleCount = len(safeIPs)
		e.lastSyncAt = store.NowUnix()
		e.lastSyncChanged = false
		e.mu.Unlock()
		return nil
	}

	// Write data shards first (if sharded) so main include never references missing files.
	anyChanged := false
	shardNames := make([]string, 0, len(snippets))
	for name := range snippets {
		if name != mainSnippetName {
			shardNames = append(shardNames, name)
		}
	}
	sort.Strings(shardNames)

	for _, name := range shardNames {
		changed, _, err := e.host.NginxSnippetPut(ctx, name, snippets[name])
		if err != nil {
			e.recordError(ctx, fmt.Errorf("put shard snippet %s: %w", name, err))
			return err
		}
		if changed {
			anyChanged = true
		}
	}

	// Write main entry snippet last.
	changed, include, err := e.host.NginxSnippetPut(ctx, mainSnippetName, snippets[mainSnippetName])
	if err != nil {
		e.recordError(ctx, fmt.Errorf("put main snippet: %w", err))
		return err
	}
	if changed {
		anyChanged = true
	}

	// Clean up stale shards if shard count decreased.
	newShardCount := len(shardNames)
	for idx := newShardCount + 1; idx <= prevShards; idx++ {
		staleName := fmt.Sprintf("%s%02d", shardSnippetPrefix, idx)
		_, _ = e.host.NginxSnippetDelete(ctx, staleName)
	}

	e.mu.Lock()
	e.lastHash = combinedHash
	e.lastShardCount = newShardCount
	if include != "" {
		e.includeDirective = include
	}
	e.activeRuleCount = len(safeIPs)
	e.lastSyncAt = store.NowUnix()
	e.lastSyncChanged = anyChanged
	e.lastError = ""
	e.pendingDirty = false
	e.mu.Unlock()

	if anyChanged {
		sdk.Infof("fail2ban: synced %d active deny rules across %d snippet(s)", len(safeIPs), len(snippets))
	}
	return nil
}

// buildSnippets renders deny rules into either a single main snippet or sharded snippets (<= 240 KiB each).
func (e *SnippetEnforcer) buildSnippets(sortedIPs []string) map[string]string {
	header := "# Managed by Nginx UI Fail2ban Guard. Do not edit manually.\n"
	if len(sortedIPs) == 0 {
		return map[string]string{
			mainSnippetName: header + "# No active bans.\n",
		}
	}

	var single strings.Builder
	single.WriteString(header)
	exceedsSingle := false
	for _, ip := range sortedIPs {
		line := "deny " + ip + ";\n"
		if single.Len()+len(line) > maxSnippetBytes {
			exceedsSingle = true
			break
		}
		single.WriteString(line)
	}
	if !exceedsSingle {
		return map[string]string{
			mainSnippetName: single.String(),
		}
	}

	// Multi-shard mode: split across fail2ban-bans-01 .. fail2ban-bans-31.
	pluginID := e.pluginID
	if e.host != nil {
		if infoID := e.host.Info().PluginID; infoID != "" {
			pluginID = infoID
		}
	}

	out := make(map[string]string)
	var indexBuilder strings.Builder
	indexBuilder.WriteString(header)

	shardIdx := 1
	var cur strings.Builder
	cur.WriteString(header)

	flushShard := func() {
		name := fmt.Sprintf("%s%02d", shardSnippetPrefix, shardIdx)
		out[name] = cur.String()
		fmt.Fprintf(&indexBuilder, "include snippets/plugins/%s/%s.conf;\n", pluginID, name)
		shardIdx++
		cur.Reset()
		cur.WriteString(header)
	}

	for _, ip := range sortedIPs {
		line := "deny " + ip + ";\n"
		if cur.Len()+len(line) > maxSnippetBytes {
			if shardIdx >= maxDataShards {
				// Reached host's 32-snippet ceiling; stop adding further rules safely.
				break
			}
			flushShard()
		}
		cur.WriteString(line)
	}
	if cur.Len() > len(header) && shardIdx <= maxDataShards {
		flushShard()
	}

	out[mainSnippetName] = indexBuilder.String()
	return out
}

func hashSnippets(snippets map[string]string) string {
	names := make([]string, 0, len(snippets))
	for k := range snippets {
		names = append(names, k)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		_, _ = h.Write([]byte(n))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(snippets[n]))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (e *SnippetEnforcer) recordError(ctx context.Context, err error) {
	msg := err.Error()
	e.mu.Lock()
	e.lastError = msg
	e.mu.Unlock()
	sdk.Errorf("fail2ban enforcer error: %v", err)
	if e.host != nil && e.host.Ready() {
		_ = e.host.Notify(
			ctx,
			"error",
			"Fail2ban: Nginx Snippet Sync Failed",
			"Failed to apply Fail2ban deny snippet. Previous Nginx configuration was kept intact.",
			map[string]any{"error": msg},
		)
	}
}

// OnReloadFailed records a host nginx.reload_failed event and alerts admins.
func (e *SnippetEnforcer) OnReloadFailed(ctx context.Context) {
	e.mu.Lock()
	e.lastError = "nginx reload failed (reported by host)"
	e.mu.Unlock()
	if e.host != nil && e.host.Ready() {
		_ = e.host.Notify(
			ctx,
			"error",
			"Fail2ban: Nginx Reload Failed",
			"Nginx UI reported an Nginx reload failure. Check your snippet include directive and Nginx error log.",
			nil,
		)
	}
}

// OnReloaded clears transient reload error status on nginx.reloaded.
func (e *SnippetEnforcer) OnReloaded() {
	e.mu.Lock()
	if e.lastError == "nginx reload failed (reported by host)" {
		e.lastError = ""
	}
	e.mu.Unlock()
}

// Status returns a snapshot of enforcer state.
func (e *SnippetEnforcer) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Status{
		Backend:          "nginx.snippet",
		IncludeDirective: e.includeDirective,
		ActiveRuleCount:  e.activeRuleCount,
		ShardCount:       max(e.lastShardCount, 1),
		LastSyncAt:       e.lastSyncAt,
		LastSyncChanged:  e.lastSyncChanged,
		LastError:        e.lastError,
		PendingDirty:     e.pendingDirty,
	}
}

// IncludeDirective returns the nginx include directive for the main ban snippet.
func (e *SnippetEnforcer) IncludeDirective() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.includeDirective
}
