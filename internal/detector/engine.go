package detector

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

const defaultQueueCapacity = 16384

// DirtyNotifier triggers the enforcer whenever the active ban set changes.
type DirtyNotifier interface {
	MarkDirty()
}

// EventBroadcaster publishes ban/unban events to WebSocket clients.
type EventBroadcaster interface {
	Broadcast(ev store.BanEvent)
}

// HostNotifier sends aggregate alerts (never raw PII) to the Nginx UI notification center.
type HostNotifier interface {
	Ready() bool
	Notify(ctx context.Context, level, title, content string, details any) error
}

// EngineStats summarizes runtime metrics for the status API.
type EngineStats struct {
	Enabled         bool  `json:"enabled"`
	QueueDepth      int   `json:"queue_depth"`
	QueueCapacity   int   `json:"queue_capacity"`
	TrackedEntries  int   `json:"tracked_entries"`
	MaxTrackedIPs   int   `json:"max_tracked_ips"`
	LogsProcessed   int64 `json:"logs_processed"`
	LogsDropped     int64 `json:"logs_dropped"`
	BansTriggered   int64 `json:"bans_triggered"`
	WhitelistedSkip int64 `json:"whitelisted_skips"`
}

// Engine consumes Nginx access log streams asynchronously and triggers bans.
type Engine struct {
	store       *store.Store
	enforcer    DirtyNotifier
	broadcaster EventBroadcaster
	notifier    HostNotifier

	window *ShardedWindow
	queue  chan sdk.LogEntry

	mu          sync.RWMutex
	globalCfg   store.GlobalConfig
	jails       map[string]*compiledJail
	jailOrder   []string
	whitelist   []netip.Prefix
	activeCache map[string]int64 // ip -> expiresAt (0 = permanent)

	// Wave notification tracking
	waveMu         sync.Mutex
	waveTimestamps []int64
	lastWaveNotify int64

	logsProcessed   atomic.Int64
	logsDropped     atomic.Int64
	bansTriggered   atomic.Int64
	whitelistedSkip atomic.Int64

	stopCh chan struct{}
	doneCh chan struct{}
	once   sync.Once
}

// NewEngine constructs and initializes the detection engine from persisted state.
func NewEngine(
	st *store.Store,
	enf DirtyNotifier,
	bc EventBroadcaster,
	notif HostNotifier,
	globalCfg store.GlobalConfig,
) (*Engine, error) {
	if globalCfg.MaxTrackedIPs <= 0 {
		globalCfg.MaxTrackedIPs = 50000
	}

	e := &Engine{
		store:       st,
		enforcer:    enf,
		broadcaster: bc,
		notifier:    notif,
		window:      NewShardedWindow(globalCfg.MaxTrackedIPs),
		queue:       make(chan sdk.LogEntry, defaultQueueCapacity),
		globalCfg:   globalCfg,
		jails:       make(map[string]*compiledJail),
		activeCache: make(map[string]int64),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}

	if err := e.loadInitialState(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) loadInitialState(ctx context.Context) error {
	savedJails, err := e.store.LoadJailConfigs(ctx)
	if err != nil {
		return err
	}

	defaults := DefaultJails()
	e.jailOrder = make([]string, 0, len(defaults))
	for _, def := range defaults {
		cfg := def
		if saved, ok := savedJails[def.ID]; ok {
			// Preserve default name/description if omitted in saved JSON.
			if saved.Name == "" {
				saved.Name = def.Name
			}
			if saved.Description == "" {
				saved.Description = def.Description
			}
			cfg = saved
		} else {
			_ = e.store.SaveJailConfig(ctx, def)
		}
		cj, err := compileJail(cfg)
		if err != nil {
			// Fallback to default if saved regex is corrupted.
			cj, _ = compileJail(def)
		}
		e.jails[def.ID] = cj
		e.jailOrder = append(e.jailOrder, def.ID)
	}

	if err := e.ReloadWhitelist(ctx); err != nil {
		return err
	}
	if err := e.ReloadActiveCache(ctx); err != nil {
		return err
	}
	return nil
}

// Start launches the background log analysis worker.
func (e *Engine) Start() {
	go e.worker()
}

// Stop signals the worker to drain remaining buffered entries and exit cleanly.
func (e *Engine) Stop() {
	e.once.Do(func() {
		close(e.stopCh)
		<-e.doneCh
	})
}

// Push implements sdk.LogSinkHandler: enqueues entries without blocking and replies immediately.
func (e *Engine) Push(_ context.Context, batch []sdk.LogEntry) (int, error) {
	accepted := 0
	for _, entry := range batch {
		select {
		case e.queue <- entry:
			accepted++
		default:
			e.logsDropped.Add(1)
		}
	}
	return accepted, nil
}

func (e *Engine) worker() {
	defer close(e.doneCh)
	for {
		select {
		case entry := <-e.queue:
			e.processLogEntry(context.Background(), entry)
		case <-e.stopCh:
			// Drain any already-buffered entries before returning.
			for {
				select {
				case entry := <-e.queue:
					e.processLogEntry(context.Background(), entry)
				default:
					return
				}
			}
		}
	}
}

func (e *Engine) processLogEntry(ctx context.Context, entry sdk.LogEntry) {
	e.logsProcessed.Add(1)

	e.mu.RLock()
	enabled := e.globalCfg.Enabled
	e.mu.RUnlock()
	if !enabled {
		return
	}

	ipStr, ok := NormalizeIP(entry.RemoteAddr)
	if !ok {
		return
	}
	if e.isProtectedOrBanned(ipStr) {
		return
	}

	nowSec := store.NowUnix()
	if ts := entry.Time(); !ts.IsZero() {
		// Only trust log timestamp if within +-5 minutes of wall clock; otherwise use now.
		if diff := nowSec - ts.Unix(); diff >= -300 && diff <= 300 {
			nowSec = ts.Unix()
		}
	}

	uriPath := StripQuery(entry.RequestURI)

	e.mu.RLock()
	matchedJails := make([]*compiledJail, 0, 2)
	for _, id := range e.jailOrder {
		if id == JailNginxUILoginGuard || id == JailRecidiveEscalation {
			continue
		}
		cj := e.jails[id]
		if cj != nil && cj.matchesLog(entry.LogPath, entry.Status, entry.RequestMethod, uriPath, entry.UserAgent) {
			matchedJails = append(matchedJails, cj)
		}
	}
	e.mu.RUnlock()

	for _, cj := range matchedJails {
		hits := e.window.Record(ipStr, cj.cfg.ID, nowSec, cj.cfg.WindowSec, cj.cfg.DeduplicateURI, uriPath)
		if hits >= cj.cfg.Threshold {
			reason := fmt.Sprintf("rule %s threshold reached (%d/%ds)", cj.cfg.ID, hits, cj.cfg.WindowSec)
			e.triggerBan(ctx, ipStr, cj.cfg.ID, reason, entry.LogPath, hits, cj.cfg.BanDurationSec, nowSec)
			e.window.Clear(ipStr, cj.cfg.ID)
			return // IP is now banned; skip remaining jails for this line.
		}
	}
}

// HandleLoginFailed processes a host auth.login_failed event for nginxui-login-guard.
func (e *Engine) HandleLoginFailed(ctx context.Context, remoteIP string) {
	e.mu.RLock()
	enabled := e.globalCfg.Enabled
	cj := e.jails[JailNginxUILoginGuard]
	e.mu.RUnlock()
	if !enabled || cj == nil || !cj.cfg.Enabled {
		return
	}

	ipStr, ok := NormalizeIP(remoteIP)
	if !ok || e.isProtectedOrBanned(ipStr) {
		return
	}

	nowSec := store.NowUnix()
	hits := e.window.Record(ipStr, cj.cfg.ID, nowSec, cj.cfg.WindowSec, false, "")
	if hits >= cj.cfg.Threshold {
		reason := fmt.Sprintf("rule %s threshold reached (%d/%ds)", cj.cfg.ID, hits, cj.cfg.WindowSec)
		e.triggerBan(ctx, ipStr, cj.cfg.ID, reason, "", hits, cj.cfg.BanDurationSec, nowSec)
		e.window.Clear(ipStr, cj.cfg.ID)
	}
}

func (e *Engine) triggerBan(ctx context.Context, ip, jailID, reason, logPath string, hits int, baseDurSec int64, nowSec int64) {
	durSec := baseDurSec

	// Apply recidive escalation if enabled.
	e.mu.RLock()
	recidive := e.jails[JailRecidiveEscalation]
	e.mu.RUnlock()
	if recidive != nil && recidive.cfg.Enabled && len(recidive.cfg.EscalationLevels) > 0 {
		prevOffenses, err := e.store.GetOffenseCount(ctx, ip, nowSec)
		if err == nil && prevOffenses > 0 {
			idx := prevOffenses
			if idx >= len(recidive.cfg.EscalationLevels) {
				idx = len(recidive.cfg.EscalationLevels) - 1
			}
			if escalated := recidive.cfg.EscalationLevels[idx]; escalated > durSec {
				durSec = escalated
				reason = fmt.Sprintf("%s (recidive #%d)", reason, prevOffenses+1)
			}
		}
	}

	var expiresAt int64
	if durSec > 0 {
		expiresAt = nowSec + durSec
	}

	rec := store.BanRecord{
		IP:        ip,
		Jail:      jailID,
		Reason:    reason,
		LogPath:   logPath,
		HitCount:  hits,
		BannedAt:  nowSec,
		ExpiresAt: expiresAt,
		CreatedBy: "system",
	}

	saved, ev, err := e.store.UpsertBan(ctx, rec, true)
	if err != nil {
		sdk.Errorf("fail2ban: failed to persist ban for jail %s: %v", jailID, err)
		return
	}

	e.MarkBanned(saved.IP, saved.ExpiresAt)
	e.bansTriggered.Add(1)

	// Privacy compliance: never log raw client IP, URL, Referer, or User-Agent.
	sdk.Infof("fail2ban: banned 1 client via rule %s (offense #%d)", jailID, saved.OffenseCount)

	if e.enforcer != nil {
		e.enforcer.MarkDirty()
	}
	if e.broadcaster != nil {
		e.broadcaster.Broadcast(ev)
	}
	e.checkWaveNotification(ctx, jailID, nowSec)
}

func (e *Engine) checkWaveNotification(ctx context.Context, jailID string, nowSec int64) {
	if e.notifier == nil || !e.notifier.Ready() {
		return
	}
	e.mu.RLock()
	waveCount := e.globalCfg.NotifyWaveCount
	waveWindow := int64(e.globalCfg.NotifyWaveWindowS)
	e.mu.RUnlock()
	if waveCount <= 0 || waveWindow <= 0 {
		return
	}

	e.waveMu.Lock()
	cutoff := nowSec - waveWindow
	kept := e.waveTimestamps[:0]
	for _, ts := range e.waveTimestamps {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, nowSec)
	e.waveTimestamps = kept

	shouldNotify := len(kept) >= waveCount && nowSec-e.lastWaveNotify >= waveWindow
	if shouldNotify {
		e.lastWaveNotify = nowSec
	}
	count := len(kept)
	e.waveMu.Unlock()

	if shouldNotify {
		_ = e.notifier.Notify(
			ctx,
			"warning",
			"Fail2ban: Elevated Ban Activity",
			fmt.Sprintf("Banned %d clients within the last %d seconds (latest rule: %s).", count, waveWindow, jailID),
			map[string]any{"count": count, "window_sec": waveWindow, "latest_jail": jailID},
		)
	}
}

// isProtectedOrBanned returns true if ip is loopback, whitelisted, or currently banned.
func (e *Engine) isProtectedOrBanned(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() {
		e.whitelistedSkip.Add(1)
		return true
	}

	now := store.NowUnix()
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, pref := range e.whitelist {
		if pref.Contains(addr) {
			e.whitelistedSkip.Add(1)
			return true
		}
	}
	if exp, ok := e.activeCache[ipStr]; ok {
		if exp == 0 || exp > now {
			return true
		}
	}
	return false
}

// IsWhitelisted checks whether an IP matches built-in loopback or user whitelist CIDRs.
func (e *Engine) IsWhitelisted(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() {
		return true
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, pref := range e.whitelist {
		if pref.Contains(addr) {
			return true
		}
	}
	return false
}

// ReloadWhitelist reloads whitelist prefixes from SQLite into memory.
func (e *Engine) ReloadWhitelist(ctx context.Context) error {
	entries, err := e.store.ListWhitelist(ctx)
	if err != nil {
		return err
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, ent := range entries {
		if p, ok := ParseCIDROrIP(ent.CIDR); ok {
			prefixes = append(prefixes, p)
		}
	}
	e.mu.Lock()
	e.whitelist = prefixes
	e.mu.Unlock()
	return nil
}

// WhitelistPrefixes returns a copy of currently loaded user whitelist prefixes.
func (e *Engine) WhitelistPrefixes() []netip.Prefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]netip.Prefix, len(e.whitelist))
	copy(out, e.whitelist)
	return out
}

// ReloadActiveCache reloads all active bans into the fast lookup map.
func (e *Engine) ReloadActiveCache(ctx context.Context) error {
	bans, _, err := e.store.ListBans(ctx, store.BanQuery{Limit: 500})
	if err != nil {
		return err
	}
	cache := make(map[string]int64, len(bans))
	for _, b := range bans {
		cache[b.IP] = b.ExpiresAt
	}
	e.mu.Lock()
	e.activeCache = cache
	e.mu.Unlock()
	return nil
}

// MarkBanned updates the in-memory active ban cache.
func (e *Engine) MarkBanned(ip string, expiresAt int64) {
	e.mu.Lock()
	e.activeCache[ip] = expiresAt
	e.mu.Unlock()
}

// MarkUnbanned removes an IP from the in-memory active ban cache.
func (e *Engine) MarkUnbanned(ip string) {
	e.mu.Lock()
	delete(e.activeCache, ip)
	e.mu.Unlock()
}

// ListJails returns all jail configs in stable display order.
func (e *Engine) ListJails() []store.JailConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]store.JailConfig, 0, len(e.jailOrder))
	for _, id := range e.jailOrder {
		if cj := e.jails[id]; cj != nil {
			out = append(out, cj.cfg)
		}
	}
	return out
}

// UpdateJail compiles, validates, persists, and hot-reloads a jail configuration.
func (e *Engine) UpdateJail(ctx context.Context, cfg store.JailConfig) (store.JailConfig, error) {
	cj, err := compileJail(cfg)
	if err != nil {
		return store.JailConfig{}, err
	}
	if err := e.store.SaveJailConfig(ctx, cfg); err != nil {
		return store.JailConfig{}, err
	}
	e.mu.Lock()
	if _, exists := e.jails[cfg.ID]; !exists {
		e.jailOrder = append(e.jailOrder, cfg.ID)
	}
	e.jails[cfg.ID] = cj
	e.mu.Unlock()
	return cfg, nil
}

// GlobalConfig returns the current global configuration.
func (e *Engine) GlobalConfig() store.GlobalConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.globalCfg
}

// SetGlobalConfig updates runtime global configuration.
func (e *Engine) SetGlobalConfig(cfg store.GlobalConfig) {
	e.mu.Lock()
	e.globalCfg = cfg
	e.mu.Unlock()
}

// Stats returns live runtime telemetry for the console.
func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	enabled := e.globalCfg.Enabled
	maxIPs := e.globalCfg.MaxTrackedIPs
	e.mu.RUnlock()
	return EngineStats{
		Enabled:         enabled,
		QueueDepth:      len(e.queue),
		QueueCapacity:   cap(e.queue),
		TrackedEntries:  e.window.Size(),
		MaxTrackedIPs:   maxIPs,
		LogsProcessed:   e.logsProcessed.Load(),
		LogsDropped:     e.logsDropped.Load(),
		BansTriggered:   e.bansTriggered.Load(),
		WhitelistedSkip: e.whitelistedSkip.Load(),
	}
}

// NormalizeIP parses an IP string, strips IPv4-mapped IPv6 prefix, and returns canonical form.
func NormalizeIP(raw string) (string, bool) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()
	return addr.String(), true
}

// ParseCIDROrIP parses either a single IP or CIDR notation into a normalized netip.Prefix.
func ParseCIDROrIP(raw string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked(), true
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

// ExpireAndSync removes expired bans from SQLite, updates cache, broadcasts events, and marks enforcer dirty.
func (e *Engine) ExpireAndSync(ctx context.Context) (int, error) {
	events, err := e.store.ExpireBans(ctx, time.Now().UTC().Unix())
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	for _, ev := range events {
		e.MarkUnbanned(ev.IP)
		if e.broadcaster != nil {
			e.broadcaster.Broadcast(ev)
		}
	}
	if e.enforcer != nil {
		e.enforcer.MarkDirty()
	}
	sdk.Infof("fail2ban: expired %d bans", len(events))
	return len(events), nil
}
