package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"
	"github.com/nginxui/plugin-sdk-go/protocol"

	"github.com/3130585774/plugin-fail2ban/internal/api"
	"github.com/3130585774/plugin-fail2ban/internal/detector"
	"github.com/3130585774/plugin-fail2ban/internal/enforcer"
	"github.com/3130585774/plugin-fail2ban/internal/store"
)

// hostProxy dynamically delegates to sdk.CurrentHost() so components constructed
// before sdk.Serve can call host.* methods seamlessly once plugin.initialized arrives.
type hostProxy struct{}

func (hostProxy) Ready() bool {
	h := sdk.CurrentHost()
	return h != nil && h.Ready()
}

func (hostProxy) Info() sdk.Info {
	if h := sdk.CurrentHost(); h != nil {
		return h.Info()
	}
	return sdk.Info{PluginID: os.Getenv(sdk.EnvPluginID)}
}

func (hostProxy) NginxSnippetPut(ctx context.Context, name, content string) (bool, string, error) {
	h := sdk.CurrentHost()
	if h == nil {
		return false, "", sdk.ErrHostNotReady
	}
	return h.NginxSnippetPut(ctx, name, content)
}

func (hostProxy) NginxSnippetDelete(ctx context.Context, name string) (bool, error) {
	h := sdk.CurrentHost()
	if h == nil {
		return false, sdk.ErrHostNotReady
	}
	return h.NginxSnippetDelete(ctx, name)
}

func (hostProxy) NginxSnippetList(ctx context.Context) ([]protocol.HostNginxSnippet, error) {
	h := sdk.CurrentHost()
	if h == nil {
		return nil, sdk.ErrHostNotReady
	}
	return h.NginxSnippetList(ctx)
}

func (hostProxy) Notify(ctx context.Context, level, title, content string, details any) error {
	h := sdk.CurrentHost()
	if h == nil {
		return sdk.ErrHostNotReady
	}
	return h.Notify(ctx, level, title, content, details)
}

func (hostProxy) KVGet(ctx context.Context, key string, out any) (bool, error) {
	h := sdk.CurrentHost()
	if h == nil {
		return false, sdk.ErrHostNotReady
	}
	return h.KVGet(ctx, key, out)
}

func (hostProxy) KVSet(ctx context.Context, key string, value any) error {
	h := sdk.CurrentHost()
	if h == nil {
		return sdk.ErrHostNotReady
	}
	return h.KVSet(ctx, key, value)
}

func (hostProxy) SitesList(ctx context.Context) ([]protocol.HostSite, error) {
	h := sdk.CurrentHost()
	if h == nil {
		return nil, sdk.ErrHostNotReady
	}
	return h.SitesList(ctx)
}

func main() {
	// Keep Go GC comfortably under the 128 MiB cgroup v2 limit (no swap).
	debug.SetMemoryLimit(100 << 20)

	dataDir := os.Getenv(sdk.EnvPluginDataDir)
	if dataDir == "" {
		dataDir = "."
	}
	dbPath := filepath.Join(dataDir, "fail2ban.db")

	st, err := store.Open(dbPath)
	if err != nil {
		sdk.Errorf("fail2ban: failed to open sqlite store: %v", err)
		os.Exit(1)
	}

	host := hostProxy{}
	pluginID := os.Getenv(sdk.EnvPluginID)
	if pluginID == "" {
		pluginID = "io.github.3130585774.fail2ban"
	}

	globalCfg := store.DefaultGlobalConfig()
	hub := api.NewHub()

	var eng *detector.Engine
	enf := enforcer.NewSnippetEnforcer(
		st,
		host,
		func() []netip.Prefix {
			if eng == nil {
				return nil
			}
			return eng.WhitelistPrefixes()
		},
		pluginID,
		time.Duration(globalCfg.DebounceSec)*time.Second,
		time.Duration(globalCfg.MaxWaitSec)*time.Second,
	)

	eng, err = detector.NewEngine(st, enf, hub, host, globalCfg)
	if err != nil {
		sdk.Errorf("fail2ban: failed to initialize detector engine: %v", err)
		_ = st.Close()
		os.Exit(1)
	}

	apiSrv := api.NewServer(st, eng, enf, hub, host)
	blocklistFeed := enforcer.NewBlocklistFeed(st, func() []netip.Prefix {
		return eng.WhitelistPrefixes()
	})

	enf.Start()
	eng.Start()

	// Once host handshake finishes, load KV config and ensure initial snippet exists.
	go func() {
		for i := 0; i < 60; i++ {
			if host.Ready() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				cfg := store.LoadGlobalConfig(ctx, host)
				eng.SetGlobalConfig(cfg)
				enf.UpdateTiming(
					time.Duration(cfg.DebounceSec)*time.Second,
					time.Duration(cfg.MaxWaitSec)*time.Second,
				)
				_ = enf.FlushNow(ctx)
				cancel()
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()

	sdk.Serve(sdk.Plugin{
		HTTP:      apiSrv.Handler(),
		LogSink:   eng,
		Blocklist: blocklistFeed,
		Events: map[string]sdk.EventHandler{
			protocol.EventAuthLoginFailed: func(ctx context.Context, ev protocol.EventNotification) {
				if ip := extractIPFromEvent(ev.Data); ip != "" {
					eng.HandleLoginFailed(ctx, ip)
				}
			},
			protocol.EventNginxReloaded: func(_ context.Context, _ protocol.EventNotification) {
				enf.OnReloaded()
			},
			protocol.EventNginxReloadFailed: func(ctx context.Context, _ protocol.EventNotification) {
				enf.OnReloadFailed(ctx)
			},
		},
		Methods: map[string]sdk.Handler{
			"fail2ban.expire": func(ctx context.Context, _ json.RawMessage) (any, error) {
				expired, err := eng.ExpireAndSync(ctx)
				if err != nil {
					return nil, err
				}
				// Periodically prune old audit rows during cron tick.
				_ = st.PruneOldEvents(ctx, eng.GlobalConfig().AuditRetentionDays)
				return map[string]any{"expired": expired}, nil
			},
		},
		Shutdown: func(ctx context.Context) error {
			sdk.Infof("fail2ban: graceful shutdown started")
			eng.Stop()
			flushCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			enf.Stop(flushCtx)
			hub.Close()
			return st.Close()
		},
	})
}

func extractIPFromEvent(data any) string {
	m, ok := data.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"ip", "remote_addr", "client_ip", "remote_ip"} {
		if v, exists := m[key]; exists {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
