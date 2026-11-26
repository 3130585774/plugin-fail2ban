package enforcer

import (
	"context"
	"net/netip"

	sdk "github.com/nginxui/plugin-sdk-go"
	"github.com/nginxui/plugin-sdk-go/protocol"
)

// Status reports the current state of the ban enforcer.
type Status struct {
	Backend          string `json:"backend"`
	IncludeDirective string `json:"include_directive"`
	ActiveRuleCount  int    `json:"active_rule_count"`
	ShardCount       int    `json:"shard_count"`
	LastSyncAt       int64  `json:"last_sync_at"`
	LastSyncChanged  bool   `json:"last_sync_changed"`
	LastError        string `json:"last_error,omitempty"`
	PendingDirty     bool   `json:"pending_dirty"`
}

// Enforcer applies the active ban set to the underlying blocking mechanism
// (default: debounced Nginx snippets; extensible to Linux nftables/ipset).
type Enforcer interface {
	Start()
	Stop(ctx context.Context)
	MarkDirty()
	FlushNow(ctx context.Context) error
	Status() Status
	IncludeDirective() string
}

// SnippetHost abstracts host.* calls needed by SnippetEnforcer for testability.
type SnippetHost interface {
	Ready() bool
	Info() sdk.Info
	NginxSnippetPut(ctx context.Context, name, content string) (changed bool, include string, err error)
	NginxSnippetDelete(ctx context.Context, name string) (removed bool, err error)
	NginxSnippetList(ctx context.Context) ([]protocol.HostNginxSnippet, error)
	Notify(ctx context.Context, level, title, content string, details any) error
}

// FilterSafeBanIPs filters out invalid, loopback, unspecified, and whitelisted IPs
// to guarantee the plugin can never self-lock the host or admin.
func FilterSafeBanIPs(rawIPs []string, whitelist []netip.Prefix) []string {
	safe := make([]string, 0, len(rawIPs))
	seen := make(map[string]struct{}, len(rawIPs))

	for _, raw := range rawIPs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
			continue
		}
		if isWhitelisted(addr, whitelist) {
			continue
		}
		canon := addr.String()
		if _, dup := seen[canon]; dup {
			continue
		}
		seen[canon] = struct{}{}
		safe = append(safe, canon)
	}
	return safe
}

func isWhitelisted(addr netip.Addr, whitelist []netip.Prefix) bool {
	for _, pref := range whitelist {
		// Reject 0.0.0.0/0 or ::/0? Those are fine in whitelist (allow-all), never in deny.
		if pref.Contains(addr) {
			return true
		}
	}
	return false
}
