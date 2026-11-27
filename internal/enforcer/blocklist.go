package enforcer

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	sdk "github.com/nginxui/plugin-sdk-go"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

const BlocklistSourceCode = "fail2ban-active"

// BlocklistFeed implements sdk.BlocklistHandler so Nginx UI's built-in
// Blocklists feature can consume Fail2ban Guard's active bans as a native source.
type BlocklistFeed struct {
	store     *store.Store
	whitelist func() []netip.Prefix
}

// NewBlocklistFeed creates a security.blocklist handler backed by the Fail2ban SQLite store.
func NewBlocklistFeed(st *store.Store, whitelist func() []netip.Prefix) *BlocklistFeed {
	return &BlocklistFeed{
		store:     st,
		whitelist: whitelist,
	}
}

// Fetch returns all currently active Fail2ban bans as CIDR entries.
func (b *BlocklistFeed) Fetch(ctx context.Context, req sdk.BlocklistRequest) (sdk.BlocklistResult, error) {
	if req.Source != "" && req.Source != BlocklistSourceCode {
		return sdk.BlocklistResult{}, sdk.InvalidConfig("source", "unsupported blocklist source")
	}

	jailFilter := ""
	if req.Config != nil {
		jailFilter = strings.TrimSpace(req.Config["jail"])
	}

	bans, err := b.store.ListActiveBansForBlocklist(ctx, jailFilter)
	if err != nil {
		return sdk.BlocklistResult{}, err
	}

	var wl []netip.Prefix
	if b.whitelist != nil {
		wl = b.whitelist()
	}

	rawIPs := make([]string, 0, len(bans))
	banByIP := make(map[string]store.BanRecord, len(bans))
	for _, ban := range bans {
		rawIPs = append(rawIPs, ban.IP)
		banByIP[strings.TrimSpace(ban.IP)] = ban
	}

	safeIPs := FilterSafeBanIPs(rawIPs, wl)
	entries := make([]sdk.BlocklistEntry, 0, len(safeIPs))
	for _, ip := range safeIPs {
		cidr, ok := normalizeToCIDR(ip)
		if !ok {
			continue
		}
		ban := banByIP[ip]
		reason := ban.Reason
		if ban.Jail != "" {
			if reason != "" {
				reason = fmt.Sprintf("[%s] %s", ban.Jail, reason)
			} else {
				reason = ban.Jail
			}
		}
		entries = append(entries, sdk.BlocklistEntry{
			CIDR:   cidr,
			Reason: reason,
		})
	}

	return sdk.BlocklistResult{
		Entries:    entries,
		TTLSeconds: 60,
	}, nil
}

func normalizeToCIDR(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		bits := 32
		if a.Is6() {
			bits = 128
		}
		return netip.PrefixFrom(a, bits).String(), true
	}
	return "", false
}
