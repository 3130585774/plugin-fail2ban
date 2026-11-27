package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"
	"github.com/nginxui/plugin-sdk-go/protocol"

	"github.com/3130585774/plugin-fail2ban/internal/detector"
	"github.com/3130585774/plugin-fail2ban/internal/enforcer"
	"github.com/3130585774/plugin-fail2ban/internal/store"
)

// HostBridge abstracts host.* calls needed by the HTTP API.
type HostBridge interface {
	Ready() bool
	KVGet(ctx context.Context, key string, out any) (bool, error)
	KVSet(ctx context.Context, key string, value any) error
	SitesList(ctx context.Context) ([]protocol.HostSite, error)
}

// Server exposes the plugin's REST endpoints on the Unix socket.
type Server struct {
	store    *store.Store
	engine   *detector.Engine
	enforcer *enforcer.SnippetEnforcer
	host     HostBridge
	mux      *http.ServeMux
}

// NewServer creates and wires the HTTP ServeMux for the plugin.
func NewServer(
	st *store.Store,
	eng *detector.Engine,
	enf *enforcer.SnippetEnforcer,
	host HostBridge,
) *Server {
	s := &Server{
		store:    st,
		engine:   eng,
		enforcer: enf,
		host:     host,
		mux:      http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// Handler returns the http.Handler to pass to sdk.Plugin.HTTP.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /status", s.handleStatus)
	s.mux.HandleFunc("PUT /config", s.handleUpdateConfig)
	s.mux.HandleFunc("POST /sync", s.handleSyncNow)

	s.mux.HandleFunc("GET /bans", s.handleListBans)
	s.mux.HandleFunc("POST /bans", s.handleCreateBan)
	s.mux.HandleFunc("DELETE /bans/{ip}", s.handleDeleteBan)
	s.mux.HandleFunc("PATCH /bans/{ip}", s.handleExtendBan)

	s.mux.HandleFunc("GET /jails", s.handleListJails)
	s.mux.HandleFunc("PUT /jails/{id}", s.handleUpdateJail)

	s.mux.HandleFunc("GET /whitelist", s.handleListWhitelist)
	s.mux.HandleFunc("POST /whitelist", s.handleAddWhitelist)
	s.mux.HandleFunc("DELETE /whitelist", s.handleDeleteWhitelist)

	s.mux.HandleFunc("GET /events/history", s.handleListEvents)

	s.mux.HandleFunc("GET /snippet/guide", s.handleSnippetGuide)
}

func actorFromRequest(r *http.Request) string {
	u := sdk.UserFromRequest(r)
	if u.Name != "" {
		return u.Name
	}
	if u.ID != "" {
		return "user:" + u.ID
	}
	return "admin"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func parseIntParam(r *http.Request, name string, def int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := store.NowUnix()
	activeBans, _ := s.store.CountActiveBans(ctx)
	bans24h, _ := s.store.CountBansSince(ctx, now-86400)
	logStats, _ := s.store.LogPathStats(ctx, now-86400)

	writeJSON(w, http.StatusOK, map[string]any{
		"config":         s.engine.GlobalConfig(),
		"engine":         s.engine.Stats(),
		"enforcer":       s.enforcer.Status(),
		"active_bans":    activeBans,
		"bans_24h":       bans24h,
		"log_path_stats": logStats,
	})
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg store.GlobalConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	def := store.DefaultGlobalConfig()
	if cfg.SchemaVersion <= 0 {
		cfg.SchemaVersion = def.SchemaVersion
	}
	if cfg.DebounceSec < 1 || cfg.DebounceSec > 30 {
		writeError(w, http.StatusBadRequest, "debounce_sec must be between 1 and 30")
		return
	}
	if cfg.MaxWaitSec < cfg.DebounceSec || cfg.MaxWaitSec > 60 {
		writeError(w, http.StatusBadRequest, "max_wait_sec must be >= debounce_sec and <= 60")
		return
	}
	if cfg.MaxTrackedIPs < 1000 || cfg.MaxTrackedIPs > 200000 {
		cfg.MaxTrackedIPs = def.MaxTrackedIPs
	}
	if cfg.AuditRetentionDays <= 0 {
		cfg.AuditRetentionDays = def.AuditRetentionDays
	}

	s.engine.SetGlobalConfig(cfg)
	s.enforcer.UpdateTiming(
		time.Duration(cfg.DebounceSec)*time.Second,
		time.Duration(cfg.MaxWaitSec)*time.Second,
	)
	_ = store.SaveGlobalConfig(r.Context(), s.host, cfg)
	sdk.Infof("fail2ban: global config updated by %s", actorFromRequest(r))
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleSyncNow(w http.ResponseWriter, r *http.Request) {
	if err := s.enforcer.FlushNow(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.enforcer.Status())
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	q := store.BanQuery{
		Search: strings.TrimSpace(r.URL.Query().Get("search")),
		Jail:   strings.TrimSpace(r.URL.Query().Get("jail")),
		Limit:  parseIntParam(r, "limit", 50),
		Offset: parseIntParam(r, "offset", 0),
	}
	items, total, err := s.store.ListBans(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	})
}

type createBanRequest struct {
	IP          string `json:"ip"`
	Reason      string `json:"reason"`
	DurationSec int64  `json:"duration_sec"` // 0 = permanent
	LogPath     string `json:"log_path"`
}

func (s *Server) handleCreateBan(w http.ResponseWriter, r *http.Request) {
	var req createBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ipStr, ok := detector.NormalizeIP(strings.TrimSpace(req.IP))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	if s.engine.IsWhitelisted(ipStr) {
		writeError(w, http.StatusConflict, "IP is protected by loopback or whitelist")
		return
	}
	if req.DurationSec < 0 {
		writeError(w, http.StatusBadRequest, "duration_sec must be >= 0")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "manual ban"
	}

	now := store.NowUnix()
	var expiresAt int64
	if req.DurationSec > 0 {
		expiresAt = now + req.DurationSec
	}

	actor := actorFromRequest(r)
	rec, _, err := s.store.UpsertBan(r.Context(), store.BanRecord{
		IP:        ipStr,
		Jail:      "manual",
		Reason:    reason,
		LogPath:   strings.TrimSpace(req.LogPath),
		HitCount:  1,
		BannedAt:  now,
		ExpiresAt: expiresAt,
		CreatedBy: actor,
	}, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.engine.MarkBanned(rec.IP, rec.ExpiresAt)
	s.enforcer.MarkDirty()
	sdk.Infof("fail2ban: manual ban added by %s", actor)

	writeJSON(w, http.StatusCreated, rec)
}

func decodeIPParam(r *http.Request) (string, bool) {
	raw := r.PathValue("ip")
	if raw == "" {
		raw = r.URL.Query().Get("ip")
	}
	if unescaped, err := url.PathUnescape(raw); err == nil {
		raw = unescaped
	}
	return detector.NormalizeIP(strings.TrimSpace(raw))
}

func (s *Server) handleDeleteBan(w http.ResponseWriter, r *http.Request) {
	ipStr, ok := decodeIPParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	actor := actorFromRequest(r)
	removed, _, err := s.store.RemoveBan(r.Context(), ipStr, actor, "unban", "manual unban")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "ban not found")
		return
	}

	s.engine.MarkUnbanned(ipStr)
	s.enforcer.MarkDirty()
	sdk.Infof("fail2ban: manual unban performed by %s", actor)

	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "ip": ipStr})
}

type extendBanRequest struct {
	ExtraSec int64 `json:"extra_sec"` // <= 0 means make permanent
}

func (s *Server) handleExtendBan(w http.ResponseWriter, r *http.Request) {
	ipStr, ok := decodeIPParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	var req extendBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	actor := actorFromRequest(r)
	rec, _, found, err := s.store.ExtendBan(r.Context(), ipStr, req.ExtraSec, actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "ban not found")
		return
	}

	s.engine.MarkBanned(rec.IP, rec.ExpiresAt)
	sdk.Infof("fail2ban: ban extended by %s", actor)
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleListJails(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items": s.engine.ListJails(),
	})
}

func (s *Server) handleUpdateJail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing jail id")
		return
	}
	var cfg store.JailConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cfg.ID = id
	updated, err := s.engine.UpdateJail(r.Context(), cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sdk.Infof("fail2ban: jail %s updated by %s", id, actorFromRequest(r))
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListWhitelist(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type addWhitelistRequest struct {
	CIDR string `json:"cidr"`
	Note string `json:"note"`
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	pref, ok := detector.ParseCIDROrIP(strings.TrimSpace(req.CIDR))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid IP or CIDR")
		return
	}

	actor := actorFromRequest(r)
	entry := store.WhitelistEntry{
		CIDR:      pref.String(),
		Note:      strings.TrimSpace(req.Note),
		CreatedAt: store.NowUnix(),
		CreatedBy: actor,
	}
	if err := s.store.AddWhitelist(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.engine.ReloadWhitelist(r.Context())

	// Automatically unban any currently active IPs covered by the new whitelist entry.
	unbannedCount := 0
	if activeIPs, err := s.store.ListActiveBanIPs(r.Context()); err == nil {
		for _, ip := range activeIPs {
			if addr, err := netip.ParseAddr(ip); err == nil && pref.Contains(addr.Unmap()) {
				if removed, _, err := s.store.RemoveBan(r.Context(), ip, actor, "whitelist_unban", "covered by new whitelist entry"); err == nil && removed {
					s.engine.MarkUnbanned(ip)
					unbannedCount++
				}
			}
		}
	}
	if unbannedCount > 0 {
		s.enforcer.MarkDirty()
	}

	s.syncWhitelistSummaryToKV(r.Context())
	sdk.Infof("fail2ban: whitelist entry added by %s (auto-unbanned %d)", actor, unbannedCount)
	writeJSON(w, http.StatusCreated, map[string]any{
		"entry":         entry,
		"auto_unbanned": unbannedCount,
	})
}

func (s *Server) handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	cidr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if cidr == "" {
		var req struct {
			CIDR string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			cidr = strings.TrimSpace(req.CIDR)
		}
	}
	if cidr == "" {
		writeError(w, http.StatusBadRequest, "cidr is required")
		return
	}
	if pref, ok := detector.ParseCIDROrIP(cidr); ok {
		cidr = pref.String()
	}

	removed, err := s.store.DeleteWhitelist(r.Context(), cidr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "whitelist entry not found")
		return
	}
	_ = s.engine.ReloadWhitelist(r.Context())
	s.syncWhitelistSummaryToKV(r.Context())
	sdk.Infof("fail2ban: whitelist entry removed by %s", actorFromRequest(r))
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "cidr": cidr})
}

func (s *Server) syncWhitelistSummaryToKV(ctx context.Context) {
	items, err := s.store.ListWhitelist(ctx)
	if err != nil {
		return
	}
	cfg := s.engine.GlobalConfig()
	summary := make([]string, 0, len(items))
	for _, it := range items {
		summary = append(summary, it.CIDR)
	}
	cfg.WhitelistSummary = summary
	s.engine.SetGlobalConfig(cfg)
	_ = store.SaveGlobalConfig(ctx, s.host, cfg)
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := store.EventQuery{
		Search:  strings.TrimSpace(r.URL.Query().Get("search")),
		Jail:    strings.TrimSpace(r.URL.Query().Get("jail")),
		Action:  strings.TrimSpace(r.URL.Query().Get("action")),
		LogPath: strings.TrimSpace(r.URL.Query().Get("log_path")),
		Limit:   parseIntParam(r, "limit", 50),
		Offset:  parseIntParam(r, "offset", 0),
	}
	items, total, err := s.store.ListEvents(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	})
}

func (s *Server) handleSnippetGuide(w http.ResponseWriter, r *http.Request) {
	var sites []protocol.HostSite
	if s.host != nil && s.host.Ready() {
		if list, err := s.host.SitesList(r.Context()); err == nil {
			sites = list
		}
	}
	if sites == nil {
		sites = []protocol.HostSite{}
	}
	inc := s.enforcer.IncludeDirective()
	writeJSON(w, http.StatusOK, map[string]any{
		"include_directive": inc,
		"http_block_hint":   fmt.Sprintf("http {\n    %s\n}", inc),
		"server_block_hint": fmt.Sprintf("server {\n    %s\n}", inc),
		"sites":             sites,
		"enforcer":          s.enforcer.Status(),
	})
}
