package store

import "time"

// BanRecord represents a currently active IP ban.
type BanRecord struct {
	IP           string `json:"ip"`
	Jail         string `json:"jail"`
	Reason       string `json:"reason"`
	LogPath      string `json:"log_path,omitempty"`
	HitCount     int    `json:"hit_count"`
	OffenseCount int    `json:"offense_count"`
	BannedAt     int64  `json:"banned_at"`
	ExpiresAt    int64  `json:"expires_at"` // 0 means permanent
	CreatedBy    string `json:"created_by"`
}

// BanEvent is an immutable audit log entry for ban/unban/extend/whitelist actions.
type BanEvent struct {
	ID          int64  `json:"id"`
	IP          string `json:"ip"`
	Jail        string `json:"jail"`
	Action      string `json:"action"` // ban, unban, expire, extend, whitelist_unban
	Reason      string `json:"reason"`
	LogPath     string `json:"log_path,omitempty"`
	DurationSec int64  `json:"duration_sec"`
	Actor       string `json:"actor"`
	CreatedAt   int64  `json:"created_at"`
}

// WhitelistEntry represents an IP or CIDR network excluded from banning.
type WhitelistEntry struct {
	CIDR      string `json:"cidr"`
	Note      string `json:"note"`
	CreatedAt int64  `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

// JailConfig defines the runtime configuration of a detection jail.
type JailConfig struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Enabled          bool     `json:"enabled"`
	Threshold        int      `json:"threshold"`
	WindowSec        int      `json:"window_sec"`
	BanDurationSec   int64    `json:"ban_duration_sec"`
	StatusCodes      []int    `json:"status_codes,omitempty"`
	Methods          []string `json:"methods,omitempty"`
	PathPrefixes     []string `json:"path_prefixes,omitempty"`
	Patterns         []string `json:"patterns,omitempty"`
	ExcludeExts      []string `json:"exclude_exts,omitempty"`
	DeduplicateURI   bool     `json:"deduplicate_uri,omitempty"`
	LogPaths         []string `json:"log_paths,omitempty"`
	EscalationLevels []int64  `json:"escalation_levels,omitempty"` // For recidive-escalation
	UpdatedAt        int64    `json:"updated_at"`
}

// GlobalConfig stores lightweight plugin-wide tuning persisted in host KV.
type GlobalConfig struct {
	SchemaVersion      int      `json:"schema_version"`
	Enabled            bool     `json:"enabled"`
	DebounceSec        int      `json:"debounce_sec"`
	MaxWaitSec         int      `json:"max_wait_sec"`
	MaxTrackedIPs      int      `json:"max_tracked_ips"`
	NotifyWaveCount    int      `json:"notify_wave_count"`
	NotifyWaveWindowS  int      `json:"notify_wave_window_sec"`
	AuditRetentionDays int      `json:"audit_retention_days"`
	WhitelistSummary   []string `json:"whitelist_summary,omitempty"`
}

// DefaultGlobalConfig returns safe defaults tuned for 128 MiB cgroup v2 limits.
func DefaultGlobalConfig() GlobalConfig {
	return GlobalConfig{
		SchemaVersion:      1,
		Enabled:            true,
		DebounceSec:        3,
		MaxWaitSec:         10,
		MaxTrackedIPs:      50000,
		NotifyWaveCount:    20,
		NotifyWaveWindowS:  60,
		AuditRetentionDays: 30,
	}
}

// BanQuery filters active bans.
type BanQuery struct {
	Search string
	Jail   string
	Limit  int
	Offset int
}

// EventQuery filters historical ban audit events.
type EventQuery struct {
	Search  string
	Jail    string
	Action  string
	LogPath string
	Limit   int
	Offset  int
}

// LogPathStat summarizes recent threat hits per nginx access log path.
type LogPathStat struct {
	LogPath    string `json:"log_path"`
	ActiveBans int    `json:"active_bans"`
	RecentHits int    `json:"recent_hits"`
	LastHitAt  int64  `json:"last_hit_at"`
}

// NowUnix returns current UTC unix timestamp in seconds.
func NowUnix() int64 {
	return time.Now().UTC().Unix()
}
