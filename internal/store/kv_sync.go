package store

import (
	"context"
)

const kvGlobalConfigKey = "global_config"

// KVClient abstracts host.kv.* calls so storage logic is unit-testable without a live host.
type KVClient interface {
	Ready() bool
	KVGet(ctx context.Context, key string, out any) (bool, error)
	KVSet(ctx context.Context, key string, value any) error
}

// LoadGlobalConfig loads GlobalConfig from host KV, falling back to DefaultGlobalConfig.
func LoadGlobalConfig(ctx context.Context, kv KVClient) GlobalConfig {
	def := DefaultGlobalConfig()
	if kv == nil || !kv.Ready() {
		return def
	}
	var cfg GlobalConfig
	found, err := kv.KVGet(ctx, kvGlobalConfigKey, &cfg)
	if err != nil || !found {
		return def
	}
	if cfg.SchemaVersion <= 0 {
		cfg.SchemaVersion = def.SchemaVersion
	}
	if cfg.DebounceSec < 1 || cfg.DebounceSec > 30 {
		cfg.DebounceSec = def.DebounceSec
	}
	if cfg.MaxWaitSec < cfg.DebounceSec || cfg.MaxWaitSec > 60 {
		cfg.MaxWaitSec = def.MaxWaitSec
	}
	if cfg.MaxTrackedIPs < 1000 || cfg.MaxTrackedIPs > 200000 {
		cfg.MaxTrackedIPs = def.MaxTrackedIPs
	}
	if cfg.AuditRetentionDays <= 0 {
		cfg.AuditRetentionDays = def.AuditRetentionDays
	}
	return cfg
}

// SaveGlobalConfig persists GlobalConfig to host KV (kept well under the 64 KiB limit).
func SaveGlobalConfig(ctx context.Context, kv KVClient, cfg GlobalConfig) error {
	if kv == nil || !kv.Ready() {
		return nil
	}
	// Cap whitelist summary so KV payload stays tiny (< 4 KiB).
	if len(cfg.WhitelistSummary) > 64 {
		cfg.WhitelistSummary = cfg.WhitelistSummary[:64]
	}
	return kv.KVSet(ctx, kvGlobalConfigKey, cfg)
}
