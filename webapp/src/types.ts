export interface BanRecord {
  ip: string
  jail: string
  reason: string
  log_path?: string
  hit_count: number
  offense_count: number
  banned_at: number
  expires_at: number
  created_by: string
}

export interface BanEvent {
  id: number
  ip: string
  jail: string
  action: 'ban' | 'unban' | 'expire' | 'extend' | 'whitelist_unban' | string
  reason: string
  log_path?: string
  duration_sec: number
  actor: string
  created_at: number
}

export interface WhitelistEntry {
  cidr: string
  note: string
  created_at: number
  created_by: string
}

export interface JailConfig {
  id: string
  name: string
  description: string
  enabled: boolean
  threshold: number
  window_sec: number
  ban_duration_sec: number
  status_codes?: number[]
  methods?: string[]
  path_prefixes?: string[]
  patterns?: string[]
  exclude_exts?: string[]
  deduplicate_uri?: boolean
  log_paths?: string[]
  escalation_levels?: number[]
  updated_at?: number
}

export interface GlobalConfig {
  schema_version: number
  enabled: boolean
  debounce_sec: number
  max_wait_sec: number
  max_tracked_ips: number
  notify_wave_count: number
  notify_wave_window_sec: number
  audit_retention_days: number
}

export interface EngineStats {
  enabled: boolean
  queue_depth: number
  queue_capacity: number
  tracked_entries: number
  max_tracked_ips: number
  logs_processed: number
  logs_dropped: number
  bans_triggered: number
  whitelisted_skips: number
}

export interface EnforcerStatus {
  backend: string
  include_directive: string
  active_rule_count: number
  shard_count: number
  last_sync_at: number
  last_sync_changed: boolean
  last_error?: string
  pending_dirty: boolean
}

export interface LogPathStat {
  log_path: string
  active_bans: number
  recent_hits: number
  last_hit_at: number
}

export interface StatusResponse {
  config: GlobalConfig
  engine: EngineStats
  enforcer: EnforcerStatus
  active_bans: number
  bans_24h: number
  log_path_stats: LogPathStat[]
}

export interface HostSite {
  name: string
  status: string
  urls: string[]
  config_file: string
}

export interface SnippetGuideResponse {
  include_directive: string
  http_block_hint: string
  server_block_hint: string
  sites: HostSite[]
  enforcer: EnforcerStatus
}
