package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

const recidiveWindowSec = 7 * 24 * 3600

// Store wraps a crash-safe SQLite WAL database for Fail2ban state.
type Store struct {
	db *sql.DB
	mu sync.Mutex // serializes multi-statement write transactions cleanly
}

// Open initializes or opens the SQLite database inside dataDir.
// If dbPath is ":memory:", an in-memory database is opened (useful for tests).
func Open(dbPath string) (*Store, error) {
	if dbPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
			return nil, fmt.Errorf("store: mkdir %s: %w", filepath.Dir(dbPath), err)
		}
	}

	dsn := dbPath
	if dbPath != ":memory:" {
		dsn = fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=cache_size(-16000)&_pragma=foreign_keys(ON)", dbPath)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}

	// Single writer connection keeps SQLite WAL predictable and avoids SQLITE_BUSY spikes.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if dbPath == ":memory:" {
		for _, pragma := range []string{
			"PRAGMA synchronous=NORMAL;",
			"PRAGMA busy_timeout=5000;",
			"PRAGMA cache_size=-16000;",
		} {
			if _, err := db.Exec(pragma); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("store: pragma %q: %w", pragma, err)
			}
		}
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close checkpoints the WAL and closes the database cleanly.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	return s.db.Close()
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS active_bans (
	ip TEXT PRIMARY KEY,
	jail TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	log_path TEXT NOT NULL DEFAULT '',
	hit_count INTEGER NOT NULL DEFAULT 1,
	offense_count INTEGER NOT NULL DEFAULT 1,
	banned_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	created_by TEXT NOT NULL DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS idx_active_bans_expires_at ON active_bans(expires_at);
CREATE INDEX IF NOT EXISTS idx_active_bans_jail ON active_bans(jail);
CREATE INDEX IF NOT EXISTS idx_active_bans_log_path ON active_bans(log_path);

CREATE TABLE IF NOT EXISTS ban_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT NOT NULL,
	jail TEXT NOT NULL,
	action TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	log_path TEXT NOT NULL DEFAULT '',
	duration_sec INTEGER NOT NULL DEFAULT 0,
	actor TEXT NOT NULL DEFAULT 'system',
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ban_events_created_at ON ban_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ban_events_log_path ON ban_events(log_path, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ban_events_ip ON ban_events(ip);

CREATE TABLE IF NOT EXISTS recidive_history (
	ip TEXT PRIMARY KEY,
	offense_count INTEGER NOT NULL DEFAULT 1,
	last_banned_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recidive_expires_at ON recidive_history(expires_at);

CREATE TABLE IF NOT EXISTS whitelist (
	cidr TEXT PRIMARY KEY,
	note TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	created_by TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS jail_configs (
	id TEXT PRIMARY KEY,
	enabled INTEGER NOT NULL DEFAULT 1,
	config_json TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// UpsertBan inserts or updates an active ban, increments recidive history, and records an audit event.
// Returns the stored BanRecord (including updated OffenseCount) and the audit event.
func (s *Store) UpsertBan(ctx context.Context, rec BanRecord, recordRecidive bool) (BanRecord, BanEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := rec.BannedAt
	if now == 0 {
		now = NowUnix()
		rec.BannedAt = now
	}
	if rec.CreatedBy == "" {
		rec.CreatedBy = "system"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rec, BanEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// Automatic bans (recordRecidive == true) must never overwrite an active manual
	// or permanent ban, nor inflate recidive_history for an IP already actively banned.
	if recordRecidive {
		var existing BanRecord
		err := tx.QueryRowContext(ctx,
			`SELECT ip, jail, reason, log_path, hit_count, offense_count, banned_at, expires_at, created_by
			 FROM active_bans WHERE ip = ?`,
			rec.IP,
		).Scan(
			&existing.IP, &existing.Jail, &existing.Reason, &existing.LogPath,
			&existing.HitCount, &existing.OffenseCount, &existing.BannedAt,
			&existing.ExpiresAt, &existing.CreatedBy,
		)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return rec, BanEvent{}, err
		}
		if err == nil && (existing.ExpiresAt == 0 || existing.ExpiresAt > now) {
			if existing.Jail == "manual" || existing.ExpiresAt == 0 || (rec.ExpiresAt > 0 && existing.ExpiresAt >= rec.ExpiresAt) {
				return existing, BanEvent{}, nil
			}
		}

		var prevCount int
		var prevExpires int64
		err = tx.QueryRowContext(ctx,
			`SELECT offense_count, expires_at FROM recidive_history WHERE ip = ?`,
			rec.IP,
		).Scan(&prevCount, &prevExpires)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && prevExpires < now) {
			rec.OffenseCount = 1
		} else if err == nil {
			rec.OffenseCount = prevCount + 1
		} else {
			return rec, BanEvent{}, err
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO recidive_history (ip, offense_count, last_banned_at, expires_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(ip) DO UPDATE SET
			   offense_count = excluded.offense_count,
			   last_banned_at = excluded.last_banned_at,
			   expires_at = excluded.expires_at`,
			rec.IP, rec.OffenseCount, now, now+recidiveWindowSec,
		); err != nil {
			return rec, BanEvent{}, err
		}
	} else if rec.OffenseCount <= 0 {
		rec.OffenseCount = 1
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO active_bans (ip, jail, reason, log_path, hit_count, offense_count, banned_at, expires_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET
		   jail = excluded.jail,
		   reason = excluded.reason,
		   log_path = CASE WHEN excluded.log_path != '' THEN excluded.log_path ELSE active_bans.log_path END,
		   hit_count = active_bans.hit_count + excluded.hit_count,
		   offense_count = excluded.offense_count,
		   banned_at = excluded.banned_at,
		   expires_at = excluded.expires_at,
		   created_by = excluded.created_by`,
		rec.IP, rec.Jail, rec.Reason, rec.LogPath, rec.HitCount, rec.OffenseCount, rec.BannedAt, rec.ExpiresAt, rec.CreatedBy,
	); err != nil {
		return rec, BanEvent{}, err
	}

	var dur int64
	if rec.ExpiresAt > rec.BannedAt {
		dur = rec.ExpiresAt - rec.BannedAt
	}
	ev := BanEvent{
		IP:          rec.IP,
		Jail:        rec.Jail,
		Action:      "ban",
		Reason:      rec.Reason,
		LogPath:     rec.LogPath,
		DurationSec: dur,
		Actor:       rec.CreatedBy,
		CreatedAt:   now,
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO ban_events (ip, jail, action, reason, log_path, duration_sec, actor, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.IP, ev.Jail, ev.Action, ev.Reason, ev.LogPath, ev.DurationSec, ev.Actor, ev.CreatedAt,
	)
	if err != nil {
		return rec, BanEvent{}, err
	}
	ev.ID, _ = res.LastInsertId()

	if err := tx.Commit(); err != nil {
		return rec, BanEvent{}, err
	}
	return rec, ev, nil
}

// GetOffenseCount returns the active 7-day offense count for an IP.
func (s *Store) GetOffenseCount(ctx context.Context, ip string, now int64) (int, error) {
	var count int
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT offense_count, expires_at FROM recidive_history WHERE ip = ?`,
		ip,
	).Scan(&count, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && expires < now) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return count, nil
}

// RemoveBan deletes an active ban and logs an unban audit event.
func (s *Store) RemoveBan(ctx context.Context, ip, actor, action, reason string) (bool, BanEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if actor == "" {
		actor = "system"
	}
	if action == "" {
		action = "unban"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, BanEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var jail, logPath string
	err = tx.QueryRowContext(ctx, `SELECT jail, log_path FROM active_bans WHERE ip = ?`, ip).Scan(&jail, &logPath)
	if errors.Is(err, sql.ErrNoRows) {
		return false, BanEvent{}, nil
	}
	if err != nil {
		return false, BanEvent{}, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM active_bans WHERE ip = ?`, ip); err != nil {
		return false, BanEvent{}, err
	}

	ev := BanEvent{
		IP:        ip,
		Jail:      jail,
		Action:    action,
		Reason:    reason,
		LogPath:   logPath,
		Actor:     actor,
		CreatedAt: NowUnix(),
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO ban_events (ip, jail, action, reason, log_path, duration_sec, actor, created_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		ev.IP, ev.Jail, ev.Action, ev.Reason, ev.LogPath, ev.Actor, ev.CreatedAt,
	)
	if err != nil {
		return false, BanEvent{}, err
	}
	ev.ID, _ = res.LastInsertId()

	if err := tx.Commit(); err != nil {
		return false, BanEvent{}, err
	}
	return true, ev, nil
}

// ExtendBan extends an active ban's expiration by extraSec (or makes it permanent if extraSec == 0).
func (s *Store) ExtendBan(ctx context.Context, ip string, extraSec int64, actor string) (BanRecord, BanEvent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if actor == "" {
		actor = "admin"
	}
	now := NowUnix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BanRecord{}, BanEvent{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var rec BanRecord
	err = tx.QueryRowContext(ctx,
		`SELECT ip, jail, reason, log_path, hit_count, offense_count, banned_at, expires_at, created_by
		 FROM active_bans WHERE ip = ?`,
		ip,
	).Scan(&rec.IP, &rec.Jail, &rec.Reason, &rec.LogPath, &rec.HitCount, &rec.OffenseCount, &rec.BannedAt, &rec.ExpiresAt, &rec.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return BanRecord{}, BanEvent{}, false, nil
	}
	if err != nil {
		return BanRecord{}, BanEvent{}, false, err
	}

	if extraSec <= 0 {
		rec.ExpiresAt = 0 // permanent
	} else {
		base := rec.ExpiresAt
		if base < now {
			base = now
		}
		rec.ExpiresAt = base + extraSec
	}

	if _, err := tx.ExecContext(ctx, `UPDATE active_bans SET expires_at = ? WHERE ip = ?`, rec.ExpiresAt, ip); err != nil {
		return BanRecord{}, BanEvent{}, false, err
	}

	ev := BanEvent{
		IP:          ip,
		Jail:        rec.Jail,
		Action:      "extend",
		Reason:      "manual ban extension",
		LogPath:     rec.LogPath,
		DurationSec: extraSec,
		Actor:       actor,
		CreatedAt:   now,
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO ban_events (ip, jail, action, reason, log_path, duration_sec, actor, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.IP, ev.Jail, ev.Action, ev.Reason, ev.LogPath, ev.DurationSec, ev.Actor, ev.CreatedAt,
	)
	if err != nil {
		return BanRecord{}, BanEvent{}, false, err
	}
	ev.ID, _ = res.LastInsertId()

	if err := tx.Commit(); err != nil {
		return BanRecord{}, BanEvent{}, false, err
	}
	return rec, ev, true, nil
}

// ExpireBans removes all bans whose expires_at > 0 and expires_at <= now.
// Also cleans up expired recidive_history entries.
func (s *Store) ExpireBans(ctx context.Context, now int64) ([]BanEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx,
		`SELECT ip, jail, log_path FROM active_bans WHERE expires_at > 0 AND expires_at <= ?`,
		now,
	)
	if err != nil {
		return nil, err
	}
	type expiredItem struct {
		ip      string
		jail    string
		logPath string
	}
	var expired []expiredItem
	for rows.Next() {
		var it expiredItem
		if err := rows.Scan(&it.ip, &it.jail, &it.logPath); err != nil {
			_ = rows.Close()
			return nil, err
		}
		expired = append(expired, it)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM active_bans WHERE expires_at > 0 AND expires_at <= ?`, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM recidive_history WHERE expires_at <= ?`, now); err != nil {
		return nil, err
	}

	events := make([]BanEvent, 0, len(expired))
	for _, it := range expired {
		ev := BanEvent{
			IP:        it.ip,
			Jail:      it.jail,
			Action:    "expire",
			Reason:    "ban duration expired",
			LogPath:   it.logPath,
			Actor:     "system",
			CreatedAt: now,
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO ban_events (ip, jail, action, reason, log_path, duration_sec, actor, created_at)
			 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
			ev.IP, ev.Jail, ev.Action, ev.Reason, ev.LogPath, ev.Actor, ev.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		ev.ID, _ = res.LastInsertId()
		events = append(events, ev)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// ListActiveBanIPs returns all currently active banned IPs sorted lexicographically.
func (s *Store) ListActiveBanIPs(ctx context.Context) ([]string, error) {
	now := NowUnix()
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip FROM active_bans WHERE expires_at = 0 OR expires_at > ? ORDER BY ip ASC`,
		now,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

// ListAllActiveBans returns all currently active bans without any row limit.
func (s *Store) ListAllActiveBans(ctx context.Context) ([]BanRecord, error) {
	return s.ListActiveBansForBlocklist(ctx, "")
}

// ListActiveBansForBlocklist returns all currently active bans sorted by IP,
// optionally filtered by jail ID, for exporting via security.blocklist.
func (s *Store) ListActiveBansForBlocklist(ctx context.Context, jail string) ([]BanRecord, error) {
	now := NowUnix()
	var (
		rows *sql.Rows
		err  error
	)
	if jail != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT ip, jail, reason, log_path, hit_count, offense_count, banned_at, expires_at, created_by
			 FROM active_bans WHERE (expires_at = 0 OR expires_at > ?) AND jail = ? ORDER BY ip ASC`,
			now, jail,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT ip, jail, reason, log_path, hit_count, offense_count, banned_at, expires_at, created_by
			 FROM active_bans WHERE expires_at = 0 OR expires_at > ? ORDER BY ip ASC`,
			now,
		)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]BanRecord, 0)
	for rows.Next() {
		var r BanRecord
		if err := rows.Scan(&r.IP, &r.Jail, &r.Reason, &r.LogPath, &r.HitCount, &r.OffenseCount, &r.BannedAt, &r.ExpiresAt, &r.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListBans returns filtered active bans and total matching count.
func (s *Store) ListBans(ctx context.Context, q BanQuery) ([]BanRecord, int, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}

	var where []string
	var args []any
	now := NowUnix()
	where = append(where, "(expires_at = 0 OR expires_at > ?)")
	args = append(args, now)

	if q.Jail != "" {
		where = append(where, "jail = ?")
		args = append(args, q.Jail)
	}
	if q.Search != "" {
		where = append(where, "(ip LIKE ? OR reason LIKE ? OR log_path LIKE ?)")
		pat := "%" + q.Search + "%"
		args = append(args, pat, pat, pat)
	}

	clause := "WHERE " + strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM active_bans `+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	queryArgs := append(append([]any{}, args...), q.Limit, q.Offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip, jail, reason, log_path, hit_count, offense_count, banned_at, expires_at, created_by
		 FROM active_bans `+clause+` ORDER BY banned_at DESC LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]BanRecord, 0)
	for rows.Next() {
		var r BanRecord
		if err := rows.Scan(&r.IP, &r.Jail, &r.Reason, &r.LogPath, &r.HitCount, &r.OffenseCount, &r.BannedAt, &r.ExpiresAt, &r.CreatedBy); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ListEvents returns historical ban audit events in reverse chronological order.
func (s *Store) ListEvents(ctx context.Context, q EventQuery) ([]BanEvent, int, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}

	var where []string
	var args []any
	if q.Jail != "" {
		where = append(where, "jail = ?")
		args = append(args, q.Jail)
	}
	if q.Action != "" {
		where = append(where, "action = ?")
		args = append(args, q.Action)
	}
	if q.LogPath != "" {
		where = append(where, "log_path = ?")
		args = append(args, q.LogPath)
	}
	if q.Search != "" {
		where = append(where, "(ip LIKE ? OR reason LIKE ?)")
		pat := "%" + q.Search + "%"
		args = append(args, pat, pat)
	}

	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ban_events `+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	queryArgs := append(append([]any{}, args...), q.Limit, q.Offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ip, jail, action, reason, log_path, duration_sec, actor, created_at
		 FROM ban_events `+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]BanEvent, 0)
	for rows.Next() {
		var e BanEvent
		if err := rows.Scan(&e.ID, &e.IP, &e.Jail, &e.Action, &e.Reason, &e.LogPath, &e.DurationSec, &e.Actor, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// PruneOldEvents removes audit events older than retentionDays to keep DB size bounded.
func (s *Store) PruneOldEvents(ctx context.Context, retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := NowUnix() - int64(retentionDays)*86400
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `DELETE FROM ban_events WHERE created_at < ?`, cutoff)
	return err
}

// ListWhitelist returns all configured whitelist CIDR entries.
func (s *Store) ListWhitelist(ctx context.Context) ([]WhitelistEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cidr, note, created_at, created_by FROM whitelist ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]WhitelistEntry, 0)
	for rows.Next() {
		var w WhitelistEntry
		if err := rows.Scan(&w.CIDR, &w.Note, &w.CreatedAt, &w.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// AddWhitelist adds or updates a whitelist CIDR entry.
func (s *Store) AddWhitelist(ctx context.Context, entry WhitelistEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.CreatedAt == 0 {
		entry.CreatedAt = NowUnix()
	}
	if entry.CreatedBy == "" {
		entry.CreatedBy = "admin"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO whitelist (cidr, note, created_at, created_by)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(cidr) DO UPDATE SET note = excluded.note`,
		entry.CIDR, entry.Note, entry.CreatedAt, entry.CreatedBy,
	)
	return err
}

// DeleteWhitelist removes a whitelist CIDR entry.
func (s *Store) DeleteWhitelist(ctx context.Context, cidr string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, `DELETE FROM whitelist WHERE cidr = ?`, cidr)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SaveJailConfig persists a jail's configuration.
func (s *Store) SaveJailConfig(ctx context.Context, cfg JailConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.UpdatedAt = NowUnix()
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO jail_configs (id, enabled, config_json, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, config_json = excluded.config_json, updated_at = excluded.updated_at`,
		cfg.ID, enabled, string(raw), cfg.UpdatedAt,
	)
	return err
}

// LoadJailConfigs loads all persisted jail configurations keyed by jail ID.
func (s *Store) LoadJailConfigs(ctx context.Context) (map[string]JailConfig, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT config_json FROM jail_configs`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]JailConfig)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cfg JailConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			continue
		}
		out[cfg.ID] = cfg
	}
	return out, rows.Err()
}

// LogPathStats returns per-log-path active ban counts and 24-hour ban hits (for nginx_log slots).
func (s *Store) LogPathStats(ctx context.Context, sinceUnix int64) ([]LogPathStat, error) {
	now := NowUnix()
	statsMap := make(map[string]*LogPathStat)

	rows, err := s.db.QueryContext(ctx,
		`SELECT log_path, COUNT(*) FROM active_bans
		 WHERE log_path != '' AND (expires_at = 0 OR expires_at > ?)
		 GROUP BY log_path`,
		now,
	)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var lp string
		var cnt int
		if err := rows.Scan(&lp, &cnt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		statsMap[lp] = &LogPathStat{LogPath: lp, ActiveBans: cnt}
	}
	_ = rows.Close()

	evRows, err := s.db.QueryContext(ctx,
		`SELECT log_path, COUNT(*), MAX(created_at) FROM ban_events
		 WHERE log_path != '' AND action = 'ban' AND created_at >= ?
		 GROUP BY log_path`,
		sinceUnix,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = evRows.Close() }()

	for evRows.Next() {
		var lp string
		var cnt int
		var last int64
		if err := evRows.Scan(&lp, &cnt, &last); err != nil {
			return nil, err
		}
		st, ok := statsMap[lp]
		if !ok {
			st = &LogPathStat{LogPath: lp}
			statsMap[lp] = st
		}
		st.RecentHits = cnt
		st.LastHitAt = last
	}

	out := make([]LogPathStat, 0, len(statsMap))
	for _, st := range statsMap {
		out = append(out, *st)
	}
	return out, evRows.Err()
}

// CountActiveBans returns the number of currently active bans.
func (s *Store) CountActiveBans(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM active_bans WHERE expires_at = 0 OR expires_at > ?`,
		NowUnix(),
	).Scan(&n)
	return n, err
}

// CountBansSince returns the number of ban events created since the given unix timestamp.
func (s *Store) CountBansSince(ctx context.Context, since int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ban_events WHERE action = 'ban' AND created_at >= ?`,
		since,
	).Scan(&n)
	return n, err
}
