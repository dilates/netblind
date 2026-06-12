package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Rule represents a persistent allow/block/ask decision for an application.
type Rule struct {
	ID        int64
	AppPath   string
	AppName   string
	Action    string // "allow", "block", "ask"
	CreatedAt time.Time
	UpdatedAt time.Time
}

// LogEntry represents a single connection event in the traffic log.
type LogEntry struct {
	ID      int64
	AppPath string
	AppName string
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
	Proto   string
	Action  string
	TS      time.Time
}

// DB wraps a SQLite database with netblind-specific query methods.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and applies the schema.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := applySchema(db); err != nil {
		db.Close()
		return nil, err
	}
	store := &DB{db: db}
	if err := store.purgeOldLogs(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the underlying database connection.
func (s *DB) Close() error {
	return s.db.Close()
}

func applySchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rules (
			id         INTEGER PRIMARY KEY,
			app_path   TEXT UNIQUE NOT NULL,
			app_name   TEXT NOT NULL,
			action     TEXT NOT NULL CHECK(action IN ('allow','block','ask')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS traffic_log (
			id       INTEGER PRIMARY KEY,
			app_path TEXT NOT NULL,
			app_name TEXT NOT NULL,
			src_ip   TEXT,
			src_port INTEGER,
			dst_ip   TEXT,
			dst_port INTEGER,
			proto    TEXT,
			action   TEXT NOT NULL,
			ts       DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_log_ts ON traffic_log(ts);
	`)
	return err
}

// purgeOldLogs removes traffic_log entries older than 7 days.
func (s *DB) purgeOldLogs() error {
	cutoff := time.Now().AddDate(0, 0, -7).UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`DELETE FROM traffic_log WHERE ts < ?`, cutoff)
	return err
}

// GetRule returns the rule for the given app path, or nil if none exists.
func (s *DB) GetRule(appPath string) (*Rule, error) {
	row := s.db.QueryRow(
		`SELECT id, app_path, app_name, action, created_at, updated_at FROM rules WHERE app_path = ?`,
		appPath,
	)
	r := &Rule{}
	err := row.Scan(&r.ID, &r.AppPath, &r.AppName, &r.Action, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get rule: %w", err)
	}
	return r, nil
}

// SetRule inserts or replaces the rule for the given app path.
func (s *DB) SetRule(appPath, appName, action string) error {
	_, err := s.db.Exec(`
		INSERT INTO rules (app_path, app_name, action, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(app_path) DO UPDATE SET
			app_name   = excluded.app_name,
			action     = excluded.action,
			updated_at = CURRENT_TIMESTAMP
	`, appPath, appName, action)
	if err != nil {
		return fmt.Errorf("set rule: %w", err)
	}
	return nil
}

// GetAllRules returns every rule in the database.
func (s *DB) GetAllRules() ([]Rule, error) {
	rows, err := s.db.Query(
		`SELECT id, app_path, app_name, action, created_at, updated_at FROM rules ORDER BY app_name`,
	)
	if err != nil {
		return nil, fmt.Errorf("get all rules: %w", err)
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.AppPath, &r.AppName, &r.Action, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// DeleteRule removes the rule for the given app path.
func (s *DB) DeleteRule(appPath string) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE app_path = ?`, appPath)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	return nil
}

// InsertLog appends a connection event to the traffic log.
func (s *DB) InsertLog(e LogEntry) error {
	_, err := s.db.Exec(`
		INSERT INTO traffic_log (app_path, app_name, src_ip, src_port, dst_ip, dst_port, proto, action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, e.AppPath, e.AppName, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto, e.Action)
	if err != nil {
		return fmt.Errorf("insert log: %w", err)
	}
	return nil
}

// GetRecentLog returns the most recent N traffic log entries, newest first.
func (s *DB) GetRecentLog(limit int) ([]LogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT id, app_path, app_name, src_ip, src_port, dst_ip, dst_port, proto, action, ts
		FROM traffic_log ORDER BY ts DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("get recent log: %w", err)
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.ID, &e.AppPath, &e.AppName, &e.SrcIP, &e.SrcPort,
			&e.DstIP, &e.DstPort, &e.Proto, &e.Action, &e.TS); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// CountTodayStats returns allowed and blocked connection counts since midnight.
func (s *DB) CountTodayStats() (allowed, blocked int, err error) {
	today := time.Now().UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
	row := s.db.QueryRow(
		`SELECT COUNT(*) FROM traffic_log WHERE action = 'allow' AND ts >= ?`, today,
	)
	if err = row.Scan(&allowed); err != nil {
		return
	}
	row = s.db.QueryRow(
		`SELECT COUNT(*) FROM traffic_log WHERE action = 'block' AND ts >= ?`, today,
	)
	err = row.Scan(&blocked)
	return
}
