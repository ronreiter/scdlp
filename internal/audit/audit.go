// Package audit is the append-only decision log.
package audit

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type Event struct {
	ID           int64
	TS           int64
	FilePath     string
	FileKey      string
	FileKeyKind  string
	ProcessPID   int
	ProcessExe   string
	ProcessChain string
	IdentityKey  string
	Verdict      string
	RuleID       *int64
	MatchedKind  string
	DurationUs   int64
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Log(e Event) error {
	_, err := s.db.Exec(`
		INSERT INTO audit (ts, file_path, file_key, file_key_kind,
		                   process_pid, process_exe, process_chain,
		                   identity_key, verdict, rule_id, matched_kind,
		                   duration_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.FilePath, e.FileKey, e.FileKeyKind,
		e.ProcessPID, e.ProcessExe, e.ProcessChain,
		e.IdentityKey, e.Verdict, e.RuleID, e.MatchedKind,
		e.DurationUs,
	)
	return err
}

type TailFilter struct {
	Since   int64
	Verdict string
	Limit   int
}

func (s *Store) Tail(f TailFilter) ([]Event, error) {
	q := `SELECT id, ts, file_path, file_key, file_key_kind, process_pid,
	             process_exe, process_chain, identity_key, verdict, rule_id,
	             COALESCE(matched_kind,''), duration_us
	        FROM audit WHERE 1=1`
	args := []any{}
	if f.Since > 0 {
		q += ` AND ts >= ?`
		args = append(args, f.Since)
	}
	if f.Verdict != "" {
		q += ` AND verdict = ?`
		args = append(args, f.Verdict)
	}
	q += ` ORDER BY ts DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ruleID sql.NullInt64
		if err := rows.Scan(&e.ID, &e.TS, &e.FilePath, &e.FileKey, &e.FileKeyKind,
			&e.ProcessPID, &e.ProcessExe, &e.ProcessChain, &e.IdentityKey,
			&e.Verdict, &ruleID, &e.MatchedKind, &e.DurationUs); err != nil {
			return nil, err
		}
		if ruleID.Valid {
			v := ruleID.Int64
			e.RuleID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Count returns the total number of audit rows.
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&n)
	return n, err
}
