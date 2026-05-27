// Package rules is the SQLite-backed allow/deny rule store.
package rules

import (
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type FileKeyKind string

const (
	FKPath     FileKeyKind = "path"
	FKCategory FileKeyKind = "category"
)

type IdentityKind string

const (
	IKChain   IdentityKind = "chain"
	IKExeOnly IdentityKind = "exe-only"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

type Rule struct {
	ID           int64
	FileKey      string
	FileKeyKind  FileKeyKind
	IdentityKey  string
	IdentityKind IdentityKind
	Verdict      Verdict
	CreatedAt    int64
	CreatedBy    string
	ExpiresAt    *int64
	Note         string
}

type Store struct {
	db *sql.DB
}

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

func (s *Store) Insert(r Rule) (int64, error) {
	if r.CreatedAt == 0 {
		r.CreatedAt = time.Now().Unix()
	}
	res, err := s.db.Exec(`
		INSERT INTO rules (file_key, file_key_kind, identity_key, identity_kind,
		                   verdict, created_at, created_by, expires_at, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.FileKey, string(r.FileKeyKind), r.IdentityKey, string(r.IdentityKind),
		string(r.Verdict), r.CreatedAt, r.CreatedBy, r.ExpiresAt, r.Note,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

type LookupKey struct {
	PathKey     string
	CategoryKey string
	ChainKey    string
	ExeKey      string
	Now         int64
}

func (s *Store) Lookup(k LookupKey) (*Rule, error) {
	row := s.db.QueryRow(`
		SELECT id, file_key, file_key_kind, identity_key, identity_kind,
		       verdict, created_at, created_by, expires_at, COALESCE(note,'')
		  FROM rules
		 WHERE ((file_key_kind = 'path'     AND file_key = ?)
		     OR (file_key_kind = 'category' AND file_key = ?))
		   AND ((identity_kind = 'chain'    AND identity_key = ?)
		     OR (identity_kind = 'exe-only' AND identity_key = ?))
		   AND (expires_at IS NULL OR expires_at > ?)
		 ORDER BY
		   CASE file_key_kind WHEN 'path'  THEN 0 ELSE 1 END,
		   CASE identity_kind WHEN 'chain' THEN 0 ELSE 1 END
		 LIMIT 1`,
		k.PathKey, k.CategoryKey, k.ChainKey, k.ExeKey, k.Now,
	)
	var r Rule
	var exp sql.NullInt64
	err := row.Scan(&r.ID, &r.FileKey, &r.FileKeyKind, &r.IdentityKey, &r.IdentityKind,
		&r.Verdict, &r.CreatedAt, &r.CreatedBy, &exp, &r.Note)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if exp.Valid {
		v := exp.Int64
		r.ExpiresAt = &v
	}
	return &r, nil
}

type ListFilter struct {
	Verdict Verdict
}

func (s *Store) List(f ListFilter) ([]Rule, error) {
	q := `SELECT id, file_key, file_key_kind, identity_key, identity_kind,
	             verdict, created_at, created_by, expires_at, COALESCE(note,'')
	        FROM rules`
	args := []any{}
	if f.Verdict != "" {
		q += ` WHERE verdict = ?`
		args = append(args, string(f.Verdict))
	}
	q += ` ORDER BY created_at DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var exp sql.NullInt64
		if err := rows.Scan(&r.ID, &r.FileKey, &r.FileKeyKind, &r.IdentityKey, &r.IdentityKind,
			&r.Verdict, &r.CreatedAt, &r.CreatedBy, &exp, &r.Note); err != nil {
			return nil, err
		}
		if exp.Valid {
			v := exp.Int64
			r.ExpiresAt = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Revoke(id int64) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE id = ?`, id)
	return err
}
