package main

import (
	"time"

	"github.com/ronreiter/scdlp/internal/audit"
	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/ronreiter/scdlp/internal/rules"
)

// daemonBackend adapts our rules+audit stores to the ipc.Backend interface.
type daemonBackend struct {
	rdb     *rules.Store
	adb     *audit.Store
	startTS int64
}

func newBackend(r *rules.Store, a *audit.Store) *daemonBackend {
	return &daemonBackend{rdb: r, adb: a, startTS: time.Now().Unix()}
}

func (d *daemonBackend) AddRule(s ipc.AddRuleSpec) (int64, error) {
	return d.rdb.Insert(rules.Rule{
		FileKey: s.FileKey, FileKeyKind: rules.FileKeyKind(s.FileKeyKind),
		IdentityKey: s.IdentityKey, IdentityKind: rules.IdentityKind(s.IdentityKind),
		Verdict: rules.Verdict(s.Verdict), CreatedBy: "ipc",
		ExpiresAt: s.ExpiresAt, Note: s.Note,
	})
}

func (d *daemonBackend) RevokeRule(id int64) error { return d.rdb.Revoke(id) }

func (d *daemonBackend) ListRules(r ipc.ListReq) ([]ipc.RuleRow, error) {
	rs, err := d.rdb.List(rules.ListFilter{Verdict: rules.Verdict(r.Verdict)})
	if err != nil {
		return nil, err
	}
	out := make([]ipc.RuleRow, len(rs))
	for i, x := range rs {
		out[i] = ipc.RuleRow{
			ID: x.ID, FileKey: x.FileKey, FileKeyKind: string(x.FileKeyKind),
			IdentityKey: x.IdentityKey, IdentityKind: string(x.IdentityKind),
			Verdict: string(x.Verdict), CreatedAt: x.CreatedAt, CreatedBy: x.CreatedBy,
			ExpiresAt: x.ExpiresAt, Note: x.Note,
		}
	}
	return out, nil
}

func (d *daemonBackend) Status() (ipc.StatusRow, error) {
	rs, _ := d.rdb.List(rules.ListFilter{})
	n, _ := d.adb.Count()
	return ipc.StatusRow{
		Healthy:     true,
		RulesTotal:  len(rs),
		AuditEvents: n,
		Mode:        "enforce",
		UptimeSec:   time.Now().Unix() - d.startTS,
	}, nil
}

func (d *daemonBackend) TailAudit(r ipc.TailReq) ([]ipc.AuditRow, error) {
	es, err := d.adb.Tail(audit.TailFilter{Since: r.Since, Verdict: r.Verdict, Limit: r.Limit})
	if err != nil {
		return nil, err
	}
	out := make([]ipc.AuditRow, len(es))
	for i, e := range es {
		out[i] = ipc.AuditRow{
			ID: e.ID, TS: e.TS, FilePath: e.FilePath, FileKey: e.FileKey,
			FileKeyKind: e.FileKeyKind, ProcessPID: e.ProcessPID, ProcessExe: e.ProcessExe,
			ProcessChain: e.ProcessChain, IdentityKey: e.IdentityKey,
			Verdict: e.Verdict, MatchedKind: e.MatchedKind, DurationUs: e.DurationUs,
		}
	}
	return out, nil
}
