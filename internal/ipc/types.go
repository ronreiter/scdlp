package ipc

type Backend interface {
	AddRule(AddRuleSpec) (int64, error)
	RevokeRule(int64) error
	ListRules(ListReq) ([]RuleRow, error)
	Status() (StatusRow, error)
	TailAudit(TailReq) ([]AuditRow, error)
}

type AddRuleSpec struct {
	FileKey      string `json:"file_key"`
	FileKeyKind  string `json:"file_key_kind"`
	IdentityKey  string `json:"identity_key"`
	IdentityKind string `json:"identity_kind"`
	Verdict      string `json:"verdict"`
	ExpiresAt    *int64 `json:"expires_at,omitempty"`
	Note         string `json:"note,omitempty"`
}

type RuleRow struct {
	ID           int64  `json:"id"`
	FileKey      string `json:"file_key"`
	FileKeyKind  string `json:"file_key_kind"`
	IdentityKey  string `json:"identity_key"`
	IdentityKind string `json:"identity_kind"`
	Verdict      string `json:"verdict"`
	CreatedAt    int64  `json:"created_at"`
	CreatedBy    string `json:"created_by"`
	ExpiresAt    *int64 `json:"expires_at,omitempty"`
	Note         string `json:"note,omitempty"`
}

type ListReq struct {
	Verdict string `json:"verdict,omitempty"`
}

type StatusRow struct {
	Healthy      bool   `json:"healthy"`
	RulesTotal   int    `json:"rules_total"`
	AuditEvents  int    `json:"audit_events"`
	HelperOnline bool   `json:"helper_online"`
	UptimeSec    int64  `json:"uptime_sec"`
	Mode         string `json:"mode"`
}

type TailReq struct {
	Since   int64  `json:"since,omitempty"`
	Verdict string `json:"verdict,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

type AuditRow struct {
	ID           int64  `json:"id"`
	TS           int64  `json:"ts"`
	FilePath     string `json:"file_path"`
	FileKey      string `json:"file_key"`
	FileKeyKind  string `json:"file_key_kind"`
	ProcessPID   int    `json:"process_pid"`
	ProcessExe   string `json:"process_exe"`
	ProcessChain string `json:"process_chain"`
	IdentityKey  string `json:"identity_key"`
	Verdict      string `json:"verdict"`
	MatchedKind  string `json:"matched_kind"`
	DurationUs   int64  `json:"duration_us"`
}
