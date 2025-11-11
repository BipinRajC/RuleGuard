package models

import "time"

// Node represents a target server for compliance monitoring
type Node struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Hostname    string    `json:"hostname"`
	Port        int       `json:"port"`
	Username    string    `json:"username"`
	AuthType    string    `json:"auth_type"` // "password" or "key"
	Credentials string    `json:"-"`         // Never expose in JSON
	Description string    `json:"description,omitempty"`
	OSType      string    `json:"os_type,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

// NodeRequest represents the API request to add a node
type NodeRequest struct {
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthType    string `json:"auth_type"` // "password" or "key"
	Password    string `json:"password,omitempty"`
	SSHKey      string `json:"ssh_key,omitempty"`
	Description string `json:"description,omitempty"`
}

// Scan represents a compliance scan execution
type Scan struct {
	ID              int       `json:"id"`
	NodeID          int       `json:"node_id"`
	Profile         string    `json:"profile"`
	Status          string    `json:"status"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	DurationSeconds *int      `json:"duration_seconds,omitempty"`
	ComplianceScore *float64  `json:"compliance_score,omitempty"`
	TotalRules      *int      `json:"total_rules,omitempty"`
	PassedRules     *int      `json:"passed_rules,omitempty"`
	FailedRules     *int      `json:"failed_rules,omitempty"`
	ErrorRules      *int      `json:"error_rules,omitempty"`
	ReportPath      *string   `json:"report_path,omitempty"`
	ErrorMessage    *string   `json:"error_message,omitempty"`
}

// ScanResult represents an individual rule result
type ScanResult struct {
	ID          int    `json:"id"`
	ScanID      int    `json:"scan_id"`
	RuleID      string `json:"rule_id"`
	Result      string `json:"result"`
	CheckOutput string `json:"check_output,omitempty"`
}

// RemediationRequest represents API request to remediate rules
type RemediationRequest struct {
	NodeID  int      `json:"node_id"`
	RuleIDs []string `json:"rule_ids"`
}

// RemediationResponse represents the result of a remediation
type RemediationResponse struct {
	NodeID   int                     `json:"node_id"`
	Fixed    int                     `json:"fixed"`
	Failed   int                     `json:"failed"`
	Results  []RemediationRuleResult `json:"results"`
}

// RemediationRuleResult represents result of remediating a single rule
type RemediationRuleResult struct {
	RuleID  string `json:"rule_id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// APIResponse is a generic API response wrapper
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}
