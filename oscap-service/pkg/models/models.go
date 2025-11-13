package models

import "time"

// Node represents a compute node in the HPC lab
type Node struct {
	ID                  int       `json:"id"`
	Name                string    `json:"name"`
	Hostname            string    `json:"hostname"`
	Description         string    `json:"description,omitempty"`
	OSType              string    `json:"os_type,omitempty"`
	NodeType            string    `json:"node_type"`
	IsActive            bool      `json:"is_active"`
	CurrentComplianceScore *float64 `json:"current_compliance_score,omitempty"`
	CurrentStatus       string    `json:"current_status,omitempty"`
	LastScanAt          *time.Time `json:"last_scan_at,omitempty"`
	LastHeartbeat       *time.Time `json:"last_heartbeat,omitempty"`
	ScanIntervalMinutes int       `json:"scan_interval_minutes"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Scan represents a compliance scan execution
type Scan struct {
	ID              int        `json:"id"`
	NodeID          int        `json:"node_id"`
	Profile         string     `json:"profile"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	DurationSeconds *int       `json:"duration_seconds,omitempty"`
	ComplianceScore *float64   `json:"compliance_score,omitempty"`
	TotalRules      *int       `json:"total_rules,omitempty"`
	PassedRules     *int       `json:"passed_rules,omitempty"`
	FailedRules     *int       `json:"failed_rules,omitempty"`
	ErrorRules      *int       `json:"error_rules,omitempty"`
	NotApplicable   *int       `json:"not_applicable,omitempty"`
	NotChecked      *int       `json:"not_checked,omitempty"`
	ReportHTMLPath  *string    `json:"report_html_path,omitempty"`
	ReportPDFPath   *string    `json:"report_pdf_path,omitempty"`
	ReportXMLPath   *string    `json:"report_xml_path,omitempty"`
	ErrorMessage    *string    `json:"error_message,omitempty"`
}

// ScanResult represents an individual rule result
type ScanResult struct {
	ID          int       `json:"id"`
	ScanID      int       `json:"scan_id"`
	RuleID      string    `json:"rule_id"`
	Result      string    `json:"result"`
	Severity    string    `json:"severity,omitempty"`
	CheckOutput *string   `json:"check_output,omitempty"`
	FixText     *string   `json:"fix_text,omitempty"`
	RecordedAt  time.Time `json:"recorded_at"`
}

// RuleBaseline represents rule metadata
type RuleBaseline struct {
	RuleID                 string   `json:"rule_id"`
	Title                  string   `json:"title"`
	Description            string   `json:"description,omitempty"`
	Rationale              string   `json:"rationale,omitempty"`
	Severity               string   `json:"severity"`
	RequiresSudo           bool     `json:"requires_sudo"`
	RequiresReboot         bool     `json:"requires_reboot"`
	AffectedFiles          []string `json:"affected_files,omitempty"`
	AffectedPackages       []string `json:"affected_packages,omitempty"`
	AffectedServices       []string `json:"affected_services,omitempty"`
	RemediationComplexity  string   `json:"remediation_complexity"`
	EstimatedDurationSecs  *int     `json:"estimated_duration_secs,omitempty"`
	IsRemediable           bool     `json:"is_remediable"`
}

// Remediation represents a remediation execution
type Remediation struct {
	ID             int        `json:"id"`
	NodeID         int        `json:"node_id"`
	ScanID         *int       `json:"scan_id,omitempty"`
	CheckpointID   *int       `json:"checkpoint_id,omitempty"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	DurationSecs   *int       `json:"duration_secs,omitempty"`
	RulesAttempted int        `json:"rules_attempted"`
	RulesSucceeded int        `json:"rules_succeeded"`
	RulesFailed    int        `json:"rules_failed"`
	ErrorMessage   *string    `json:"error_message,omitempty"`
	ExecutedBy     string     `json:"executed_by"`
	InitiatedBy    string     `json:"initiated_by"`
	RemediatedBy   string     `json:"remediated_by,omitempty"`
}

// RemediationAction represents a single remediation action
type RemediationAction struct {
	ID              int        `json:"id"`
	RemediationID   int        `json:"remediation_id"`
	RuleID          string     `json:"rule_id"`
	ActionType      string     `json:"action_type"`
	TargetPath      *string    `json:"target_path,omitempty"`
	OldValue        *string    `json:"old_value,omitempty"`
	NewValue        *string    `json:"new_value,omitempty"`
	ExecutionOrder  int        `json:"execution_order"`
	Status          string     `json:"status"`
	ExecutedAt      *time.Time `json:"executed_at,omitempty"`
	DurationSecs    *int       `json:"duration_secs,omitempty"`
	ErrorMessage    *string    `json:"error_message,omitempty"`
}

// Checkpoint represents a system checkpoint
type Checkpoint struct {
	ID               int        `json:"id"`
	NodeID           int        `json:"node_id"`
	ScanID           *int       `json:"scan_id,omitempty"`
	CheckpointType   string     `json:"checkpoint_type"`
	Description      string     `json:"description"`
	ComplianceScore  *float64   `json:"compliance_score,omitempty"`
	CriticalFailures *int       `json:"critical_failures,omitempty"`
	FilesCount       int        `json:"files_count"`
	PackagesCount    int        `json:"packages_count"`
	ServicesCount    int        `json:"services_count"`
	CreatedAt        time.Time  `json:"created_at"`
	CreatedBy        string     `json:"created_by"`
}

// CheckpointFile represents a backed up file
type CheckpointFile struct {
	ID           int       `json:"id"`
	CheckpointID int       `json:"checkpoint_id"`
	FilePath     string    `json:"file_path"`
	FileContent  string    `json:"file_content"`
	FileMode     string    `json:"file_mode"`
	FileOwner    string    `json:"file_owner"`
	FileGroup    string    `json:"file_group"`
	BackedUpAt   time.Time `json:"backed_up_at"`
}

// RestoreOperation represents a rollback operation
type RestoreOperation struct {
	ID               int        `json:"id"`
	CheckpointID     int        `json:"checkpoint_id"`
	NodeID           int        `json:"node_id"`
	Status           string     `json:"status"`
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	DurationSecs     *int       `json:"duration_secs,omitempty"`
	FilesRestored    int        `json:"files_restored"`
	PackagesRestored int        `json:"packages_restored"`
	ServicesRestored int        `json:"services_restored"`
	ErrorMessage     *string    `json:"error_message,omitempty"`
	InitiatedBy      string     `json:"initiated_by"`
}

// CLIResponse is a generic response structure for CLI output
type CLIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}
