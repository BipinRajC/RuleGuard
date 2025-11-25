package remediation

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"oscap-service/internal/database"
	"oscap-service/pkg/models"
	sshpkg "oscap-service/pkg/ssh"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Remediator handles rule remediation operations
type Remediator struct {
	NodeID    int
	NodeName  string
	Profile   string
	IsRemote  bool
	SSHClient *sshpkg.Client
}

// NewRemediator creates a new remediator instance for local execution
func NewRemediator(nodeID int, nodeName, profile string) *Remediator {
	return &Remediator{
		NodeID:   nodeID,
		NodeName: nodeName,
		Profile:  profile,
		IsRemote: false,
	}
}

// NewRemoteRemediator creates a new remediator instance for remote execution via SSH
func NewRemoteRemediator(nodeID int, nodeName, profile string, sshClient *sshpkg.Client) *Remediator {
	return &Remediator{
		NodeID:    nodeID,
		NodeName:  nodeName,
		Profile:   profile,
		IsRemote:  true,
		SSHClient: sshClient,
	}
}

// RemediateRules executes remediation for specified rule IDs
func (r *Remediator) RemediateRules(ruleIDs []string) (*models.Remediation, error) {
	if len(ruleIDs) == 0 {
		return nil, fmt.Errorf("no rules specified for remediation")
	}

	// Create remediation record
	remediation := &models.Remediation{
		NodeID:     r.NodeID,
		Status:     "running",
		InitiatedBy: "scaprun",
		StartedAt:  time.Now(),
	}

	var remediationID int
	err := database.DB.QueryRow(`
		INSERT INTO remediations (node_id, hostname, method, status, executed_by, executed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		remediation.NodeID, r.NodeName, "openscap_auto", remediation.Status, remediation.InitiatedBy, remediation.StartedAt,
	).Scan(&remediationID)

	if err != nil {
		return nil, fmt.Errorf("failed to create remediation record: %w", err)
	}

	remediation.ID = remediationID

	// Execute remediate.sh script with profile and rule IDs
	scriptPath := "/home/bipin/OSCAP-project/oscap-service/scripts/remediate.sh"
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read remediate script: %w", err)
	}

	var output string
	ruleIDsStr := strings.Join(ruleIDs, ",")

	if r.IsRemote {
		// Execute remotely via SSH
		// Pass profile and rule IDs as environment variables
		script := fmt.Sprintf("export PROFILE='%s'\nexport RULE_IDS='%s'\n%s", r.Profile, ruleIDsStr, string(scriptContent))
		output, err = r.SSHClient.ExecuteScriptContent(script)
	} else {
		// Execute locally
		output, err = r.executeLocalRemediation(scriptPath, r.Profile, ruleIDsStr)
	}

	completedAt := time.Now()

	if err != nil {
		// Mark remediation as failed
		_, updateErr := database.DB.Exec(`
			UPDATE remediations 
			SET status = 'failed', 
				completed_at = $1,
				error_message = $2
			WHERE id = $3`,
			completedAt, err.Error(), remediationID,
		)
		if updateErr != nil {
			return nil, fmt.Errorf("remediation failed and couldn't update: %v, %v", err, updateErr)
		}
		return nil, fmt.Errorf("remediation execution failed: %w", err)
	}

	// Parse remediation output
	stats := r.parseRemediationOutput(output)

	// Update remediation record
	totalFixed := 0
	totalAttempted := len(ruleIDs)
	totalFailed := 0

	if val, ok := stats["fixed"].(int); ok {
		totalFixed = val
	}
	if val, ok := stats["failed"].(int); ok {
		totalFailed = val
	}

	status := "completed"
	if totalFixed == 0 && totalFailed > 0 {
		status = "failed"
	} else if totalFailed > 0 {
		status = "partial"
	}

	_, err = database.DB.Exec(`
		UPDATE remediations 
		SET status = $1,
			completed_at = $2,
			rules_count = $3,
			successful_count = $4,
			failed_count = $5,
			execution_output = $6
		WHERE id = $7`,
		status, completedAt,
		totalAttempted, totalFixed, totalFailed,
		output[:min(len(output), 10000)], // Limit output size
		remediationID,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to update remediation: %w", err)
	}

	// Store individual rule remediation results in remediation_actions table
	if fixedRules, ok := stats["fixed_rules"].([]string); ok {
		for i, ruleID := range fixedRules {
			r.storeRemediationAction(remediationID, ruleID, "success", nil, i+1)
		}
	}

	if failedRules, ok := stats["failed_rules"].(map[string]string); ok {
		i := 0
		for ruleID, errorMsg := range failedRules {
			r.storeRemediationAction(remediationID, ruleID, "failed", &errorMsg, i+1)
			i++
		}
	}

	// Fetch updated remediation
	remediation, err = r.getRemediationByID(remediationID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remediation: %w", err)
	}

	return remediation, nil
}

// executeLocalRemediation executes remediation script locally
func (r *Remediator) executeLocalRemediation(scriptPath, profile, ruleIDs string) (string, error) {
	cmd := exec.Command("bash", scriptPath)
	cmd.Env = append(os.Environ(), 
		fmt.Sprintf("PROFILE=%s", profile),
		fmt.Sprintf("RULE_IDS=%s", ruleIDs),
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// parseRemediationOutput parses the output from remediate.sh
func (r *Remediator) parseRemediationOutput(output string) map[string]interface{} {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")
	
	fixedRules := []string{}
	failedRules := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse RULE_SUCCESS:rulename
		if strings.HasPrefix(line, "RULE_SUCCESS:") {
			ruleID := strings.TrimPrefix(line, "RULE_SUCCESS:")
			// Handle optional message after colon (e.g., RULE_SUCCESS:rule:Already compliant)
			if idx := strings.Index(ruleID, ":"); idx > 0 {
				ruleID = ruleID[:idx]
			}
			fixedRules = append(fixedRules, strings.TrimSpace(ruleID))
			continue
		}

		// Parse RULE_FAILED:rulename or RULE_FAILED:rulename:error
		if strings.HasPrefix(line, "RULE_FAILED:") {
			parts := strings.SplitN(strings.TrimPrefix(line, "RULE_FAILED:"), ":", 2)
			ruleID := strings.TrimSpace(parts[0])
			errorMsg := "Unknown error"
			if len(parts) > 1 {
				errorMsg = strings.TrimSpace(parts[1])
			}
			failedRules[ruleID] = errorMsg
			continue
		}

		// Parse key:value pairs
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "TOTAL_FIXED":
			if i, err := strconv.Atoi(value); err == nil {
				result["fixed"] = i
			}
		case "TOTAL_FAILED":
			if i, err := strconv.Atoi(value); err == nil {
				result["failed"] = i
			}
		}
	}

	// If we parsed RULE_SUCCESS lines, use them as fixed count
	if len(fixedRules) > 0 {
		result["fixed_rules"] = fixedRules
		if _, exists := result["fixed"]; !exists {
			result["fixed"] = len(fixedRules)
		}
	}
	if len(failedRules) > 0 {
		result["failed_rules"] = failedRules
		if _, exists := result["failed"]; !exists {
			result["failed"] = len(failedRules)
		}
	}

	return result
}

// storeRemediationAction stores individual rule remediation action
func (r *Remediator) storeRemediationAction(remediationID int, ruleID, status string, errorMessage *string, order int) {
	_, err := database.DB.Exec(`
		INSERT INTO remediation_actions (remediation_id, rule_id, action_type, status, error_message, execution_order)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		remediationID, ruleID, "command_execute", status, errorMessage, order,
	)
	if err != nil {
		fmt.Printf("Warning: Failed to store remediation action for rule %s: %v\n", ruleID, err)
	}
}

// getRemediationByID retrieves a remediation by ID
func (r *Remediator) getRemediationByID(remediationID int) (*models.Remediation, error) {
	remediation := &models.Remediation{}
	var executedBy, executedAt sql.NullString
	var completedAt sql.NullTime
	
	err := database.DB.QueryRow(`
		SELECT id, node_id, status, executed_by, executed_at, completed_at,
		       rules_count, successful_count, failed_count, error_message
		FROM remediations
		WHERE id = $1`,
		remediationID,
	).Scan(
		&remediation.ID, &remediation.NodeID, &remediation.Status, &executedBy,
		&executedAt, &completedAt, &remediation.RulesAttempted,
		&remediation.RulesSucceeded, &remediation.RulesFailed, &remediation.ErrorMessage,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("remediation not found")
		}
		return nil, err
	}

	// Handle nullable fields
	if executedBy.Valid {
		remediation.InitiatedBy = executedBy.String
	}
	if executedAt.Valid {
		if t, err := time.Parse(time.RFC3339, executedAt.String); err == nil {
			remediation.StartedAt = t
		}
	}
	if completedAt.Valid {
		remediation.CompletedAt = &completedAt.Time
	}

	return remediation, nil
}

// GetFailedRules retrieves all failed rules from the latest scan for a node
func (r *Remediator) GetFailedRules() ([]models.ScanResult, error) {
	rows, err := database.DB.Query(`
		SELECT sr.id, sr.scan_id, sr.rule_id, sr.result, sr.created_at
		FROM scan_results sr
		INNER JOIN scans s ON sr.scan_id = s.id
		WHERE sr.node_id = $1 
		  AND sr.result = 'fail'
		  AND s.status = 'completed'
		  AND s.id = (
		      SELECT id FROM scans 
		      WHERE node_id = $1 AND status = 'completed'
		      ORDER BY completed_at DESC LIMIT 1
		  )
		ORDER BY sr.rule_id`,
		r.NodeID,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query failed rules: %w", err)
	}
	defer rows.Close()

	var results []models.ScanResult
	for rows.Next() {
		var result models.ScanResult
		err := rows.Scan(
			&result.ID, &result.ScanID, &result.RuleID, &result.Result,
			&result.RecordedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}
