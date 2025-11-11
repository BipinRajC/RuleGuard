package handlers

import (
	"compliance-monitor/backend/db"
	"compliance-monitor/backend/models"
	"compliance-monitor/backend/ssh"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// Remediate handles POST /remediate
func Remediate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, models.APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	var req models.RemediationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request body",
		})
		return
	}

	if req.NodeID == 0 || len(req.RuleIDs) == 0 {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "node_id and rule_ids are required",
		})
		return
	}

	// Fetch node
	query := `
		SELECT id, name, hostname, port, username, auth_type, credentials
		FROM nodes
		WHERE id = $1 AND is_active = true
	`

	var node struct {
		ID          int
		Name        string
		Hostname    string
		Port        int
		Username    string
		AuthType    string
		Credentials string
	}

	err := db.DB.QueryRow(query, req.NodeID).Scan(
		&node.ID, &node.Name, &node.Hostname, &node.Port,
		&node.Username, &node.AuthType, &node.Credentials,
	)

	if err != nil {
		respondJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Node not found",
		})
		return
	}

	// Create SSH client
	var sshClient *ssh.Client
	if node.AuthType == "password" {
		sshClient = ssh.NewClient(node.Hostname, node.Port, node.Username, node.Credentials, "")
	} else {
		sshClient = ssh.NewClient(node.Hostname, node.Port, node.Username, "", node.Credentials)
	}

	// Execute remediation script
	scriptPath := filepath.Join("scripts", "remediate.sh")
	output, err := sshClient.ExecuteScript(scriptPath, req.RuleIDs...)

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Remediation failed",
			Data: map[string]string{
				"output": output,
				"error":  err.Error(),
			},
		})
		return
	}

	// Parse remediation output
	remResults := parseRemediationOutput(output)

	// Store remediation records
	for _, result := range remResults.Results {
		status := "failed"
		if result.Success {
			status = "success"
		}

		insertRem := `
			INSERT INTO remediations (node_id, rule_id, method, status, execution_output, executed_at)
			VALUES ($1, $2, 'openscap_auto', $3, $4, $5)
		`
		db.DB.Exec(insertRem, req.NodeID, result.RuleID, status, result.Message, time.Now())
	}

	// If remediations succeeded, trigger a new scan to update scores
	if remResults.Fixed > 0 {
		// Optionally trigger automatic rescan here
		// For now, just return success and let user manually rescan
	}

	respondJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("Remediation completed: %d fixed, %d failed", remResults.Fixed, remResults.Failed),
		Data:    remResults,
	})
}

// parseRemediationOutput parses the output from remediate.sh
func parseRemediationOutput(output string) models.RemediationResponse {
	response := models.RemediationResponse{
		Results: []models.RemediationRuleResult{},
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "RULE_START:") {
			// Track rule start if needed for debugging
			continue
		} else if strings.HasPrefix(line, "RULE_SUCCESS:") {
			ruleID := strings.TrimPrefix(line, "RULE_SUCCESS:")
			response.Results = append(response.Results, models.RemediationRuleResult{
				RuleID:  ruleID,
				Success: true,
				Message: "Remediation successful",
			})
			response.Fixed++
		} else if strings.HasPrefix(line, "RULE_FAILED:") {
			ruleID := strings.TrimPrefix(line, "RULE_FAILED:")
			response.Results = append(response.Results, models.RemediationRuleResult{
				RuleID:  ruleID,
				Success: false,
				Message: "Remediation failed",
			})
			response.Failed++
		} else if strings.HasPrefix(line, "FIXED:") {
			// Already counted above
		} else if strings.HasPrefix(line, "FAILED:") {
			// Already counted above
		}
	}

	return response
}
