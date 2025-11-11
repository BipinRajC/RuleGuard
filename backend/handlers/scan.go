package handlers

import (
	"compliance-monitor/backend/db"
	"compliance-monitor/backend/models"
	"compliance-monitor/backend/ssh"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Scan handles POST /scan?node_id=X
func Scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, models.APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "node_id query parameter is required",
		})
		return
	}

	// Fetch node
	query := `
		SELECT id, name, hostname, port, username, auth_type, credentials, scan_profile
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
		Profile     string
	}

	err := db.DB.QueryRow(query, nodeID).Scan(
		&node.ID, &node.Name, &node.Hostname, &node.Port,
		&node.Username, &node.AuthType, &node.Credentials, &node.Profile,
	)

	if err != nil {
		respondJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Node not found",
		})
		return
	}

	// Create scan record
	insertScan := `
		INSERT INTO scans (node_id, profile, status, started_at)
		VALUES ($1, $2, 'running', $3)
		RETURNING id
	`

	var scanID int
	startTime := time.Now()
	err = db.DB.QueryRow(insertScan, node.ID, node.Profile, startTime).Scan(&scanID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create scan record: %v", err),
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

	// Execute scan script
	scriptPath := filepath.Join("scripts", "scan.sh")
	output, err := sshClient.ExecuteScript(scriptPath)

	if err != nil {
		// Mark scan as failed
		updateScan := `
			UPDATE scans 
			SET status = 'failed', 
			    completed_at = $1, 
			    duration_seconds = $2, 
			    error_message = $3
			WHERE id = $4
		`
		duration := int(time.Since(startTime).Seconds())
		db.DB.Exec(updateScan, time.Now(), duration, err.Error(), scanID)

		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Scan failed",
			Data: map[string]interface{}{
				"scan_id": scanID,
				"output":  output,
				"error":   err.Error(),
			},
		})
		return
	}

	// Parse scan output
	scanData := parseScanOutput(output)
	if scanData == nil {
		updateScan := `
			UPDATE scans 
			SET status = 'failed', 
			    completed_at = $1, 
			    error_message = $2
			WHERE id = $3
		`
		db.DB.Exec(updateScan, time.Now(), "Failed to parse scan output", scanID)

		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to parse scan results",
			Data:    map[string]string{"output": output},
		})
		return
	}

	// Update scan record with results
	updateScan := `
		UPDATE scans 
		SET status = 'completed',
		    completed_at = $1,
		    duration_seconds = $2,
		    compliance_score = $3,
		    total_rules = $4,
		    passed_rules = $5,
		    failed_rules = $6,
		    error_rules = $7,
		    report_path = $8
		WHERE id = $9
	`

	completedAt := time.Now()
	duration := int(completedAt.Sub(startTime).Seconds())

	_, err = db.DB.Exec(updateScan,
		completedAt, duration, scanData["score"], scanData["total"],
		scanData["passed"], scanData["failed"], scanData["error"],
		scanData["report_path"], scanID,
	)

	if err != nil {
		fmt.Printf("Warning: Failed to update scan: %v\n", err)
	}

	// Store failed rules as scan results
	if failedRules, ok := scanData["failed_rules"].([]string); ok {
		for _, ruleID := range failedRules {
			insertResult := `
				INSERT INTO scan_results (scan_id, rule_id, result)
				VALUES ($1, $2, 'fail')
			`
			db.DB.Exec(insertResult, scanID, ruleID)
		}
	}

	respondJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("Scan completed on %s", node.Name),
		Data: map[string]interface{}{
			"scan_id":          scanID,
			"compliance_score": scanData["score"],
			"total_rules":      scanData["total"],
			"passed_rules":     scanData["passed"],
			"failed_rules":     scanData["failed"],
			"error_rules":      scanData["error"],
		},
	})
}

// parseScanOutput parses the output from scan.sh
func parseScanOutput(output string) map[string]interface{} {
	result := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	var failedRules []string
	inFailedRules := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "FAILED_RULES_START") {
			inFailedRules = true
			continue
		}
		if strings.HasPrefix(line, "FAILED_RULES_END") {
			inFailedRules = false
			continue
		}

		if inFailedRules && line != "" {
			failedRules = append(failedRules, line)
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
		case "SCORE":
			if f, err := strconv.ParseFloat(value, 64); err == nil {
				result["score"] = f
			}
		case "PASSED":
			if i, err := strconv.Atoi(value); err == nil {
				result["passed"] = i
			}
		case "FAILED":
			if i, err := strconv.Atoi(value); err == nil {
				result["failed"] = i
			}
		case "ERROR":
			if i, err := strconv.Atoi(value); err == nil {
				result["error"] = i
			}
		case "TOTAL":
			if i, err := strconv.Atoi(value); err == nil {
				result["total"] = i
			}
		case "APPLICABLE":
			if i, err := strconv.Atoi(value); err == nil {
				result["applicable"] = i
			}
		case "NOTAPPLICABLE", "NOTCHECKED", "NOTSELECTED":
			// Store these for fallback calculation if APPLICABLE is missing
			if i, err := strconv.Atoi(value); err == nil {
				result[strings.ToLower(key)] = i
			}
		case "RESULTS_XML", "REPORT_HTML":
			result[strings.ToLower(key)] = value
		}
	}

	if len(failedRules) > 0 {
		result["failed_rules"] = failedRules
	}

	// Calculate compliance score based on APPLICABLE rules only
	// Compliance Score = PASSED / (PASSED + FAILED + ERROR) × 100
	// This represents the percentage of applicable rules that passed
	
	if passed, passedOk := result["passed"].(int); passedOk {
		failed, _ := result["failed"].(int)
		errors, _ := result["error"].(int)
		
		applicable := passed + failed + errors
		
		if applicable > 0 {
			score := (float64(passed) / float64(applicable)) * 100.0
			// Round to nearest integer (0-100)
			result["score"] = float64(int(score + 0.5))
		} else {
			result["score"] = 0.0
		}
	} else {
		result["score"] = 0.0
	}

	// Verify we got minimum required data
	if _, ok := result["score"]; !ok {
		return nil
	}

	return result
}

// GetScanStatus handles GET /scan/:id
func GetScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, models.APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	// Extract scan ID from path
	re := regexp.MustCompile(`/scan/(\d+)`)
	matches := re.FindStringSubmatch(r.URL.Path)
	if len(matches) < 2 {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid scan ID",
		})
		return
	}

	scanID := matches[1]

	query := `
		SELECT s.id, s.node_id, n.name, s.profile, s.status, s.started_at, 
		       s.completed_at, s.duration_seconds, s.compliance_score,
		       s.total_rules, s.passed_rules, s.failed_rules, s.error_rules,
		       s.report_path, s.error_message
		FROM scans s
		JOIN nodes n ON s.node_id = n.id
		WHERE s.id = $1
	`

	var scan struct {
		ID              int
		NodeID          int
		NodeName        string
		Profile         string
		Status          string
		StartedAt       time.Time
		CompletedAt     *time.Time
		DurationSeconds *int
		ComplianceScore *float64
		TotalRules      *int
		PassedRules     *int
		FailedRules     *int
		ErrorRules      *int
		ReportPath      *string
		ErrorMessage    *string
	}

	err := db.DB.QueryRow(query, scanID).Scan(
		&scan.ID, &scan.NodeID, &scan.NodeName, &scan.Profile, &scan.Status,
		&scan.StartedAt, &scan.CompletedAt, &scan.DurationSeconds,
		&scan.ComplianceScore, &scan.TotalRules, &scan.PassedRules,
		&scan.FailedRules, &scan.ErrorRules, &scan.ReportPath, &scan.ErrorMessage,
	)

	if err != nil {
		respondJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Scan not found",
		})
		return
	}

	respondJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    scan,
	})
}
