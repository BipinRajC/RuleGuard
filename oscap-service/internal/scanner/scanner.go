package scanner

import (
	"database/sql"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"oscap-service/internal/database"
	"oscap-service/pkg/models"
)

// Scanner handles compliance scanning operations
type Scanner struct {
	NodeID   int
	NodeName string
	Profile  string
}

// NewScanner creates a new scanner instance
func NewScanner(nodeID int, nodeName string) *Scanner {
	return &Scanner{
		NodeID:   nodeID,
		NodeName: nodeName,
		Profile:  "xccdf_org.ssgproject.content_profile_standard",
	}
}

// ExecuteScan runs a compliance scan locally
func (s *Scanner) ExecuteScan(reportsPath string) (*models.Scan, error) {
	// Create scan record
	scan := &models.Scan{
		NodeID:    s.NodeID,
		Profile:   s.Profile,
		Status:    "running",
		StartedAt: time.Now(),
	}

	// Get hostname for denormalized field
	hostname := s.NodeName
	
	var scanID int
	err := database.DB.QueryRow(`
		INSERT INTO scans (node_id, hostname, profile, status, started_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		scan.NodeID, hostname, scan.Profile, scan.Status, scan.StartedAt,
	).Scan(&scanID)

	if err != nil {
		return nil, fmt.Errorf("failed to create scan record: %w", err)
	}

	scan.ID = scanID

	// Execute scan script
	scriptPath := filepath.Join("scripts", "scan.sh")
	output, err := s.executeScript(scriptPath)

	completedAt := time.Now()
	durationSecs := int(completedAt.Sub(scan.StartedAt).Seconds())

	if err != nil {
		// Mark scan as failed
		_, updateErr := database.DB.Exec(`
			UPDATE scans 
			SET status = 'failed', 
				completed_at = $1, 
				duration_seconds = $2, 
				error_message = $3
			WHERE id = $4`,
			completedAt, durationSecs, err.Error(), scanID,
		)
		if updateErr != nil {
			return nil, fmt.Errorf("scan failed and couldn't update: %v, %v", err, updateErr)
		}
		return nil, fmt.Errorf("scan execution failed: %w", err)
	}

	// Parse scan output
	scanData := s.parseScanOutput(output)
	if scanData == nil {
		_, updateErr := database.DB.Exec(`
			UPDATE scans 
			SET status = 'failed', 
				completed_at = $1, 
				error_message = $2
			WHERE id = $3`,
			completedAt, "Failed to parse scan output", scanID,
		)
		if updateErr != nil {
			return nil, fmt.Errorf("parse failed and couldn't update: %v", updateErr)
		}
		return nil, fmt.Errorf("failed to parse scan results")
	}

	// Update scan record with results
	notApplicable := 0
	if val, ok := scanData["notapplicable"].(int); ok {
		notApplicable = val
	}
	
	_, err = database.DB.Exec(`
		UPDATE scans 
		SET status = 'completed',
			completed_at = $1,
			duration_seconds = $2,
			compliance_score = $3,
			total_rules = $4,
			passed_rules = $5,
			failed_rules = $6,
			error_rules = $7,
			notapplicable_rules = $8,
			report_html_path = $9,
			report_xml_path = $10
		WHERE id = $11`,
		completedAt, durationSecs,
		scanData["score"], scanData["total"],
		scanData["passed"], scanData["failed"], scanData["error"],
		notApplicable,
		scanData["report_html"], scanData["report_xml"],
		scanID,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to update scan: %w", err)
	}

	// Store failed rules as scan results
	if failedRules, ok := scanData["failed_rules"].([]string); ok {
		for _, ruleID := range failedRules {
			_, err = database.DB.Exec(`
				INSERT INTO scan_results (scan_id, node_id, rule_id, result)
				VALUES ($1, $2, $3, 'fail')`,
				scanID, s.NodeID, ruleID,
			)
			if err != nil {
				fmt.Printf("Warning: Failed to store failed rule %s: %v\n", ruleID, err)
			}
		}
	}

	// Fetch updated scan
	scan, err = s.getScanByID(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve scan: %w", err)
	}

	return scan, nil
}

// executeScript runs a shell script locally
func (s *Scanner) executeScript(scriptPath string) (string, error) {
	cmd := exec.Command("bash", scriptPath)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// parseScanOutput parses the output from scan.sh
func (s *Scanner) parseScanOutput(output string) map[string]interface{} {
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
		case "NOTAPPLICABLE":
			if i, err := strconv.Atoi(value); err == nil {
				result["notapplicable"] = i
			}
		case "RESULTS_XML":
			result["report_xml"] = value
		case "REPORT_HTML":
			result["report_html"] = value
		}
	}

	if len(failedRules) > 0 {
		result["failed_rules"] = failedRules
	}

	// Calculate compliance score based on applicable rules
	if passed, ok := result["passed"].(int); ok {
		failed, _ := result["failed"].(int)
		errors, _ := result["error"].(int)
		
		applicable := passed + failed + errors
		
		if applicable > 0 {
			score := (float64(passed) / float64(applicable)) * 100.0
			result["score"] = float64(int(score + 0.5)) // Round to nearest integer
		} else {
			result["score"] = 0.0
		}
	}

	// Verify we got minimum required data
	if _, ok := result["score"]; !ok {
		return nil
	}

	return result
}

// getScanByID retrieves a scan by ID
func (s *Scanner) getScanByID(scanID int) (*models.Scan, error) {
	scan := &models.Scan{}
	err := database.DB.QueryRow(`
		SELECT id, node_id, profile, status, started_at, completed_at,
		       duration_seconds, compliance_score, total_rules, passed_rules,
		       failed_rules, error_rules, report_html_path, report_xml_path,
		       error_message
		FROM scans
		WHERE id = $1`,
		scanID,
	).Scan(
		&scan.ID, &scan.NodeID, &scan.Profile, &scan.Status,
		&scan.StartedAt, &scan.CompletedAt, &scan.DurationSeconds,
		&scan.ComplianceScore, &scan.TotalRules, &scan.PassedRules,
		&scan.FailedRules, &scan.ErrorRules, &scan.ReportHTMLPath,
		&scan.ReportXMLPath, &scan.ErrorMessage,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan not found")
		}
		return nil, err
	}

	return scan, nil
}
