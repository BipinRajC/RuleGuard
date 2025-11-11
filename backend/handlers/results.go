package handlers

import (
	"compliance-monitor/backend/db"
	"compliance-monitor/backend/models"
	"database/sql"
	"fmt"
	"net/http"
	"time"
)

// GetResults handles GET /results?node_id=X
func GetResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	// Get node info with latest scan
	nodeQuery := `
		SELECT n.id, n.name, n.hostname, n.current_compliance_score, 
		       n.current_status, n.last_scan_at, n.last_scan_id
		FROM nodes n
		WHERE n.id = $1 AND n.is_active = true
	`

	var node struct {
		ID              int
		Name            string
		Hostname        string
		ComplianceScore sql.NullFloat64
		Status          sql.NullString
		LastScanAt      sql.NullTime
		LastScanID      sql.NullInt64
	}

	err := db.DB.QueryRow(nodeQuery, nodeID).Scan(
		&node.ID, &node.Name, &node.Hostname, &node.ComplianceScore,
		&node.Status, &node.LastScanAt, &node.LastScanID,
	)

	if err != nil {
		respondJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Node not found",
		})
		return
	}

	response := map[string]interface{}{
		"node_id":  node.ID,
		"name":     node.Name,
		"hostname": node.Hostname,
	}

	if node.ComplianceScore.Valid {
		response["compliance_score"] = node.ComplianceScore.Float64
	}
	if node.Status.Valid {
		response["status"] = node.Status.String
	}
	if node.LastScanAt.Valid {
		response["last_scan_at"] = node.LastScanAt.Time
	}

	// Get scan details if available
	if node.LastScanID.Valid {
		scanQuery := `
			SELECT id, profile, status, started_at, completed_at, 
			       compliance_score, total_rules, passed_rules, 
			       failed_rules, error_rules, duration_seconds
			FROM scans
			WHERE id = $1
		`

		var scan struct {
			ID              int
			Profile         string
			Status          string
			StartedAt       time.Time
			CompletedAt     sql.NullTime
			ComplianceScore sql.NullFloat64
			TotalRules      sql.NullInt64
			PassedRules     sql.NullInt64
			FailedRules     sql.NullInt64
			ErrorRules      sql.NullInt64
			DurationSeconds sql.NullInt64
		}

		err := db.DB.QueryRow(scanQuery, node.LastScanID.Int64).Scan(
			&scan.ID, &scan.Profile, &scan.Status, &scan.StartedAt,
			&scan.CompletedAt, &scan.ComplianceScore, &scan.TotalRules,
			&scan.PassedRules, &scan.FailedRules, &scan.ErrorRules,
			&scan.DurationSeconds,
		)

		if err == nil {
			scanData := map[string]interface{}{
				"scan_id":    scan.ID,
				"profile":    scan.Profile,
				"status":     scan.Status,
				"started_at": scan.StartedAt,
			}

			if scan.CompletedAt.Valid {
				scanData["completed_at"] = scan.CompletedAt.Time
			}
			if scan.ComplianceScore.Valid {
				scanData["compliance_score"] = scan.ComplianceScore.Float64
			}
			if scan.TotalRules.Valid {
				scanData["total_rules"] = scan.TotalRules.Int64
			}
			if scan.PassedRules.Valid {
				scanData["passed_rules"] = scan.PassedRules.Int64
			}
			if scan.FailedRules.Valid {
				scanData["failed_rules"] = scan.FailedRules.Int64
			}
			if scan.ErrorRules.Valid {
				scanData["error_rules"] = scan.ErrorRules.Int64
			}
			if scan.DurationSeconds.Valid {
				scanData["duration_seconds"] = scan.DurationSeconds.Int64
			}

			response["latest_scan"] = scanData

			// Get failed rules for this scan
			failedRulesQuery := `
				SELECT sr.rule_id, sr.result, sr.check_output
				FROM scan_results sr
				WHERE sr.scan_id = $1 AND sr.result IN ('fail', 'error')
				ORDER BY sr.rule_id
			`

			rows, err := db.DB.Query(failedRulesQuery, scan.ID)
			if err == nil {
				defer rows.Close()

				var failedRules []map[string]interface{}
				for rows.Next() {
					var ruleID, result string
					var checkOutput sql.NullString

					if err := rows.Scan(&ruleID, &result, &checkOutput); err == nil {
						rule := map[string]interface{}{
							"rule_id": ruleID,
							"result":  result,
						}
						if checkOutput.Valid {
							rule["check_output"] = checkOutput.String
						}
						failedRules = append(failedRules, rule)
					}
				}
				response["failed_rules"] = failedRules
			}
		}
	}

	// Get recent scan history
	historyQuery := `
		SELECT id, profile, status, started_at, compliance_score, 
		       failed_rules, total_rules
		FROM scans
		WHERE node_id = $1
		ORDER BY started_at DESC
		LIMIT 10
	`

	rows, err := db.DB.Query(historyQuery, nodeID)
	if err == nil {
		defer rows.Close()

		var history []map[string]interface{}
		for rows.Next() {
			var scanID int
			var profile, status string
			var startedAt time.Time
			var score sql.NullFloat64
			var failed, total sql.NullInt64

			if err := rows.Scan(&scanID, &profile, &status, &startedAt, &score, &failed, &total); err == nil {
				item := map[string]interface{}{
					"scan_id":    scanID,
					"profile":    profile,
					"status":     status,
					"started_at": startedAt,
				}
				if score.Valid {
					item["compliance_score"] = score.Float64
				}
				if failed.Valid {
					item["failed_rules"] = failed.Int64
				}
				if total.Valid {
					item["total_rules"] = total.Int64
				}
				history = append(history, item)
			}
		}
		response["scan_history"] = history
	}

	respondJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    response,
	})
}

// GetAllResults handles GET /results (without node_id)
func GetAllResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, models.APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	query := `
		SELECT n.id, n.name, n.hostname, n.current_compliance_score,
		       n.current_status, n.last_scan_at,
		       s.failed_rules, s.total_rules
		FROM nodes n
		LEFT JOIN scans s ON n.last_scan_id = s.id
		WHERE n.is_active = true
		ORDER BY n.current_compliance_score ASC NULLS LAST
	`

	rows, err := db.DB.Query(query)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to fetch results: %v", err),
		})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var nodeID int
		var name, hostname string
		var score sql.NullFloat64
		var status sql.NullString
		var lastScan sql.NullTime
		var failed, total sql.NullInt64

		err := rows.Scan(&nodeID, &name, &hostname, &score, &status, &lastScan, &failed, &total)
		if err != nil {
			continue
		}

		result := map[string]interface{}{
			"node_id":  nodeID,
			"name":     name,
			"hostname": hostname,
		}

		if score.Valid {
			result["compliance_score"] = score.Float64
		}
		if status.Valid {
			result["status"] = status.String
		}
		if lastScan.Valid {
			result["last_scan_at"] = lastScan.Time
		}
		if failed.Valid {
			result["failed_rules"] = failed.Int64
		}
		if total.Valid {
			result["total_rules"] = total.Int64
		}

		results = append(results, result)
	}

	respondJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    results,
	})
}
