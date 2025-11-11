package handlers

import (
	"compliance-monitor/backend/db"
	"compliance-monitor/backend/models"
	"compliance-monitor/backend/ssh"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
)

// AddNode handles POST /add-node
func AddNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, models.APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	var req models.NodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request body",
		})
		return
	}

	// Validate required fields
	if req.Name == "" || req.Hostname == "" || req.Username == "" {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "name, hostname, and username are required",
		})
		return
	}

	if req.AuthType != "password" && req.AuthType != "key" {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "auth_type must be 'password' or 'key'",
		})
		return
	}

	if req.AuthType == "password" && req.Password == "" {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "password is required when auth_type is 'password'",
		})
		return
	}

	if req.AuthType == "key" && req.SSHKey == "" {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "ssh_key is required when auth_type is 'key'",
		})
		return
	}

	// Set defaults
	if req.Port == 0 {
		req.Port = 22
	}

	// Test SSH connection before saving
	var sshClient *ssh.Client
	if req.AuthType == "password" {
		sshClient = ssh.NewClient(req.Hostname, req.Port, req.Username, req.Password, "")
	} else {
		sshClient = ssh.NewClient(req.Hostname, req.Port, req.Username, "", req.SSHKey)
	}

	if err := sshClient.TestConnection(); err != nil {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("SSH connection failed: %v", err),
		})
		return
	}

	// Detect OS
	osInfo, err := sshClient.DetectOS()
	if err != nil {
		// Don't fail, just log
		fmt.Printf("Warning: Could not detect OS for %s: %v\n", req.Hostname, err)
	}

	// Prepare credentials (in production, encrypt this!)
	credentials := ""
	if req.AuthType == "password" {
		credentials = req.Password
	} else {
		credentials = req.SSHKey
	}

	// Insert into database
	query := `
		INSERT INTO nodes (name, hostname, port, username, auth_type, credentials, description, os_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at
	`

	var node models.Node
	err = db.DB.QueryRow(query,
		req.Name, req.Hostname, req.Port, req.Username,
		req.AuthType, credentials, req.Description, osInfo,
	).Scan(&node.ID, &node.CreatedAt)

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to save node: %v", err),
		})
		return
	}

	// Populate response
	node.Name = req.Name
	node.Hostname = req.Hostname
	node.Port = req.Port
	node.Username = req.Username
	node.AuthType = req.AuthType
	node.Description = req.Description
	node.OSType = osInfo
	node.IsActive = true

	// Initialize scan schedule
	_, err = db.DB.Exec("SELECT init_scan_schedule($1)", node.ID)
	if err != nil {
		fmt.Printf("Warning: Failed to init scan schedule: %v\n", err)
	}

	respondJSON(w, http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Node added successfully",
		Data:    node,
	})
}

// ListNodes handles GET /nodes
func ListNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, models.APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	query := `
		SELECT id, name, hostname, port, username, auth_type, description, 
		       os_type, is_active, current_compliance_score, current_status, 
		       last_scan_at, created_at
		FROM nodes
		WHERE is_active = true
		ORDER BY created_at DESC
	`

	rows, err := db.DB.Query(query)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to fetch nodes: %v", err),
		})
		return
	}
	defer rows.Close()

	var nodes []models.Node
	for rows.Next() {
		var node models.Node
		var score sql.NullFloat64
		var status sql.NullString
		var lastScan sql.NullTime

		err := rows.Scan(&node.ID, &node.Name, &node.Hostname, &node.Port,
			&node.Username, &node.AuthType, &node.Description, &node.OSType,
			&node.IsActive, &score, &status, &lastScan, &node.CreatedAt)

		if err != nil {
			fmt.Printf("Error scanning row: %v\n", err)
			continue
		}

		nodes = append(nodes, node)
	}

	respondJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    nodes,
	})
}

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
