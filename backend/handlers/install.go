package handlers

import (
	"compliance-monitor/backend/db"
	"compliance-monitor/backend/models"
	"compliance-monitor/backend/ssh"
	"fmt"
	"net/http"
	"path/filepath"
)

// InstallOpenSCAP handles POST /install-openscap?node_id=X
func InstallOpenSCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, models.APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	// Get node_id from query params
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		respondJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "node_id query parameter is required",
		})
		return
	}

	// Fetch node from database
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

	err := db.DB.QueryRow(query, nodeID).Scan(
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

	// Get script path (assuming it's in scripts/ directory relative to backend)
	scriptPath := filepath.Join("scripts", "install_oscap.sh")

	// Execute installation script
	output, err := sshClient.ExecuteScript(scriptPath)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Installation failed",
			Data: map[string]string{
				"output": output,
				"error":  err.Error(),
			},
		})
		return
	}

	respondJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("OpenSCAP installed successfully on %s", node.Name),
		Data: map[string]string{
			"node_id": nodeID,
			"output":  output,
		},
	})
}
