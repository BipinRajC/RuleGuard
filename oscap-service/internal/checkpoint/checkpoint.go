package checkpoint

import (
	"fmt"
	"strings"
	"time"

	"oscap-service/internal/database"
	"oscap-service/pkg/models"
	sshpkg "oscap-service/pkg/ssh"
)

// Manager handles checkpoint creation and restoration
type Manager struct {
	NodeID    int
	NodeName  string
	IsRemote  bool
	SSHClient *sshpkg.Client
}

// NewLocalManager creates a checkpoint manager for local operations
func NewLocalManager(nodeID int, nodeName string) *Manager {
	return &Manager{
		NodeID:   nodeID,
		NodeName: nodeName,
		IsRemote: false,
	}
}

// NewRemoteManager creates a checkpoint manager for remote operations
func NewRemoteManager(nodeID int, nodeName string, sshClient *sshpkg.Client) *Manager {
	return &Manager{
		NodeID:    nodeID,
		NodeName:  nodeName,
		IsRemote:  true,
		SSHClient: sshClient,
	}
}

// CreateCheckpoint creates a checkpoint before remediation
func (m *Manager) CreateCheckpoint(name, description string, ruleIDs []string, scanID *int) (*models.Checkpoint, error) {
	checkpoint := &models.Checkpoint{
		NodeID:         m.NodeID,
		Hostname:       m.NodeName,
		Name:           name,
		Description:    description,
		CheckpointType: "pre_remediation",
		IsActive:       true,
		CreatedAt:      time.Now(),
	}

	if scanID != nil {
		checkpoint.ScanID = scanID
	}

	// Get current compliance score from latest scan
	var score float64
	var failures int
	err := database.DB.QueryRow(`
		SELECT COALESCE(compliance_score, 0), COALESCE(failed_rules, 0)
		FROM scans WHERE node_id = $1 AND status = 'completed'
		ORDER BY completed_at DESC LIMIT 1`,
		m.NodeID,
	).Scan(&score, &failures)
	if err == nil {
		checkpoint.ComplianceScore = &score
		checkpoint.TotalFailures = &failures
	}

	// Insert checkpoint record
	var checkpointID int
	err = database.DB.QueryRow(`
		INSERT INTO checkpoints (node_id, hostname, scan_id, name, description, 
		                         checkpoint_type, compliance_score, total_failures, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		checkpoint.NodeID, checkpoint.Hostname, checkpoint.ScanID, checkpoint.Name,
		checkpoint.Description, checkpoint.CheckpointType, checkpoint.ComplianceScore,
		checkpoint.TotalFailures, checkpoint.IsActive,
	).Scan(&checkpointID)

	if err != nil {
		return nil, fmt.Errorf("failed to create checkpoint record: %w", err)
	}
	checkpoint.ID = checkpointID

	// Backup files that will be affected by remediation
	filesToBackup := m.getFilesForRules(ruleIDs)
	filesBackedUp := 0
	for _, filePath := range filesToBackup {
		if err := m.backupFile(checkpointID, filePath); err != nil {
			// Log warning but continue - file might not exist yet
			fmt.Printf("Warning: Could not backup %s: %v\n", filePath, err)
		} else {
			filesBackedUp++
		}
	}

	// Update checkpoint with counts
	_, _ = database.DB.Exec(`
		UPDATE checkpoints SET files_count = $1 WHERE id = $2`,
		filesBackedUp, checkpointID,
	)
	checkpoint.FilesCount = &filesBackedUp

	return checkpoint, nil
}

// backupFile backs up a single file's content
func (m *Manager) backupFile(checkpointID int, filePath string) error {
	var content, permissions, owner, hash string
	var size int
	var isBinary bool

	cmd := fmt.Sprintf(`
		if [ -f "%s" ]; then
			stat -c '%%a %%U:%%G %%s' "%s" 2>/dev/null || echo "644 root:root 0"
			sha256sum "%s" 2>/dev/null | awk '{print $1}' || echo ""
			cat "%s" 2>/dev/null || echo ""
		else
			echo "FILE_NOT_FOUND"
		fi
	`, filePath, filePath, filePath, filePath)

	output, err := m.executeCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if strings.TrimSpace(output) == "FILE_NOT_FOUND" {
		return fmt.Errorf("file does not exist")
	}

	lines := strings.SplitN(output, "\n", 3)
	if len(lines) < 3 {
		return fmt.Errorf("unexpected output format")
	}

	// Parse stat output: permissions owner:group size
	statParts := strings.Fields(lines[0])
	if len(statParts) >= 3 {
		permissions = statParts[0]
		owner = statParts[1]
		fmt.Sscanf(statParts[2], "%d", &size)
	}
	hash = strings.TrimSpace(lines[1])
	content = strings.Join(lines[2:], "\n")

	// Check if binary (contains null bytes or non-printable chars)
	isBinary = strings.ContainsAny(content, "\x00")

	_, err = database.DB.Exec(`
		INSERT INTO checkpoint_files 
		(checkpoint_id, file_path, file_content, file_permissions, file_owner, file_size, file_hash, is_binary)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (checkpoint_id, file_path) DO UPDATE 
		SET file_content = EXCLUDED.file_content,
		    file_permissions = EXCLUDED.file_permissions,
		    file_owner = EXCLUDED.file_owner,
		    file_size = EXCLUDED.file_size,
		    file_hash = EXCLUDED.file_hash`,
		checkpointID, filePath, content, permissions, owner, size, hash, isBinary,
	)

	return err
}

// executeCommand runs a command locally or remotely
func (m *Manager) executeCommand(cmd string) (string, error) {
	if m.IsRemote {
		if m.SSHClient == nil {
			return "", fmt.Errorf("SSH client not connected")
		}
		stdout, stderr, err := m.SSHClient.ExecuteCommand(cmd)
		if err != nil {
			return stdout + stderr, err
		}
		return stdout, nil
	}

	// Local execution
	return "", fmt.Errorf("local checkpoint not implemented yet")
}

// getFilesForRules returns the list of files that may be modified by remediation
func (m *Manager) getFilesForRules(ruleIDs []string) []string {
	files := make(map[string]bool)

	for _, rule := range ruleIDs {
		// SSH related rules
		if strings.Contains(rule, "sshd") {
			files["/etc/ssh/sshd_config"] = true
			files["/etc/ssh/sshd_config.d/50-cloud-init.conf"] = true
		}

		// Sysctl rules
		if strings.Contains(rule, "sysctl") {
			files["/etc/sysctl.conf"] = true
			files["/etc/sysctl.d/99-oscap.conf"] = true
		}

		// Audit rules
		if strings.Contains(rule, "audit") {
			files["/etc/audit/auditd.conf"] = true
			files["/etc/audit/rules.d/audit.rules"] = true
		}

		// Logrotate
		if strings.Contains(rule, "logrotate") {
			files["/etc/logrotate.conf"] = true
		}

		// Service related
		if strings.Contains(rule, "service_") {
			// Services are handled via systemctl, no config file to backup
		}

		// PAM rules
		if strings.Contains(rule, "pam") {
			files["/etc/pam.d/common-auth"] = true
			files["/etc/pam.d/common-password"] = true
			files["/etc/pam.d/system-auth"] = true
		}

		// Password rules
		if strings.Contains(rule, "password") || strings.Contains(rule, "passwd") {
			files["/etc/login.defs"] = true
			files["/etc/security/pwquality.conf"] = true
		}

		// Grub/boot
		if strings.Contains(rule, "grub") || strings.Contains(rule, "boot") {
			files["/etc/default/grub"] = true
		}
	}

	result := make([]string, 0, len(files))
	for file := range files {
		result = append(result, file)
	}
	return result
}

// GetCheckpoints returns all checkpoints for a node
func (m *Manager) GetCheckpoints() ([]models.Checkpoint, error) {
	rows, err := database.DB.Query(`
		SELECT id, node_id, hostname, scan_id, name, description, checkpoint_type,
		       compliance_score, total_failures, files_count, packages_count, 
		       services_count, is_active, created_at
		FROM checkpoints
		WHERE node_id = $1 AND is_active = true
		ORDER BY created_at DESC`,
		m.NodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checkpoints []models.Checkpoint
	for rows.Next() {
		var cp models.Checkpoint
		err := rows.Scan(
			&cp.ID, &cp.NodeID, &cp.Hostname, &cp.ScanID, &cp.Name, &cp.Description,
			&cp.CheckpointType, &cp.ComplianceScore, &cp.TotalFailures, &cp.FilesCount,
			&cp.PackagesCount, &cp.ServicesCount, &cp.IsActive, &cp.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		checkpoints = append(checkpoints, cp)
	}

	return checkpoints, nil
}

// RestoreCheckpoint restores system state from a checkpoint
func (m *Manager) RestoreCheckpoint(checkpointID int) error {
	// Get checkpoint files
	rows, err := database.DB.Query(`
		SELECT file_path, file_content, file_permissions, file_owner
		FROM checkpoint_files
		WHERE checkpoint_id = $1`,
		checkpointID,
	)
	if err != nil {
		return fmt.Errorf("failed to get checkpoint files: %w", err)
	}
	defer rows.Close()

	var restoredCount, failedCount int
	for rows.Next() {
		var filePath, content, permissions, owner string
		if err := rows.Scan(&filePath, &content, &permissions, &owner); err != nil {
			failedCount++
			continue
		}

		if err := m.restoreFile(filePath, content, permissions, owner); err != nil {
			fmt.Printf("Warning: Failed to restore %s: %v\n", filePath, err)
			failedCount++
		} else {
			restoredCount++
		}
	}

	if restoredCount == 0 && failedCount > 0 {
		return fmt.Errorf("failed to restore any files")
	}

	fmt.Printf("Restored %d files, %d failed\n", restoredCount, failedCount)

	// Deactivate the checkpoint after use
	_, _ = database.DB.Exec(`UPDATE checkpoints SET is_active = false WHERE id = $1`, checkpointID)

	return nil
}

// restoreFile restores a single file from backup
func (m *Manager) restoreFile(filePath, content, permissions, owner string) error {
	// Create a temporary file and move it to the destination
	cmd := fmt.Sprintf(`
		cat > /tmp/restore_file_$$ << 'RESTORE_EOF'
%s
RESTORE_EOF
		sudo mv /tmp/restore_file_$$ "%s"
		sudo chmod %s "%s" 2>/dev/null || true
		sudo chown %s "%s" 2>/dev/null || true
	`, content, filePath, permissions, filePath, owner, filePath)

	_, err := m.executeCommand(cmd)
	return err
}

// DeleteCheckpoint marks a checkpoint as inactive
func (m *Manager) DeleteCheckpoint(checkpointID int) error {
	_, err := database.DB.Exec(`UPDATE checkpoints SET is_active = false WHERE id = $1`, checkpointID)
	return err
}
