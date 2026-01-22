package checkpoint

import (
	"encoding/base64"
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
		CheckpointType: "auto", // 'auto' for system-created, 'manual' for user-created
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
		ruleLower := strings.ToLower(rule)
		
		// SSH related rules
		if strings.Contains(ruleLower, "sshd") || strings.Contains(ruleLower, "ssh_") {
			files["/etc/ssh/sshd_config"] = true
			files["/etc/ssh/sshd_config.d/50-cloud-init.conf"] = true
			files["/etc/ssh/sshd_config.d/50-redhat.conf"] = true
			files["/etc/ssh/ssh_config"] = true
		}

		// Sysctl rules (network, kernel settings)
		if strings.Contains(ruleLower, "sysctl") || strings.Contains(ruleLower, "kernel") ||
		   strings.Contains(ruleLower, "net_ipv4") || strings.Contains(ruleLower, "net_ipv6") {
			files["/etc/sysctl.conf"] = true
			files["/etc/sysctl.d/99-oscap.conf"] = true
			files["/etc/sysctl.d/99-sysctl.conf"] = true
		}

		// Audit rules
		if strings.Contains(ruleLower, "audit") {
			files["/etc/audit/auditd.conf"] = true
			files["/etc/audit/rules.d/audit.rules"] = true
			files["/etc/audit/rules.d/30-ospp-v42-1-create-failed.rules"] = true
			files["/etc/audit/rules.d/30-ospp-v42-1-create-success.rules"] = true
		}

		// Logrotate and journald
		if strings.Contains(ruleLower, "logrotate") || strings.Contains(ruleLower, "journald") {
			files["/etc/logrotate.conf"] = true
			files["/etc/systemd/journald.conf"] = true
		}

		// PAM rules
		if strings.Contains(ruleLower, "pam") || strings.Contains(ruleLower, "faillock") {
			files["/etc/pam.d/common-auth"] = true
			files["/etc/pam.d/common-password"] = true
			files["/etc/pam.d/system-auth"] = true
			files["/etc/pam.d/password-auth"] = true
			files["/etc/pam.d/su"] = true
			files["/etc/security/faillock.conf"] = true
		}

		// Password and account rules
		if strings.Contains(ruleLower, "password") || strings.Contains(ruleLower, "passwd") ||
		   strings.Contains(ruleLower, "account") || strings.Contains(ruleLower, "login_defs") {
			files["/etc/login.defs"] = true
			files["/etc/security/pwquality.conf"] = true
			files["/etc/default/useradd"] = true
		}

		// Grub/boot
		if strings.Contains(ruleLower, "grub") || strings.Contains(ruleLower, "boot") {
			files["/etc/default/grub"] = true
			files["/boot/grub2/grub.cfg"] = true
			files["/etc/grub.d/01_users"] = true
		}

		// Crypto policy
		if strings.Contains(ruleLower, "crypto") {
			files["/etc/crypto-policies/config"] = true
		}

		// Coredump
		if strings.Contains(ruleLower, "coredump") {
			files["/etc/systemd/coredump.conf"] = true
		}

		// Banners
		if strings.Contains(ruleLower, "banner") || strings.Contains(ruleLower, "issue") {
			files["/etc/issue"] = true
			files["/etc/issue.net"] = true
			files["/etc/motd"] = true
		}

		// AIDE (file integrity)
		if strings.Contains(ruleLower, "aide") {
			files["/etc/aide.conf"] = true
		}

		// Cron
		if strings.Contains(ruleLower, "cron") {
			files["/etc/crontab"] = true
			files["/etc/cron.allow"] = true
			files["/etc/cron.deny"] = true
			files["/etc/anacrontab"] = true
		}

		// Sudo
		if strings.Contains(ruleLower, "sudo") {
			files["/etc/sudoers"] = true
			files["/etc/sudoers.d/00-oscap"] = true
		}

		// UMASK
		if strings.Contains(ruleLower, "umask") {
			files["/etc/bashrc"] = true
			files["/etc/profile"] = true
			files["/etc/profile.d/oscap-umask.sh"] = true
		}

		// TMOUT (shell timeout)
		if strings.Contains(ruleLower, "tmout") {
			files["/etc/profile"] = true
			files["/etc/profile.d/tmout.sh"] = true
			files["/etc/bashrc"] = true
		}

		// Modprobe/kernel modules
		if strings.Contains(ruleLower, "kernel_module") || strings.Contains(ruleLower, "modprobe") {
			files["/etc/modprobe.d/blacklist.conf"] = true
			files["/etc/modprobe.d/oscap-blacklist.conf"] = true
		}

		// Firewall
		if strings.Contains(ruleLower, "firewalld") || strings.Contains(ruleLower, "nftables") ||
		   strings.Contains(ruleLower, "iptables") {
			files["/etc/firewalld/firewalld.conf"] = true
		}

		// SELinux
		if strings.Contains(ruleLower, "selinux") {
			files["/etc/selinux/config"] = true
		}

		// Mount options
		if strings.Contains(ruleLower, "mount") {
			files["/etc/fstab"] = true
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
	restoredFiles := []string{}
	
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
			restoredFiles = append(restoredFiles, filePath)
		}
	}

	if restoredCount == 0 && failedCount > 0 {
		return fmt.Errorf("failed to restore any files")
	}

	fmt.Printf("Restored %d files, %d failed\n", restoredCount, failedCount)
	
	// Reload services that may have been affected
	m.reloadAffectedServices(restoredFiles)

	// Deactivate the checkpoint after use
	_, _ = database.DB.Exec(`UPDATE checkpoints SET is_active = false WHERE id = $1`, checkpointID)

	return nil
}

// reloadAffectedServices reloads services based on which config files were restored
func (m *Manager) reloadAffectedServices(restoredFiles []string) {
	servicesToReload := make(map[string]bool)
	
	for _, filePath := range restoredFiles {
		// SSH config changes
		if strings.Contains(filePath, "/etc/ssh/") {
			servicesToReload["sshd"] = true
		}
		
		// Sysctl changes
		if strings.Contains(filePath, "sysctl") {
			servicesToReload["sysctl-reload"] = true
		}
		
		// Audit config changes
		if strings.Contains(filePath, "/etc/audit/") {
			servicesToReload["auditd"] = true
		}
		
		// Journald changes
		if strings.Contains(filePath, "journald") {
			servicesToReload["systemd-journald"] = true
		}
		
		// Firewalld changes
		if strings.Contains(filePath, "firewalld") {
			servicesToReload["firewalld"] = true
		}
	}
	
	// Reload each affected service
	for service := range servicesToReload {
		var cmd string
		if service == "sysctl-reload" {
			cmd = "sudo sysctl --system 2>/dev/null || true"
		} else {
			cmd = fmt.Sprintf("sudo systemctl reload %s 2>/dev/null || sudo systemctl restart %s 2>/dev/null || true", service, service)
		}
		
		output, err := m.executeCommand(cmd)
		if err != nil {
			fmt.Printf("⚠️  Could not reload %s: %v\n", service, err)
		} else {
			if strings.TrimSpace(output) != "" {
				fmt.Printf("   %s\n", strings.TrimSpace(output))
			}
			fmt.Printf("🔄 Reloaded: %s\n", service)
		}
	}
}

// restoreFile restores a single file from backup
func (m *Manager) restoreFile(filePath, content, permissions, owner string) error {
	// Use base64 encoding to safely transfer file content
	// This avoids issues with special characters in heredocs
	encoded := base64Encode(content)
	
	// Create script that decodes base64 and restores file
	cmd := fmt.Sprintf(`
		ENCODED="%s"
		DEST="%s"
		PERMS="%s"
		OWNER="%s"
		
		# Create temp file
		TMPFILE=$(mktemp)
		
		# Decode base64 content to temp file
		echo "$ENCODED" | base64 -d > "$TMPFILE" 2>/dev/null
		
		# Backup current file if exists
		if [ -f "$DEST" ]; then
			sudo cp "$DEST" "${DEST}.bak" 2>/dev/null || true
		fi
		
		# Move temp file to destination
		sudo mv "$TMPFILE" "$DEST"
		
		# Restore permissions and owner
		sudo chmod "$PERMS" "$DEST" 2>/dev/null || true
		sudo chown "$OWNER" "$DEST" 2>/dev/null || true
		
		echo "RESTORED: $DEST"
	`, encoded, filePath, permissions, owner)

	output, err := m.executeCommand(cmd)
	if err != nil {
		return fmt.Errorf("restore failed: %w (output: %s)", err, output)
	}
	return nil
}

// base64Encode encodes string to base64
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// DeleteCheckpoint marks a checkpoint as inactive
func (m *Manager) DeleteCheckpoint(checkpointID int) error {
	_, err := database.DB.Exec(`UPDATE checkpoints SET is_active = false WHERE id = $1`, checkpointID)
	return err
}
