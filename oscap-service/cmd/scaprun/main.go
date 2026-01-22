package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"oscap-service/internal/checkpoint"
	"oscap-service/internal/config"
	"oscap-service/internal/database"
	"oscap-service/internal/remediation"
	"oscap-service/internal/scanner"
	sshpkg "oscap-service/pkg/ssh"
	
	"github.com/joho/godotenv"
)

// Session holds the current execution context
type Session struct {
	cfg                  *config.Config
	targetMode           string // "local" or "remote"
	sshClient            *sshpkg.Client
	targetHost           string
	targetOS             string
	nodeID               int
	nodeName             string
	selectedProfile      string // Full XCCDF profile ID for oscap
	selectedProfileShort string // Short name for display/database
	selectedProfileTitle string // Human-readable title for display
}

var session *Session

func main() {
	// Initialize
	if err := initialize(); err != nil {
		log.Fatalf("%s[-]%s Initialization failed: %v", Red, Reset, err)
	}

	// Clear screen and show banner
	ClearScreen()
	PrintBanner()
	PrintMainMenu()

	// Main menu loop
	for {
		// Show styled prompt
		PrintPrompt("")
		choice := readInputRaw()

		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1", "target":
			selectTarget()
		case "2", "profile":
			selectProfile()
		case "3", "install":
			installOpenSCAP()
		case "4", "scan":
			runScan()
		case "5", "status", "view":
			viewStatus()
		case "6", "remediate":
			remediateMenu()
		case "7", "rollback":
			rollbackMenu()
		case "8", "reports", "report":
			reportsMenu()
		case "9", "clear":
			ClearScreen()
			PrintBanner()
			PrintMainMenu()
		case "0", "exit", "quit":
			fmt.Println("\n" + HPEGreen + "[*]" + Reset + " Goodbye!")
			cleanup()
			os.Exit(0)
		case "help", "?", "menu":
			PrintMainMenu()
		case "":
			continue
		default:
			PrintError("Unknown command: %s (type 'help' for commands)", choice)
		}
	}
}

// initialize loads config and connects to database
func initialize() error {
	var err error

	// Load .env file from binary directory or current directory
	// Try current directory first
	if err := godotenv.Load(); err != nil {
		// If not found, try the oscap-service directory
		if err := godotenv.Load("oscap-service/.env"); err != nil {
			// If still not found, try relative to binary location
			exePath, _ := os.Executable()
			exeDir := strings.TrimSuffix(exePath, "/scaprun")
			envPath := exeDir + "/.env"
			if err := godotenv.Load(envPath); err != nil {
				// Silent fail or debug log
			}
		}
	}

	// Load configuration
	session = &Session{}
	session.cfg, err = config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Connect to central database on admin node
	if err := database.Connect(session.cfg.DB.ConnectionString()); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	return nil
}

// showMainMenu displays the main menu (now delegated to style.go)
func showMainMenu() {
	PrintMainMenu()
	showSessionStatus()
}

// showSessionStatus displays current session info
func showSessionStatus() {
	if session.targetMode != "" {
		headers := []string{"Component", "Status", "Details"}
		rows := [][]string{}
		
		if session.targetMode == "local" {
			rows = append(rows, []string{"Target", "Connected", "Local (Admin Node)"})
		} else {
			rows = append(rows, []string{"Target", "Connected", session.targetHost + " (SSH)"})
		}
		
		rows = append(rows, []string{"OS", "Detected", session.targetOS})
		
		if session.selectedProfile != "" {
			rows = append(rows, []string{"Profile", "Active", session.selectedProfileShort})
		} else {
			rows = append(rows, []string{"Profile", "Not Set", "-"})
		}
		
		PrintStatusTable(headers, rows)
	}
}

// readInput reads a line from stdin with a prompt
func readInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// readInputRaw reads a line from stdin without a prompt (prompt shown separately)
func readInputRaw() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// selectTarget handles target selection menu
func selectTarget() {
	PrintSection("Target Selection")
	
	fmt.Printf("   %s[1]%s %-15s %s- %sLocal (This Admin Node)%s\n", HPEGreen, Reset, Bold+"local"+Reset, DarkGray, White, Reset)
	fmt.Printf("   %s[2]%s %-15s %s- %sRemote Node (via SSH)%s\n", HPEGreen, Reset, Bold+"remote"+Reset, DarkGray, White, Reset)
	fmt.Printf("   %s[0]%s %-15s %s- %sBack to Main Menu%s\n\n", HPEGreen, Reset, Bold+"back"+Reset, DarkGray, White, Reset)
	
	choice := readInput(HPEGreen + "  Select target > " + Reset)
	
	switch choice {
	case "1", "local":
		selectLocalTarget()
	case "2", "remote":
		selectRemoteTarget()
	case "0", "back":
		return
	default:
		PrintError("Invalid choice")
	}
}

// selectLocalTarget sets up local execution mode
func selectLocalTarget() {
	PrintInfo("Setting up local target...")
	
	// Detect local OS
	osInfo := detectOS()
	hostname, _ := os.Hostname()
	
	// Register or get node in database
	nodeID, err := database.RegisterNode(
		hostname,
		hostname,
		"Admin node - local execution",
		osInfo,
		"admin",
	)
	
	if err != nil {
		// Try to get existing node
		nodeID, _, err = database.GetNodeByHostname(hostname)
		if err != nil {
			PrintError("Failed to register node: %v", err)
			return
		}
	}
	
	// Update session
	session.targetMode = "local"
	session.targetHost = hostname
	session.targetOS = osInfo
	session.nodeID = nodeID
	session.nodeName = hostname
	session.sshClient = nil
	
	// Update heartbeat
	database.UpdateNodeHeartbeat(nodeID)
	
	PrintSuccess("Target set to LOCAL")
	
	// Show connection status table
	headers := []string{"Property", "Value"}
	rows := [][]string{
		{"Host", hostname},
		{"OS", osInfo},
		{"Node ID", fmt.Sprintf("%d", nodeID)},
		{"Status", "Connected"},
	}
	PrintStatusTable(headers, rows)
}

// selectRemoteTarget sets up SSH connection
func selectRemoteTarget() {
	PrintSection("SSH Connection Setup")
	
	// Get connection details
	host := readInput(HPEGreen + "  Hostname/IP > " + Reset)
	if host == "" {
		PrintError("Hostname is required")
		return
	}
	
	port := readInput(HPEGreen + "  SSH Port [22] > " + Reset)
	if port == "" {
		port = "22"
	}
	
	username := readInput(HPEGreen + "  Username > " + Reset)
	if username == "" {
		PrintError("Username is required")
		return
	}
	
	// Get authentication method
	fmt.Println()
	fmt.Printf("   %s[1]%s Password\n", HPEGreen, Reset)
	fmt.Printf("   %s[2]%s SSH Key\n\n", HPEGreen, Reset)
	authChoice := readInput(HPEGreen + "  Auth method [1] > " + Reset)
	if authChoice == "" {
		authChoice = "1"
	}
	
	portNum := 22
	if port != "22" {
		fmt.Sscanf(port, "%d", &portNum)
	}
	
	var sshClient *sshpkg.Client
	
	if authChoice == "1" {
		// Password authentication
		password := readPassword(HPEGreen + "  Password > " + Reset)
		sshClient = sshpkg.NewClient(host, portNum, username, password, "")
	} else {
		// Key authentication
		keyPath := readInput(HPEGreen + "  Key path [~/.ssh/id_rsa] > " + Reset)
		if keyPath == "" {
			keyPath = "~/.ssh/id_rsa"
		}
		// Expand ~ to home directory
		if strings.HasPrefix(keyPath, "~/") {
			homeDir, _ := os.UserHomeDir()
			keyPath = strings.Replace(keyPath, "~", homeDir, 1)
		}
		
		// Read key file
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			PrintError("Failed to read SSH key: %v", err)
			return
		}
		
		sshClient = sshpkg.NewClient(host, portNum, username, "", string(keyData))
	}
	
	// Test connection
	PrintInfo("Testing SSH connection...")
	if err := sshClient.TestConnection(); err != nil {
		PrintError("SSH connection failed: %v", err)
		return
	}
	
	PrintSuccess("SSH connection successful")
	
	// Detect remote OS
	PrintInfo("Detecting OS...")
	osInfo, err := sshClient.DetectOS()
	if err != nil {
		PrintWarning("Could not detect OS: %v", err)
		osInfo = "unknown"
	}
	osInfo = strings.TrimSpace(osInfo)
	
	// Register or get node in database
	nodeID, err := database.RegisterNode(
		host,
		host,
		fmt.Sprintf("Remote node via SSH - %s", username),
		osInfo,
		"compute",
	)
	
	if err != nil {
		// Try to get existing node
		nodeID, _, err = database.GetNodeByHostname(host)
		if err != nil {
			PrintError("Failed to register node: %v", err)
			return
		}
	}
	
	// Update session
	session.targetMode = "remote"
	session.targetHost = host
	session.targetOS = osInfo
	session.nodeID = nodeID
	session.nodeName = host
	session.sshClient = sshClient
	
	// Update heartbeat
	database.UpdateNodeHeartbeat(nodeID)
	
	PrintSuccess("Target set to REMOTE")
	
	// Show connection status table
	headers := []string{"Property", "Value"}
	rows := [][]string{
		{"Host", fmt.Sprintf("%s:%s", host, port)},
		{"User", username},
		{"OS", osInfo},
		{"Node ID", fmt.Sprintf("%d", nodeID)},
		{"Status", "Connected"},
	}
	PrintStatusTable(headers, rows)
}

// readPassword reads password without echoing
func readPassword(prompt string) string {
	fmt.Print(prompt)
	// For now, just read normally - we can enhance this later with terminal package
	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(password)
}

// installOpenSCAP installs OpenSCAP on the target node
func installOpenSCAP() {
	if session.targetMode == "" {
		PrintError("Please select a target first (use 'target')")
		return
	}
	
	PrintSection("Install OpenSCAP")
	PrintKeyValue("Target", fmt.Sprintf("%s (%s)", session.targetHost, session.targetOS))
	
	// Get script path relative to binary or use absolute path
	scriptPath := "scripts/install_oscap.sh"
	
	// If relative path doesn't exist, try absolute path
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		scriptPath = "/home/bipin/OSCAP-project/oscap-service/scripts/install_oscap.sh"
	}
	
	// Read the install script
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		PrintError("Failed to read install script: %v", err)
		return
	}
	
	var output string
	
	if session.targetMode == "local" {
		// Local installation
		PrintInfo("Installing locally...")
		
		// Write script to temp file
		tmpScript := "/tmp/install_oscap_local.sh"
		if err := os.WriteFile(tmpScript, scriptContent, 0755); err != nil {
			PrintError("Failed to write temp script: %v", err)
			return
		}
		defer os.Remove(tmpScript)
		
		// Execute locally
		cmd := fmt.Sprintf("sudo bash %s", tmpScript)
		output, err = executeLocalCommand(cmd)
		
	} else {
		// Remote installation via SSH
		PrintInfo("Installing via SSH...")
		
		if session.sshClient == nil {
			PrintError("SSH client not initialized")
			return
		}
		
		// Execute script content on remote host
		output, err = session.sshClient.ExecuteScriptContent(string(scriptContent))
	}
	
	if err != nil {
		PrintError("Installation failed: %v", err)
		PrintInfo("Installation output:")
		fmt.Println(output)
		return
	}
	
	// Parse and display output
	PrintInfo("Installation output:")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "SUCCESS:") {
			PrintSuccess(strings.TrimPrefix(line, "SUCCESS: "))
		} else if strings.HasPrefix(line, "ERROR:") {
			PrintError(strings.TrimPrefix(line, "ERROR: "))
		} else if strings.HasPrefix(line, "WARNING:") {
			PrintWarning(strings.TrimPrefix(line, "WARNING: "))
		} else if strings.HasPrefix(line, "INFO:") {
			fmt.Printf("   %s\n", strings.TrimPrefix(line, "INFO: "))
		} else if line != "" {
			fmt.Printf("   %s\n", line)
		}
	}
	
	PrintSuccess("OpenSCAP installation complete!")
}

// executeLocalCommand executes a command locally and returns output
func executeLocalCommand(cmd string) (string, error) {
	// Execute the command using bash
	execCmd := exec.Command("bash", "-c", cmd)
	
	// Capture combined output (stdout + stderr)
	output, err := execCmd.CombinedOutput()
	
	return string(output), err
}

// ProfileInfo holds profile metadata
type ProfileInfo struct {
	ID          string // Full XCCDF ID
	ShortName   string // Short name for storage
	Title       string // Human-readable title
	Description string // Profile description
	Strictness  int    // 1=Minimal, 2=Standard, 3=Strict, 4=Maximum
	Recommended bool   // Is this the recommended default?
}

// selectProfile allows user to choose a compliance profile
func selectProfile() {
	PrintSection("Select Compliance Profile")
	
	if session.targetOS == "" {
		PrintError("Please select a target first")
		return
	}
	
	PrintInfo("Detecting available profiles from target system...")
	
	// Get available profiles dynamically
	profiles, err := getAvailableProfiles()
	if err != nil {
		PrintError("Failed to detect profiles: %v", err)
		PrintWarning("Make sure OpenSCAP is installed on the target (use 'install')")
		return
	}
	
	if len(profiles) == 0 {
		PrintError("No profiles found on target system")
		PrintWarning("Install OpenSCAP first (use 'install')")
		return
	}
	
	// Display profiles with metadata
	fmt.Printf("\n%sAvailable Profiles (%d found):%s\n\n", Bold, len(profiles), Reset)
	
	for i, p := range profiles {
		// Format strictness indicator
		strictnessBar := ""
		switch p.Strictness {
		case 1:
			strictnessBar = Green + "▮" + Reset + "░░░ Minimal"
		case 2:
			strictnessBar = Yellow + "▮▮" + Reset + "░░ Standard"
		case 3:
			strictnessBar = Red + "▮▮▮" + Reset + "░ Strict"
		case 4:
			strictnessBar = Red + Bold + "▮▮▮▮ Maximum" + Reset
		}
		
		// Mark recommended
		recommended := ""
		if p.Recommended {
			recommended = Green + " [RECOMMENDED]" + Reset
		}
		
		fmt.Printf("   %s%s%d. %s%s%s\n", Bold, Cyan, i+1, Reset, p.Title, recommended)
		fmt.Printf("      ID: %s\n", p.ShortName)
		fmt.Printf("      Strictness: %s\n", strictnessBar)
		if p.Description != "" && p.Description != p.Title {
			// Truncate description if too long
			desc := p.Description
			if len(desc) > 80 {
				desc = desc[:77] + "..."
			}
			fmt.Printf("      %s\n", desc)
		}
		fmt.Println()
	}
	fmt.Printf("   %s%s%d. Cancel%s\n\n", Bold, Red, len(profiles)+1, Reset)
	
	// Get user selection
	choice := readInput(fmt.Sprintf("%sChoose profile [1-%d]: %s", Bold, len(profiles)+1, Reset))
	
	// Parse choice
	var idx int
	_, err = fmt.Sscanf(choice, "%d", &idx)
	if err != nil || idx < 1 || idx > len(profiles)+1 {
		PrintError("Invalid choice")
		return
	}
	
	if idx == len(profiles)+1 {
		PrintWarning("Profile selection cancelled")
		return
	}
	
	// Set selected profile
	selectedProfile := profiles[idx-1]
	session.selectedProfile = selectedProfile.ID                 // Full XCCDF ID for oscap
	session.selectedProfileShort = selectedProfile.ShortName     // Short name for display/database
	session.selectedProfileTitle = selectedProfile.Title         // Human-readable title
	
	PrintSuccess("Profile selected: %s", selectedProfile.Title)
	PrintKeyValue("Short Name", selectedProfile.ShortName)
	PrintKeyValue("Full ID", selectedProfile.ID)
}

// runScan executes compliance scan
func runScan() {
	if session.targetMode == "" {
		PrintError("Please select a target first (use 'target')")
		return
	}
	
	// Let user select profile if not already selected
	if session.selectedProfile == "" {
		selectProfile()
		if session.selectedProfile == "" {
			return // User cancelled
		}
	}
	
	PrintInfo("Running compliance scan...")
	PrintKeyValue("Target", fmt.Sprintf("%s (%s)", session.targetHost, session.targetOS))
	PrintKeyValue("Profile", fmt.Sprintf("%s (%s)", session.selectedProfileShort, session.selectedProfileTitle))
	
	// Create scanner instance based on mode
	var scannerInstance *scanner.Scanner
	
	if session.targetMode == "local" {
		scannerInstance = scanner.NewScanner(session.nodeID, session.nodeName, session.selectedProfile)
		PrintInfo("Executing scan locally...")
	} else {
		scannerInstance = scanner.NewRemoteScanner(session.nodeID, session.nodeName, session.selectedProfile, session.sshClient)
		PrintInfo("Executing scan via SSH...")
	}
	
	// Execute scan
	reportsPath := "/var/lib/scaprun/reports"
	scan, err := scannerInstance.ExecuteScan(reportsPath)
	
	if err != nil {
		PrintError("Scan failed: %v", err)
		return
	}
	
	// Display results with colors
	PrintSection("SCAN RESULTS")
	
	PrintKeyValue("Scan ID", fmt.Sprintf("%d", scan.ID))
	PrintKeyValue("Started", scan.StartedAt.Format("2006-01-02 15:04:05"))
	
	if scan.CompletedAt != nil {
		PrintKeyValue("Completed", scan.CompletedAt.Format("2006-01-02 15:04:05"))
	}
	if scan.DurationSeconds != nil {
		PrintKeyValue("Duration", fmt.Sprintf("%d seconds", *scan.DurationSeconds))
	}

	// Compliance score with color coding
	score := 0.0
	if scan.ComplianceScore != nil {
		score = *scan.ComplianceScore
	}
	
	var scoreColor string
	var scoreStatus string
	if score >= 90 {
		scoreColor = Green + Bold
		scoreStatus = "COMPLIANT"
	} else if score >= 70 {
		scoreColor = Yellow + Bold
		scoreStatus = "PARTIAL"
	} else {
		scoreColor = Red + Bold
		scoreStatus = "NON-COMPLIANT"
	}
	
	fmt.Printf("\n   %s█████████████████████████████████████████████████████%s\n", DarkGray, Reset)
	fmt.Printf("   %s   COMPLIANCE SCORE: %.1f%% (%s)   %s\n", scoreColor, score, scoreStatus, Reset)
	fmt.Printf("   %s█████████████████████████████████████████████████████%s\n\n", DarkGray, Reset)
	
	// Rule breakdown using table
	passed := 0
	failed := 0
	errored := 0
	notappl := 0
	
	if scan.PassedRules != nil {
		passed = *scan.PassedRules
	}
	if scan.FailedRules != nil {
		failed = *scan.FailedRules
	}
	if scan.ErrorRules != nil {
		errored = *scan.ErrorRules
	}
	if scan.NotApplicable != nil {
		notappl = *scan.NotApplicable
	}
	
	headers := []string{"Rule Status", "Count", "Percentage"}
	total := passed + failed + errored + notappl
	rows := [][]string{
		{"Passed", fmt.Sprintf("%d", passed), fmt.Sprintf("%.1f%%", float64(passed)/float64(total)*100)},
		{"Failed", fmt.Sprintf("%d", failed), fmt.Sprintf("%.1f%%", float64(failed)/float64(total)*100)},
		{"Errors", fmt.Sprintf("%d", errored), fmt.Sprintf("%.1f%%", float64(errored)/float64(total)*100)},
		{"Not Applicable", fmt.Sprintf("%d", notappl), fmt.Sprintf("%.1f%%", float64(notappl)/float64(total)*100)},
	}
	PrintStatusTable(headers, rows)
	
	// Reports
	if (scan.ReportHTMLPath != nil && *scan.ReportHTMLPath != "") || (scan.ReportXMLPath != nil && *scan.ReportXMLPath != "") {
		PrintSection("Reports")
		if scan.ReportHTMLPath != nil && *scan.ReportHTMLPath != "" {
			PrintKeyValue("HTML Report", *scan.ReportHTMLPath)
		}
		if scan.ReportXMLPath != nil && *scan.ReportXMLPath != "" {
			PrintKeyValue("XML Report", *scan.ReportXMLPath)
		}
	}
	
	// Update node compliance status
	database.DB.Exec(`
		UPDATE nodes 
		SET current_compliance_score = $1,
		    current_status = CASE
		        WHEN $1 >= 90 THEN 'compliant'
		        WHEN $1 >= 70 THEN 'partial'
		        ELSE 'non_compliant'
		    END,
		    last_scan_at = $2
		WHERE id = $3`,
		score, scan.StartedAt, session.nodeID,
	)
	
	PrintSuccess("Scan complete! Use 'status' to view details or 'remediate' to fix issues.")
}

// viewStatus shows current status
func viewStatus() {
	if session.targetMode == "" {
		PrintError("Please select a target first (use 'target')")
		return
	}
	
	PrintSection("System Status")
	
	// Build status table
	headers := []string{"Component", "Status", "Details"}
	rows := [][]string{
		{"Node Name", "Active", session.nodeName},
		{"Host", "Connected", session.targetHost},
		{"OS", "Detected", session.targetOS},
		{"Mode", "Active", session.targetMode},
		{"Node ID", "-", fmt.Sprintf("%d", session.nodeID)},
	}
	
	// Query latest scan from database
	var score *float64
	var status string
	var lastScan *string
	
	err := database.DB.QueryRow(`
		SELECT current_compliance_score, current_status, 
		       to_char(last_scan_at, 'YYYY-MM-DD HH24:MI:SS')
		FROM nodes WHERE id = $1`, session.nodeID,
	).Scan(&score, &status, &lastScan)
	
	if err == nil {
		scoreStr := "N/A"
		if score != nil {
			scoreStr = fmt.Sprintf("%.0f%%", *score)
		}
		
		scanTime := "-"
		if lastScan != nil {
			scanTime = *lastScan
		}
		
		rows = append(rows, []string{"Compliance", status, scoreStr})
		rows = append(rows, []string{"Last Scan", "-", scanTime})
	}
	
	if session.selectedProfile != "" {
		rows = append(rows, []string{"Profile", "Active", session.selectedProfileShort})
	}
	
	PrintStatusTable(headers, rows)
}

// remediateMenu shows remediation menu
func remediateMenu() {
	if session.targetMode == "" {
		PrintError("Please select a target first (use 'target')")
		return
	}
	
	PrintSection("REMEDIATION MENU")
	
	// Check if profile is selected
	if session.selectedProfile == "" {
		PrintError("Please select a profile first (use 'profile' or 'scan')")
		return
	}
	
	// Create remediator instance with profile
	var remediatorInstance *remediation.Remediator
	
	if session.targetMode == "local" {
		remediatorInstance = remediation.NewRemediator(session.nodeID, session.nodeName, session.selectedProfile)
	} else {
		remediatorInstance = remediation.NewRemoteRemediator(session.nodeID, session.nodeName, session.selectedProfile, session.sshClient)
	}
	
	// Get failed rules from latest scan
	PrintInfo("Fetching failed rules from latest scan...")
	failedRules, err := remediatorInstance.GetFailedRules()
	
	if err != nil {
		fmt.Printf("❌ Failed to fetch failed rules: %v\n", err)
		return
	}
	
	if len(failedRules) == 0 {
		fmt.Println("✨ No failed rules found! System is compliant.")
		return
	}
	
	// Display failed rules
	fmt.Printf("\n� Found %d failed rule(s):\n\n", len(failedRules))
	for i, rule := range failedRules {
		severity := strings.ToUpper(rule.Severity)
		severityIcon := "⚠️"
		if severity == "HIGH" || severity == "CRITICAL" {
			severityIcon = "🔴"
		} else if severity == "MEDIUM" {
			severityIcon = "🟡"
		} else if severity == "LOW" {
			severityIcon = "🟢"
		}
		
		fmt.Printf("%2d. %s [%s] %s\n", i+1, severityIcon, severity, rule.RuleID)
	}
	
	fmt.Println("\n" + strings.Repeat("─", 60))
	fmt.Println("\nOptions:")
	fmt.Println("1. Remediate ALL failed rules")
	fmt.Println("2. Remediate specific rules (comma-separated numbers)")
	fmt.Println("0. Back to main menu")
	fmt.Println()
	
	choice := readInput("Enter your choice: ")
	
	var selectedRules []string
	
	switch choice {
	case "0":
		return
	case "1":
		// Remediate all
		fmt.Printf("\n⚠️  WARNING: You are about to remediate %d rules.\n", len(failedRules))
		fmt.Println("This will make system changes and create a checkpoint.")
		confirm := readInput("Are you sure? (yes/no): ")
		if strings.ToLower(confirm) != "yes" {
			fmt.Println("❌ Remediation cancelled")
			return
		}
		
		for _, rule := range failedRules {
			selectedRules = append(selectedRules, rule.RuleID)
		}
		
	case "2":
		// Remediate specific
		indices := readInput("Enter rule numbers (e.g., 1,3,5): ")
		parts := strings.Split(indices, ",")
		
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if idx, err := strconv.Atoi(part); err == nil && idx >= 1 && idx <= len(failedRules) {
				selectedRules = append(selectedRules, failedRules[idx-1].RuleID)
			}
		}
		
		if len(selectedRules) == 0 {
			fmt.Println("❌ No valid rules selected")
			return
		}
		
		fmt.Printf("\n⚠️  You selected %d rule(s) for remediation.\n", len(selectedRules))
		confirm := readInput("Proceed? (yes/no): ")
		if strings.ToLower(confirm) != "yes" {
			fmt.Println("❌ Remediation cancelled")
			return
		}
		
	default:
		fmt.Println("❌ Invalid choice")
		return
	}
	
	// Create checkpoint before remediation
	PrintSection("Creating Checkpoint")
	
	var checkpointManager *checkpoint.Manager
	if session.targetMode == "remote" {
		checkpointManager = checkpoint.NewRemoteManager(session.nodeID, session.nodeName, session.sshClient)
	} else {
		checkpointManager = checkpoint.NewLocalManager(session.nodeID, session.nodeName)
	}
	
	checkpointName := fmt.Sprintf("pre_remediation_%s", time.Now().Format("20060102_150405"))
	checkpointDesc := fmt.Sprintf("Checkpoint before remediating %d rules", len(selectedRules))
	
	cp, err := checkpointManager.CreateCheckpoint(checkpointName, checkpointDesc, selectedRules, nil)
	if err != nil {
		PrintWarning("Could not create checkpoint: %v", err)
		PrintInfo("Proceeding without checkpoint (rollback will not be available)")
		confirm := readInput("Continue anyway? (yes/no): ")
		if strings.ToLower(confirm) != "yes" {
			PrintWarning("Remediation cancelled")
			return
		}
	} else {
		filesCount := 0
		if cp.FilesCount != nil {
			filesCount = *cp.FilesCount
		}
		PrintSuccess("Checkpoint created: ID %d", cp.ID)
		PrintKeyValue("Files backed up", fmt.Sprintf("%d", filesCount))
		PrintInfo("Use 'rollback' to restore if needed")
	}
	
	// Execute remediation
	PrintSection("Starting Remediation")
	PrintInfo("Remediating %d rule(s)...", len(selectedRules))
	
	result, err := remediatorInstance.RemediateRules(selectedRules)
	
	if err != nil {
		PrintError("Remediation failed: %v", err)
		return
	}
	
	// Display results
	PrintSection("REMEDIATION RESULTS")
	
	PrintKeyValue("Remediation ID", fmt.Sprintf("%d", result.ID))
	PrintKeyValue("Started", result.StartedAt.Format("2006-01-02 15:04:05"))
	if result.CompletedAt != nil {
		PrintKeyValue("Completed", result.CompletedAt.Format("2006-01-02 15:04:05"))
	}
	if result.DurationSecs != nil {
		PrintKeyValue("Duration", fmt.Sprintf("%d seconds", *result.DurationSecs))
	}
	
	attempted := result.RulesAttempted
	fixed := result.RulesSucceeded
	failed := result.RulesFailed
	
	PrintSection("Summary")
	fmt.Printf("   %s%-15s : %d%s\n", Blue, "Attempted", attempted, Reset)
	fmt.Printf("   %s%-15s : %d%s\n", Green, "Fixed", fixed, Reset)
	fmt.Printf("   %s%-15s : %d%s\n", Red, "Failed", failed, Reset)
	
	successRate := 0.0
	if attempted > 0 {
		successRate = (float64(fixed) / float64(attempted)) * 100.0
	}
	
	fmt.Printf("\n   %sSuccess Rate    : %.1f%%%s\n", Bold, successRate, Reset)

	
	fmt.Println("\n" + strings.Repeat("═", 60))
	
	if result.Status == "completed" {
		fmt.Println("\n✨ Remediation completed successfully!")
		fmt.Println("💡 Tip: Run a new scan (Option 3) to verify the fixes.")
	} else if result.Status == "partial" {
		fmt.Println("\n⚠️  Remediation completed with some failures.")
		fmt.Println("💡 Check the logs for details on failed rules.")
	} else {
		fmt.Println("\n❌ Remediation failed.")
	}
}

// rollbackMenu shows rollback menu
func rollbackMenu() {
	if session.targetMode == "" {
		PrintError("Please select a target first (use 'target')")
		return
	}
	
	PrintSection("ROLLBACK TO CHECKPOINT")
	
	// Create checkpoint manager
	var checkpointManager *checkpoint.Manager
	if session.targetMode == "remote" {
		checkpointManager = checkpoint.NewRemoteManager(session.nodeID, session.nodeName, session.sshClient)
	} else {
		checkpointManager = checkpoint.NewLocalManager(session.nodeID, session.nodeName)
	}
	
	// Get available checkpoints
	PrintInfo("Fetching available checkpoints...")
	checkpoints, err := checkpointManager.GetCheckpoints()
	if err != nil {
		PrintError("Failed to fetch checkpoints: %v", err)
		return
	}
	
	if len(checkpoints) == 0 {
		PrintWarning("No checkpoints available for this node.")
		PrintInfo("Checkpoints are automatically created before each remediation.")
		return
	}
	
	PrintInfo("Found %d checkpoint(s):", len(checkpoints))
	fmt.Println()
	
	for i, cp := range checkpoints {
		score := "N/A"
		if cp.ComplianceScore != nil {
			score = fmt.Sprintf("%.1f%%", *cp.ComplianceScore)
		}
		files := 0
		if cp.FilesCount != nil {
			files = *cp.FilesCount
		}
		
		fmt.Printf("   %d. %s%s%s\n", i+1, Bold, cp.Name, Reset)
		fmt.Printf("       Created: %s\n", cp.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("       Score at checkpoint: %s | Files: %d\n", score, files)
		if cp.Description != "" {
			fmt.Printf("       %s\n", cp.Description)
		}
		fmt.Println()
	}
	
	fmt.Printf("   %s0. Back to main menu%s\n\n", Bold, Reset)
	
	choice := readInput("Select checkpoint to restore (number): ")
	if choice == "0" {
		return
	}
	
	idx, err := strconv.Atoi(choice)
	if err != nil || idx < 1 || idx > len(checkpoints) {
		PrintError("Invalid selection")
		return
	}
	
	selectedCP := checkpoints[idx-1]
	
	PrintWarning("WARNING: You are about to restore checkpoint:")
	fmt.Printf("   %s%s%s\n", Bold, selectedCP.Name, Reset)
	fmt.Printf("   Created: %s\n", selectedCP.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println("\nThis will:")
	fmt.Println("  • Restore backed up configuration files")
	fmt.Println("  • Overwrite current configurations")
	fmt.Println("  • May require service restarts")
	fmt.Println()
	
	confirm := readInput("Type 'RESTORE' to confirm: ")
	if confirm != "RESTORE" {
		PrintWarning("Rollback cancelled")
		return
	}
	
	PrintInfo("Restoring checkpoint...")
	
	if err := checkpointManager.RestoreCheckpoint(selectedCP.ID); err != nil {
		PrintError("Rollback failed: %v", err)
		return
	}
	
	PrintSuccess("Checkpoint restored successfully!")
	PrintInfo("Tip: Run a new scan to verify the system state")
	PrintWarning("Some changes may require service restarts or reboot")
}

// reportsMenu shows reports menu
func reportsMenu() {
	if session.targetMode == "" {
		PrintError("Please select a target first (use 'target')")
		return
	}
	
	PrintSection("Download Reports")
	PrintWarning("Not yet implemented")
	// TODO: Implement in Task 8
}

// cleanup closes connections and cleans up resources
func cleanup() {
	// SSH client doesn't need explicit close as connections are per-operation
	if database.DB != nil {
		database.DB.Close()
	}
}

// detectOS detects the operating system
func detectOS() string {
	// Read from /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	
	lines := string(data)
	for _, line := range strings.Split(lines, "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	
	return "unknown"
}

// getAvailableProfiles dynamically detects available profiles from target system
func getAvailableProfiles() ([]ProfileInfo, error) {
	// First, detect SCAP content file location
	contentFile, err := detectSCAPContent()
	if err != nil {
		return nil, fmt.Errorf("failed to detect SCAP content: %w", err)
	}
	
	// Get oscap info output
	var output string
	
	if session.targetMode == "local" {
		cmd := exec.Command("oscap", "info", contentFile)
		outBytes, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("oscap info failed: %w (output: %s)", err, string(outBytes))
		}
		output = string(outBytes)
	} else {
		// Remote execution
		if session.sshClient == nil {
			return nil, fmt.Errorf("SSH client not initialized")
		}
		
		cmd := fmt.Sprintf("oscap info %s 2>&1", contentFile)
		stdout, stderr, err := session.sshClient.ExecuteCommand(cmd)
		output = stdout + stderr
		if err != nil {
			return nil, fmt.Errorf("remote oscap info failed: %w", err)
		}
	}
	
	// Parse profiles from output
	profiles := parseProfilesFromOscapInfo(output)
	
	// Add metadata and recommendations
	profiles = enrichProfileMetadata(profiles)
	
	return profiles, nil
}

// detectSCAPContent finds the SCAP content file on target system
func detectSCAPContent() (string, error) {
	// Script to detect content file
	script := `#!/bin/bash
set -e

if [ ! -f /etc/os-release ]; then
    echo "ERROR: Cannot detect OS"
    exit 1
fi

. /etc/os-release

# Try to find SCAP content based on OS
case "$ID" in
    rhel|centos|rocky|almalinux)
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d. -f1)
        
        # Try multiple patterns for RHEL family
        for pattern in \
            "/usr/share/xml/scap/ssg/content/ssg-rhel${MAJOR_VERSION}-ds.xml" \
            "/usr/share/xml/scap/ssg/content/ssg-${ID}${MAJOR_VERSION}-ds.xml" \
            "/usr/share/xml/scap/ssg/content/ssg-cs${MAJOR_VERSION}-ds.xml" \
            "/usr/share/xml/scap/ssg/content/ssg-rl${MAJOR_VERSION}-ds.xml" \
            "/usr/share/xml/scap/ssg/content/ssg-almalinux${MAJOR_VERSION}-ds.xml" \
            "/usr/share/scap-security-guide/ssg-rhel${MAJOR_VERSION}-ds.xml" \
            "/usr/share/scap-security-guide/ssg-${ID}${MAJOR_VERSION}-ds.xml"
        do
            if [ -f "$pattern" ]; then
                echo "$pattern"
                exit 0
            fi
        done
        ;;
        
    ubuntu)
        VERSION_NUM=$(echo "$VERSION_ID" | tr -d '.')
        
        for pattern in \
            "/usr/share/xml/scap/ssg/content/ssg-ubuntu${VERSION_NUM}-ds.xml" \
            "/usr/share/scap-security-guide/ssg-ubuntu${VERSION_NUM}-ds.xml"
        do
            if [ -f "$pattern" ]; then
                echo "$pattern"
                exit 0
            fi
        done
        ;;
        
    sles|sles_sap)
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d. -f1)
        
        # Try exact version first, then fallback to SLE 15 for newer versions
        for pattern in \
            "/usr/share/xml/scap/ssg/content/ssg-sle${MAJOR_VERSION}-ds.xml" \
            "/usr/share/scap-security-guide/ssg-sle${MAJOR_VERSION}-ds.xml" \
            "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml" \
            "/usr/share/scap-security-guide/ssg-sle15-ds.xml"
        do
            if [ -f "$pattern" ]; then
                echo "$pattern"
                exit 0
            fi
        done
        ;;
        
    debian)
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d. -f1)
        
        for pattern in \
            "/usr/share/xml/scap/ssg/content/ssg-debian${MAJOR_VERSION}-ds.xml" \
            "/usr/share/scap-security-guide/ssg-debian${MAJOR_VERSION}-ds.xml"
        do
            if [ -f "$pattern" ]; then
                echo "$pattern"
                exit 0
            fi
        done
        ;;
        
    fedora)
        for pattern in \
            "/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml" \
            "/usr/share/scap-security-guide/ssg-fedora-ds.xml"
        do
            if [ -f "$pattern" ]; then
                echo "$pattern"
                exit 0
            fi
        done
        ;;
esac

echo "ERROR: No SCAP content found"
exit 1
`
	
	var output string
	var err error
	
	if session.targetMode == "local" {
		cmd := exec.Command("bash", "-c", script)
		outBytes, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("detection script failed: %w", err)
		}
		output = string(outBytes)
	} else {
		output, err = session.sshClient.ExecuteScriptContent(script)
		if err != nil {
			return "", fmt.Errorf("remote detection failed: %w", err)
		}
	}
	
	// Extract content file path from output
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, ".xml") {
			return line, nil
		}
	}
	
	return "", fmt.Errorf("no content file found in output: %s", output)
}

// parseProfilesFromOscapInfo parses profile information from oscap info output
func parseProfilesFromOscapInfo(output string) []ProfileInfo {
	var profiles []ProfileInfo
	lines := strings.Split(output, "\n")
	
	inProfilesSection := false
	
	for i, line := range lines {
		// Check if we entered Profiles section
		if strings.Contains(line, "Profiles:") {
			inProfilesSection = true
			continue
		}
		
		// Check if we exited Profiles section
		if inProfilesSection && !strings.HasPrefix(line, "\t") && strings.TrimSpace(line) != "" && !strings.HasPrefix(line, " ") {
			inProfilesSection = false
		}
		
		if !inProfilesSection {
			continue
		}
		
		trimmed := strings.TrimSpace(line)
		
		// Look for "Title:" lines (they come BEFORE "Id:" in oscap output)
		// Only match if the line starts with whitespace (indented profile entries)
		if strings.HasPrefix(trimmed, "Title:") && (strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "  ")) {
			// Extract title
			title := strings.TrimSpace(strings.TrimPrefix(trimmed, "Title:"))
			
			// Look for the NEXT line with "Id:" (should also be indented)
			profileID := ""
			if i+1 < len(lines) {
				nextLine := lines[i+1]
				nextTrimmed := strings.TrimSpace(nextLine)
				if strings.HasPrefix(nextTrimmed, "Id:") && (strings.HasPrefix(nextLine, "\t") || strings.HasPrefix(nextLine, "  ")) {
					profileID = strings.TrimSpace(strings.TrimPrefix(nextTrimmed, "Id:"))
				}
			}
			
			// Skip if no ID found
			if profileID == "" {
				continue
			}
			
			// Extract short name from full ID
			// Format: xccdf_org.ssgproject.content_profile_SHORTNAME
			shortName := profileID
			if strings.Contains(profileID, "_profile_") {
				parts := strings.Split(profileID, "_profile_")
				if len(parts) == 2 {
					shortName = parts[1]
				}
			}
			
			profile := ProfileInfo{
				ID:        profileID,
				ShortName: shortName,
				Title:     title,
			}
			profiles = append(profiles, profile)
		}
	}
	
	return profiles
}

// enrichProfileMetadata adds strictness levels and recommendations
func enrichProfileMetadata(profiles []ProfileInfo) []ProfileInfo {
	// OS detection for recommended profile
	osLower := strings.ToLower(session.targetOS)
	
	for i := range profiles {
		p := &profiles[i]
		
		// Convert to lowercase for matching
		idLower := strings.ToLower(p.ID)
		shortLower := strings.ToLower(p.ShortName)
		titleLower := strings.ToLower(p.Title)
		
		// Default values
		p.Strictness = 2
		p.Description = p.Title
		
		// Match by ID/ShortName patterns and assign strictness
		if strings.Contains(shortLower, "ospp") || strings.Contains(idLower, "ospp") {
			p.Strictness = 4
			p.Description = "Operating System Protection Profile (very strict, government/military)"
		} else if strings.Contains(shortLower, "stig") || strings.Contains(idLower, "stig") {
			p.Strictness = 4
			p.Description = "Security Technical Implementation Guide (DoD standard)"
		} else if strings.Contains(shortLower, "cui") || strings.Contains(idLower, "cui") {
			p.Strictness = 4
			p.Description = "Controlled Unclassified Information"
		} else if strings.Contains(titleLower, "level 2") || strings.Contains(shortLower, "cis_server_l2") || 
		           strings.Contains(shortLower, "cis_level2") || strings.Contains(titleLower, "cis") && strings.Contains(titleLower, "level 2") {
			p.Strictness = 3
			p.Description = "CIS Level 2 - Stricter security for high-security environments"
		} else if strings.Contains(shortLower, "pci") || strings.Contains(idLower, "pci-dss") {
			p.Strictness = 3
			p.Description = "Payment Card Industry Data Security Standard"
		} else if strings.Contains(shortLower, "hipaa") || strings.Contains(idLower, "hipaa") {
			p.Strictness = 3
			p.Description = "Health Insurance Portability and Accountability Act"
		} else if strings.Contains(shortLower, "e8") || strings.Contains(idLower, "essential") {
			p.Strictness = 3
			p.Description = "Essential Eight - Australian Cyber Security Centre"
		} else if strings.Contains(shortLower, "ism") || strings.Contains(titleLower, "ism") {
			p.Strictness = 3
			p.Description = "Australian ISM Official"
		} else if strings.Contains(shortLower, "anssi") || strings.Contains(idLower, "anssi") {
			p.Strictness = 3
			if strings.Contains(shortLower, "high") || strings.Contains(titleLower, "high") {
				p.Description = "ANSSI-BP-028 High (French security standard)"
			} else if strings.Contains(shortLower, "intermediary") {
				p.Description = "ANSSI-BP-028 Intermediary (French security standard)"
			} else {
				p.Description = "ANSSI-BP-028 Minimal (French security standard)"
			}
		} else if strings.Contains(shortLower, "ccn") || strings.Contains(titleLower, "ccn") || strings.Contains(titleLower, "centro") {
			p.Strictness = 3
			if strings.Contains(shortLower, "advanced") || strings.Contains(titleLower, "advanced") {
				p.Description = "CCN-STIC Advanced (Spanish security standard)"
			} else if strings.Contains(shortLower, "intermediate") {
				p.Description = "CCN-STIC Intermediate (Spanish security standard)"
			} else {
				p.Description = "CCN-STIC Basic (Spanish security standard)"
			}
		} else if strings.Contains(shortLower, "bsi") || strings.Contains(titleLower, "bsi") {
			p.Strictness = 3
			p.Description = "BSI SYS.1.1 and SYS.1.3 (German security standard)"
		} else if strings.Contains(titleLower, "level 1") || strings.Contains(shortLower, "cis_server_l1") || 
		           strings.Contains(shortLower, "cis_level1") || strings.Contains(shortLower, "cis_workstation_l1") {
			p.Strictness = 2
			if strings.Contains(titleLower, "workstation") {
				p.Description = "CIS Level 1 - Baseline for workstations"
			} else {
				p.Description = "CIS Level 1 - Practical baseline for production servers"
			}
		} else if strings.Contains(shortLower, "standard") || strings.Contains(idLower, "standard") {
			p.Strictness = 2
			p.Description = "Standard compliance baseline suitable for most systems"
		}
		
		// Set recommended based on OS and profile
		if strings.Contains(osLower, "rhel") || strings.Contains(osLower, "centos") ||
			strings.Contains(osLower, "rocky") || strings.Contains(osLower, "alma") {
			// RHEL family: Recommend CIS Server L1
			if strings.Contains(titleLower, "cis") && strings.Contains(titleLower, "level 1") && 
			   strings.Contains(titleLower, "server") {
				p.Recommended = true
			}
		} else if strings.Contains(osLower, "ubuntu") || strings.Contains(osLower, "debian") {
			// Ubuntu/Debian: Recommend CIS Level 1 Server or Standard
			if (strings.Contains(titleLower, "cis") && strings.Contains(titleLower, "level 1") && strings.Contains(titleLower, "server")) || 
			   (strings.Contains(shortLower, "standard") && !p.Recommended) {
				p.Recommended = true
			}
		} else if strings.Contains(osLower, "sles") || strings.Contains(osLower, "suse") {
			// SLES: Recommend CIS Server L1 or Standard
			if (strings.Contains(titleLower, "cis") && strings.Contains(titleLower, "level 1")) || 
			   (strings.Contains(shortLower, "standard") && !p.Recommended) {
				p.Recommended = true
			}
		}
	}
	
	// Sort: Recommended first, then by strictness (low to high), then alphabetically
	sortedProfiles := make([]ProfileInfo, len(profiles))
	copy(sortedProfiles, profiles)
	
	// Simple bubble sort
	for i := 0; i < len(sortedProfiles); i++ {
		for j := i + 1; j < len(sortedProfiles); j++ {
			swap := false
			
			// Recommended profiles first
			if !sortedProfiles[i].Recommended && sortedProfiles[j].Recommended {
				swap = true
			} else if sortedProfiles[i].Recommended == sortedProfiles[j].Recommended {
				// Same recommendation status, sort by strictness
				if sortedProfiles[i].Strictness > sortedProfiles[j].Strictness {
					swap = true
				} else if sortedProfiles[i].Strictness == sortedProfiles[j].Strictness {
					// Same strictness, sort alphabetically by title
					if sortedProfiles[i].Title > sortedProfiles[j].Title {
						swap = true
					}
				}
			}
			
			if swap {
				sortedProfiles[i], sortedProfiles[j] = sortedProfiles[j], sortedProfiles[i]
			}
		}
	}
	
	return sortedProfiles
}
