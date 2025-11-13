package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"oscap-service/internal/config"
	"oscap-service/internal/database"
	"oscap-service/internal/scanner"

	"github.com/spf13/cobra"
)

var (
	cfg    *config.Config
	nodeID int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "oscap-service",
		Short: "OpenSCAP Security Hardening Service",
		Long: `OpenSCAP Security Hardening Service - Automated compliance scanning and remediation
		
A systemd service for continuous security compliance monitoring using OpenSCAP.
Runs on compute nodes and reports to central admin database.`,
		PersistentPreRun: initConfig,
	}

	// Add commands
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(remediateCmd())
	rootCmd.AddCommand(rollbackCmd())
	rootCmd.AddCommand(reportsCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// initConfig initializes configuration and database connection
func initConfig(cmd *cobra.Command, args []string) {
	var err error
	
	// Load configuration
	cfg, err = config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to central database
	if err := database.Connect(cfg.DB.ConnectionString()); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Register or get node ID
	nodeID, err = database.RegisterNode(
		cfg.Node.Name,
		cfg.Node.Hostname,
		fmt.Sprintf("Compute node - %s", cfg.Node.NodeType),
		detectOS(),
		cfg.Node.NodeType,
	)
	if err != nil {
		// Try to get existing node
		nodeID, _, err = database.GetNodeByHostname(cfg.Node.Hostname)
		if err != nil {
			log.Fatalf("Failed to register/retrieve node: %v", err)
		}
	}

	// Update heartbeat
	if err := database.UpdateNodeHeartbeat(nodeID); err != nil {
		log.Printf("Warning: Failed to update heartbeat: %v", err)
	}
}

// scanCmd creates the scan command
func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Run compliance scan",
		Long:  "Execute OpenSCAP compliance scan on this node and report results to central database",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("🔍 Running compliance scan...")
			
			s := scanner.NewScanner(nodeID, cfg.Node.Name)
			scan, err := s.ExecuteScan(cfg.Local.ReportsPath)
			
			if err != nil {
				fmt.Printf("❌ Scan failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("✓ Scan completed successfully\n")
			fmt.Printf("📊 Compliance Score: %.0f%%\n", *scan.ComplianceScore)
			fmt.Printf("📈 Passed: %d | Failed: %d | Error: %d\n", 
				*scan.PassedRules, *scan.FailedRules, *scan.ErrorRules)
			
			if scan.ReportHTMLPath != nil {
				fmt.Printf("📄 Report: %s\n", *scan.ReportHTMLPath)
			}
		},
	}
}

// statusCmd creates the status command
func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show service status",
		Long:  "Display current compliance status and service information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("📊 OpenSCAP Service Status")
			fmt.Printf("Node: %s (%s)\n", cfg.Node.Name, cfg.Node.Hostname)
			fmt.Printf("Node ID: %d\n", nodeID)
			fmt.Printf("Database: %s@%s:%s/%s\n", 
				cfg.DB.User, cfg.DB.Host, cfg.DB.Port, cfg.DB.DBName)
			
			// Get latest scan info from database
			var score *float64
			var status string
			var lastScan *string
			
			err := database.DB.QueryRow(`
				SELECT current_compliance_score, current_status, 
				       to_char(last_scan_at, 'YYYY-MM-DD HH24:MI:SS')
				FROM nodes WHERE id = $1`, nodeID,
			).Scan(&score, &status, &lastScan)
			
			if err == nil {
				if score != nil {
					fmt.Printf("Compliance Score: %.0f%%\n", *score)
				}
				fmt.Printf("Status: %s\n", status)
				if lastScan != nil {
					fmt.Printf("Last Scan: %s\n", *lastScan)
				}
			}
		},
	}
}

// remediateCmd creates the remediate command
func remediateCmd() *cobra.Command {
	var remediateAll bool
	
	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Interactive remediation menu",
		Long:  "Launch interactive menu to select and remediate failed compliance rules",
		Run: func(cmd *cobra.Command, args []string) {
			if remediateAll {
				fmt.Println("🔧 Remediating all failed rules...")
				// TODO: Implement remediate all
				fmt.Println("⚠️  Not yet implemented")
			} else {
				fmt.Println("🔧 Interactive remediation menu")
				// TODO: Implement interactive menu
				fmt.Println("⚠️  Not yet implemented")
			}
		},
	}
	
	cmd.Flags().BoolVarP(&remediateAll, "all", "a", false, "Remediate all failed rules without confirmation")
	
	return cmd
}

// rollbackCmd creates the rollback command
func rollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rollback",
		Short: "Restore system to previous checkpoint",
		Long:  "List available checkpoints and restore system to a previous state",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("🔄 Available checkpoints")
			// TODO: Implement rollback
			fmt.Println("⚠️  Not yet implemented")
		},
	}
}

// reportsCmd creates the reports command
func reportsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reports",
		Short: "Manage scan reports",
		Long:  "List, view, and export compliance scan reports",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("📄 Recent reports")
			// TODO: Implement reports management
			fmt.Println("⚠️  Not yet implemented")
		},
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
