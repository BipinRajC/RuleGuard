package config

import (
	"fmt"
	"os"
)

// Config holds the application configuration
type Config struct {
	DB       DBConfig
	Node     NodeConfig
	Local    LocalConfig
	Security SecurityConfig
	Schedule ScheduleConfig
}

// DBConfig contains database connection settings (central admin node)
type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// NodeConfig contains node identification
type NodeConfig struct {
	ID       int    // Set after registration
	Name     string // e.g., "compute-node-01"
	Hostname string // FQDN or IP
	NodeType string // "compute", "storage", etc.
}

// LocalConfig contains local paths
type LocalConfig struct {
	ReportsPath string // e.g., /home/user/openscap-reports
	LogPath     string // e.g., /var/log/oscap-service.log
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	RequireConfirmation bool // Always ask before remediation
	PrivilegeWarnings   bool // Show detailed privilege warnings
	AutoCheckpoint      bool // Create checkpoint before remediation
}

// ScheduleConfig contains scheduling settings
type ScheduleConfig struct {
	ScanInterval string // e.g., "3h"
	MaxRetries   int    // Max retry attempts for failed scans
}

// Load reads configuration from environment variables and config file
func Load() (*Config, error) {
	cfg := &Config{
		DB: DBConfig{
			Host:     getEnv("OSCAP_DB_HOST", "localhost"),
			Port:     getEnv("OSCAP_DB_PORT", "5432"),
			User:     getEnv("OSCAP_DB_USER", "oscap_node"),
			Password: getEnv("OSCAP_DB_PASSWORD", ""),
			DBName:   getEnv("OSCAP_DB_NAME", "oscap-service-db"),
			SSLMode:  getEnv("OSCAP_DB_SSLMODE", "require"),
		},
		Node: NodeConfig{
			Name:     getEnv("OSCAP_NODE_NAME", ""),
			Hostname: getEnv("OSCAP_NODE_HOSTNAME", ""),
			NodeType: getEnv("OSCAP_NODE_TYPE", "compute"),
		},
		Local: LocalConfig{
			ReportsPath: getEnv("OSCAP_REPORTS_PATH", fmt.Sprintf("/home/%s/openscap-reports", os.Getenv("USER"))),
			LogPath:     getEnv("OSCAP_LOG_PATH", "/var/log/oscap-service.log"),
		},
		Security: SecurityConfig{
			RequireConfirmation: getEnvBool("OSCAP_REQUIRE_CONFIRMATION", true),
			PrivilegeWarnings:   getEnvBool("OSCAP_PRIVILEGE_WARNINGS", true),
			AutoCheckpoint:      getEnvBool("OSCAP_AUTO_CHECKPOINT", true),
		},
		Schedule: ScheduleConfig{
			ScanInterval: getEnv("OSCAP_SCAN_INTERVAL", "3h"),
			MaxRetries:   getEnvInt("OSCAP_MAX_RETRIES", 3),
		},
	}

	// Validate required fields
	if cfg.DB.Password == "" {
		return nil, fmt.Errorf("OSCAP_DB_PASSWORD is required")
	}

	// Auto-detect hostname if not set
	if cfg.Node.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to detect hostname: %w", err)
		}
		cfg.Node.Hostname = hostname
	}

	// Auto-detect node name if not set
	if cfg.Node.Name == "" {
		cfg.Node.Name = cfg.Node.Hostname
	}

	return cfg, nil
}

// ConnectionString returns PostgreSQL connection string
func (c *DBConfig) ConnectionString() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode)
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}

func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	var result int
	fmt.Sscanf(value, "%d", &result)
	return result
}
