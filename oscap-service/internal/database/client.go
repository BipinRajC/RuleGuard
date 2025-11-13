package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// DB is the global database connection
var DB *sql.DB

// Connect initializes database connection pool to central admin node
func Connect(connStr string) error {
	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(5)
	DB.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection to central database
	if err = DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	return nil
}

// Close closes database connection
func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// RegisterNode registers this compute node with the central database
func RegisterNode(name, hostname, description, osType, nodeType string) (int, error) {
	var nodeID int
	err := DB.QueryRow(`
		SELECT register_node($1, $2, $3, $4, $5)`,
		name, hostname, description, osType, nodeType,
	).Scan(&nodeID)

	if err != nil {
		return 0, fmt.Errorf("failed to register node: %w", err)
	}

	return nodeID, nil
}

// UpdateNodeHeartbeat updates the last_heartbeat for this node
func UpdateNodeHeartbeat(nodeID int) error {
	_, err := DB.Exec(`
		UPDATE nodes 
		SET last_heartbeat = NOW() 
		WHERE id = $1`,
		nodeID,
	)
	return err
}

// GetNodeByHostname retrieves node information by hostname
func GetNodeByHostname(hostname string) (int, string, error) {
	var nodeID int
	var nodeName string
	err := DB.QueryRow(`
		SELECT id, name 
		FROM nodes 
		WHERE hostname = $1 AND is_active = true`,
		hostname,
	).Scan(&nodeID, &nodeName)

	if err != nil {
		return 0, "", err
	}

	return nodeID, nodeName, nil
}
