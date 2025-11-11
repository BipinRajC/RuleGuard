package main

import (
	"compliance-monitor/backend/config"
	"compliance-monitor/backend/db"
	"compliance-monitor/backend/handlers"
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	if err := db.Connect(cfg.DB.ConnectionString()); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("✓ Connected to PostgreSQL")

	// Setup routes
	http.HandleFunc("/add-node", corsMiddleware(handlers.AddNode))
	http.HandleFunc("/nodes", corsMiddleware(handlers.ListNodes))
	http.HandleFunc("/install-openscap", corsMiddleware(handlers.InstallOpenSCAP))
	http.HandleFunc("/scan/", corsMiddleware(handlers.GetScanStatus))
	http.HandleFunc("/scan", corsMiddleware(handlers.Scan))
	http.HandleFunc("/remediate", corsMiddleware(handlers.Remediate))
	http.HandleFunc("/results", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_id") != "" {
			handlers.GetResults(w, r)
		} else {
			handlers.GetAllResults(w, r)
		}
	}))

	// Health check endpoint
	http.HandleFunc("/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","service":"compliance-monitor"}`)
	}))

	// Start server
	addr := ":" + cfg.Server.Port
	log.Printf("🚀 Server starting on %s", addr)
	log.Println("\nAvailable endpoints:")
	log.Println("  POST   /add-node           - Add a new node")
	log.Println("  GET    /nodes              - List all nodes")
	log.Println("  POST   /install-openscap   - Install OpenSCAP on a node")
	log.Println("  POST   /scan               - Run compliance scan")
	log.Println("  GET    /scan/:id           - Get scan status")
	log.Println("  POST   /remediate          - Remediate failed rules")
	log.Println("  GET    /results            - Get all compliance results")
	log.Println("  GET    /results?node_id=X  - Get results for specific node")
	log.Println("  GET    /health             - Health check")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// corsMiddleware adds CORS headers for API access
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}
