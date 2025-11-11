# Compliance Monitoring Backend

A lightweight, efficient Go backend for OpenSCAP compliance monitoring.

## Features

- **Node Management**: Add and manage target servers for compliance monitoring
- **Remote Installation**: Install OpenSCAP on remote servers via SSH
- **Compliance Scanning**: Execute OpenSCAP scans and store results
- **Remediation**: Apply fixes for failed compliance rules
- **Results API**: Query compliance scores and detailed scan results

## Project Structure

```
backend/
├── main.go              # HTTP server and routing
├── config/              # Configuration management
├── db/                  # PostgreSQL connection
├── models/              # Data structures
├── handlers/            # API handlers
│   ├── node.go         # Node management endpoints
│   ├── install.go      # OpenSCAP installation
│   ├── scan.go         # Compliance scanning
│   ├── remediate.go    # Rule remediation
│   └── results.go      # Results retrieval
├── ssh/                 # SSH client utilities
└── scripts/             # Shell scripts for OpenSCAP operations
```

## Setup

### Prerequisites

- Go 1.21+
- PostgreSQL 12+
- SSH access to target nodes

### 1. Install Dependencies

```bash
cd backend
go mod download
```

### 2. Database Setup

Create the database and apply the schema:

```bash
createdb compliance_monitor
psql -d compliance_monitor -f compliance_schema.sql
```

### 3. Configuration

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Edit `.env` with your database credentials:

```
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_NAME=compliance_monitor
DB_SSLMODE=disable

SERVER_PORT=8080
```

### 4. Run the Server

```bash
# Load environment variables
export $(cat .env | xargs)

# Start the server
go run main.go
```

The server will start on `http://localhost:8080`

## API Endpoints

### Health Check
```bash
curl http://localhost:8080/health
```

### Add a Node
```bash
curl -X POST http://localhost:8080/add-node \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-server",
    "hostname": "192.168.1.100",
    "port": 22,
    "username": "admin",
    "auth_type": "password",
    "password": "yourpassword",
    "description": "Test Ubuntu server"
  }'
```

### List Nodes
```bash
curl http://localhost:8080/nodes
```

### Install OpenSCAP
```bash
curl -X POST "http://localhost:8080/install-openscap?node_id=1"
```

### Run a Scan
```bash
curl -X POST "http://localhost:8080/scan?node_id=1"
```

### Get Scan Status
```bash
curl http://localhost:8080/scan/1
```

### Remediate Failed Rules
```bash
curl -X POST http://localhost:8080/remediate \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": 1,
    "rule_ids": ["accounts_password_minlen_login_defs", "package_aide_installed"]
  }'
```

### Get Results for a Node
```bash
curl "http://localhost:8080/results?node_id=1"
```

### Get All Results
```bash
curl http://localhost:8080/results
```

## Development

### Build for Production

```bash
go build -o compliance-monitor main.go
```

### Run with Custom Port

```bash
SERVER_PORT=9090 go run main.go
```

## Testing Flow

1. **Add a node**: Start by adding a target server
2. **Install OpenSCAP**: Install the scanning tools on the target
3. **Run a scan**: Execute a compliance scan
4. **View results**: Check compliance scores and failed rules
5. **Remediate**: Fix failed rules
6. **Rescan**: Run another scan to verify fixes

## Notes

- SSH credentials are stored in plaintext for simplicity. In production, encrypt the `credentials` column.
- The server uses `InsecureIgnoreHostKey()` for SSH. Implement proper host key verification for production.
- Scripts must be in the `scripts/` directory relative to where the binary runs.
- Database triggers automatically update node status after each scan.

## Next Steps

- [ ] Add authentication/authorization
- [ ] Implement credential encryption
- [ ] Add WebSocket support for real-time scan updates
- [ ] Implement scheduled scans
- [ ] Add more comprehensive error handling
- [ ] Create Docker deployment
