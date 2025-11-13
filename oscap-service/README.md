# OpenSCAP Security Hardening Service

A lightweight systemd service for automated OpenSCAP compliance scanning and remediation on HPC compute nodes.

## Features

- ✅ Automated compliance scanning every 3 hours
- ✅ Central PostgreSQL database for all nodes
- ✅ Interactive remediation with security prompts
- ✅ Checkpoint/rollback system for safe remediation
- ✅ Local report storage (HTML/PDF)
- ✅ CLI interface with Cobra

## Architecture

```
Admin Node (Central)
├── PostgreSQL Database (oscap-service-db)
└── Stores all scan results, checkpoints, remediations

Compute Nodes
├── oscap-service (this binary)
├── Scans locally with OpenSCAP
├── Reports to central database
└── Stores reports in ~/openscap-reports/
```

## Installation

### On Admin Node (One-time Setup)

1. **Create central database:**
```bash
sudo -u postgres createdb oscap-service-db
sudo -u postgres psql -d oscap-service-db -f openscap-service.sql
```

2. **Create database user:**
```bash
sudo -u postgres psql -d oscap-service-db << 'EOF'
CREATE USER oscap_node WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE "oscap-service-db" TO oscap_node;
GRANT ALL ON ALL TABLES IN SCHEMA public TO oscap_node;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO oscap_node;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO oscap_node;
EOF
```

3. **Configure PostgreSQL for remote connections:**
```bash
# Edit /etc/postgresql/*/main/postgresql.conf
listen_addresses = '*'

# Edit /etc/postgresql/*/main/pg_hba.conf
host    oscap-service-db    oscap_node    10.0.0.0/8    scram-sha-256

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### On Each Compute Node

1. **Copy the service:**
```bash
scp oscap-service compute-node:/usr/local/bin/
chmod +x /usr/local/bin/oscap-service
```

2. **Create configuration:**
```bash
cp .env.example /etc/oscap-service/.env
nano /etc/oscap-service/.env
# Set database connection details
```

3. **Install OpenSCAP (if not already installed):**
```bash
sudo bash scripts/install_oscap.sh
```

## Current Status (Phase 1)

### ✅ Implemented

- [x] Project structure created
- [x] Configuration management (env vars)
- [x] Database client (connects to central DB)
- [x] Node registration
- [x] Scanner module (local OpenSCAP execution)
- [x] Basic CLI commands (scan, status)
- [x] Models and data structures
- [x] Build system working

### 🚧 In Progress

- [ ] Systemd service file
- [ ] Systemd timer (3-hour interval)
- [ ] Interactive remediation UI
- [ ] Checkpoint creation
- [ ] Rollback functionality
- [ ] Report management
- [ ] Security privilege handling

## Usage

### Configure Environment

```bash
export OSCAP_DB_HOST=admin-node.hpc.lab
export OSCAP_DB_PORT=5432
export OSCAP_DB_USER=oscap_node
export OSCAP_DB_PASSWORD=your_password
export OSCAP_DB_NAME=oscap-service-db
export OSCAP_NODE_NAME=compute-01
```

### Run Scan

```bash
sudo oscap-service scan
```

Output:
```
🔍 Running compliance scan...
✓ Scan completed successfully
📊 Compliance Score: 73%
📈 Passed: 32 | Failed: 12 | Error: 0
📄 Report: /home/user/openscap-reports/scan_20251114_120000.html
```

### Check Status

```bash
oscap-service status
```

### Interactive Remediation (Coming Soon)

```bash
sudo oscap-service remediate
```

### Rollback to Checkpoint (Coming Soon)

```bash
sudo oscap-service rollback
```

## Development

### Build

```bash
go build -o oscap-service ./cmd/oscap-service
```

### Run Tests

```bash
go test ./...
```

### Project Structure

```
oscap-service/
├── cmd/oscap-service/          # CLI entry point
├── internal/
│   ├── config/                 # Configuration management
│   ├── database/               # DB client
│   ├── scanner/                # Scan execution
│   ├── remediation/            # Remediation logic (TODO)
│   ├── checkpoint/             # Checkpoint/rollback (TODO)
│   ├── reports/                # Report management (TODO)
│   └── scheduler/              # Auto-scan scheduler (TODO)
├── pkg/models/                 # Data structures
├── scripts/                    # OpenSCAP scripts
└── systemd/                    # Service files (TODO)
```

## Next Steps

1. Create systemd service + timer
2. Implement interactive remediation with Bubble Tea
3. Add checkpoint/rollback system
4. Build report management
5. Add security privilege handling
6. Create installation script
7. Full testing on HPC nodes

## License

MIT

## Author

Part of the RuleGuard project
