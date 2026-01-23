# HPE ScapRun - OpenSCAP Compliance Framework

Enterprise-grade TUI tool for OpenSCAP compliance scanning, remediation, and rollback across Linux nodes.

## Quick Setup

### Prerequisites
- Go 1.21+
- PostgreSQL 14+
- Linux (Ubuntu 20.04+ / RHEL 8+)

### 1. Database Setup

```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib   # Ubuntu/Debian
sudo dnf install postgresql-server postgresql   # RHEL/Rocky

# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE USER scaprun WITH PASSWORD 'your_secure_password';
CREATE DATABASE scaprundb OWNER scaprun;
GRANT ALL PRIVILEGES ON DATABASE scaprundb TO scaprun;
EOF

# Import schema
sudo -u postgres psql -d scaprundb -f openscap-service.sql
```

### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

**.env file:**
```env
OSCAP_DB_HOST=localhost
OSCAP_DB_PORT=5432
OSCAP_DB_USER=<user>
OSCAP_DB_PASSWORD=<password>
OSCAP_DB_NAME=<db-name>
OSCAP_DB_SSLMODE=require

# Node Configuration
OSCAP_NODE_NAME=compute-node-01
OSCAP_NODE_HOSTNAME=node01.hpc.lab
OSCAP_NODE_TYPE=compute

# Local Paths
OSCAP_REPORTS_PATH=/home/<user>/openscap-reports
OSCAP_LOG_PATH=/var/log/oscap-service.log

# Security Settings
OSCAP_REQUIRE_CONFIRMATION=true
OSCAP_PRIVILEGE_WARNINGS=true
OSCAP_AUTO_CHECKPOINT=true

# Scheduling
OSCAP_SCAN_INTERVAL=3h
OSCAP_MAX_RETRIES=3
```

### 3. Build & Run

```bash
# From oscap-service directory
go build -o scaprun ./cmd/scaprun
./scaprun
```

> **Note:** You must specify `./cmd/scaprun` path - running `go build` alone won't work.

---

## Usage

```
┌──────────────────────────────────────────────────────────┐
│                   TARGET MANAGEMENT                       │
├──────────────────────────────────────────────────────────┤
│  [1] target       - Select Target Node                   │
│  [2] install      - Install OpenSCAP on Target           │
└──────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────┐
│                 COMPLIANCE OPERATIONS                     │
├──────────────────────────────────────────────────────────┤
│  [3] profile      - Select Compliance Profile            │
│  [4] scan         - Run Compliance Scan                  │
│  [5] status       - View Current Status                  │
└──────────────────────────────────────────────────────────┘
```

### Workflow
1. `target` → Select local or remote node (SSH)
2. `install` → Auto-install OpenSCAP on target
3. `profile` → Choose compliance profile (CIS, STIG, etc.)
4. `scan` → Run compliance scan
5. `remediate` → Fix failed rules (creates checkpoint)
6. `rollback` → Restore from checkpoint if needed

---

## Optional: pgAdmin4 Setup

```bash
# Install pgAdmin4
curl -fsS https://www.pgadmin.org/static/packages_pgadmin_org.pub | sudo gpg --dearmor -o /usr/share/keyrings/pgadmin.gpg
echo "deb [signed-by=/usr/share/keyrings/pgadmin.gpg] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/$(lsb_release -cs) pgadmin4 main" | sudo tee /etc/apt/sources.list.d/pgadmin4.list
sudo apt update && sudo apt install pgadmin4-web

# Configure
sudo /usr/pgadmin4/bin/setup-web.sh
```

Access at: `http://localhost/pgadmin4`

---

## Supported Systems

| OS | Versions |
|----|----------|
| Ubuntu | 20.04, 22.04, 24.04 |
| RHEL/Rocky/Alma | 8, 9, 10 |
| SLES | 15 |

---

## Project Structure

```
oscap-service/
├── cmd/scaprun/         # Main TUI application
│   ├── main.go
│   └── style.go         # HPE themed styling
├── internal/
│   ├── checkpoint/      # Backup & rollback
│   ├── database/        # PostgreSQL client
│   ├── remediation/     # Auto-fix logic
│   └── scanner/         # Scan execution
├── scripts/             # Shell scripts for nodes
├── openscap-service.sql # Database schema
└── .env.example         # Environment template
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `no Go files` | Run from `oscap-service/` dir with `./cmd/scaprun` |
| DB connection failed | Check `.env` credentials and PostgreSQL status |
| SSH connection failed | Verify SSH key/password and target accessibility |
| No profiles found | Run `install` first to install OpenSCAP on target |

---

## License
MIT
