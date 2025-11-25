# ScapRun - OpenSCAP Compliance Management Tool

A centralized TUI-based tool for managing OpenSCAP compliance scanning and remediation across HPC cluster nodes via SSH.

## Features

- 🔍 **Remote Scanning** - Run compliance scans on remote nodes via SSH
- 📋 **Dynamic Profile Selection** - Auto-detect available SCAP profiles from target systems
- 🔧 **Interactive Remediation** - Select and remediate failed rules with confirmation
- 💾 **Checkpoint System** - Automatic backups before remediation for safe rollback
- 🔄 **Rollback Support** - Restore system state from checkpoints
- 🗄️ **Central Database** - PostgreSQL storage for all scan results and remediations
- 🖥️ **TUI Interface** - Clean terminal UI for interactive operations

## Supported Operating Systems

| OS | Versions | Status |
|----|----------|--------|
| Ubuntu LTS | 18.04, 20.04, 22.04, 24.04 | ✅ Tested |
| RHEL/Rocky/AlmaLinux | 7, 8, 9 | ✅ Supported |
| CentOS Stream | 8, 9 | ⚠️ Limited (CPE mismatch) |
| SLES | 12, 15 | ✅ Supported |

## Quick Start

### 1. Database Setup (Admin Node)

```bash
# Create database
sudo -u postgres createdb oscap-service-db
sudo -u postgres psql -d oscap-service-db -f openscap-service.sql
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your database credentials
```

### 3. Build & Run

```bash
go build -o scaprun ./cmd/scaprun/
./scaprun
```

## Usage

```
═══════════════ MAIN MENU ═══════════════
🎯 Target: 192.168.1.100 (SSH)
📋 Profile: standard
─────────────────────────────────────────
1. Select Target (Local/SSH)
2. Select Compliance Profile
3. Install OpenSCAP on Target
4. Run Compliance Scan
5. View Status
6. Remediate Failed Rules
7. Rollback to Checkpoint
8. Download Reports
9. Exit
═════════════════════════════════════════
```

### Workflow

1. **Select Target** - Connect to remote node via SSH (password or key)
2. **Select Profile** - Choose from detected profiles (standard, CIS, STIG)
3. **Install OpenSCAP** - Auto-install on target if needed (skips if present)
4. **Run Scan** - Execute compliance scan and store results
5. **View Status** - See compliance score and rule breakdown
6. **Remediate** - Fix failed rules (creates checkpoint first)
7. **Rollback** - Restore from checkpoint if needed

## Project Structure

```
oscap-service/
├── cmd/scaprun/main.go      # TUI application entry point
├── internal/
│   ├── checkpoint/          # Checkpoint/rollback system
│   ├── config/              # Configuration management
│   ├── database/            # PostgreSQL client
│   ├── remediation/         # Remediation execution
│   └── scanner/             # Scan execution
├── pkg/
│   ├── models/              # Data structures
│   └── ssh/                 # SSH client wrapper
├── scripts/
│   ├── install_oscap.sh     # OpenSCAP installation
│   ├── scan.sh              # Scan execution
│   └── remediate.sh         # Remediation execution
└── openscap-service.sql     # Database schema
```

## Database Schema

- `nodes` - Registered compute nodes
- `scans` - Scan execution records
- `scan_results` - Individual rule results
- `checkpoints` - System state snapshots
- `checkpoint_files` - Backed up configuration files
- `remediations` - Remediation execution records
- `remediation_actions` - Individual rule remediation results

## Requirements

- Go 1.21+
- PostgreSQL 12+
- OpenSCAP 1.2+ (on target nodes)
- SSH access to target nodes

## License

MIT

## Author

Part of the RuleGuard project
