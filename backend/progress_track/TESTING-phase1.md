# Complete Testing Guide - Compliance Monitoring Backend

This document contains **all commands** to test the complete workflow from setup to remediation.

---

## Prerequisites

**Target Server Requirements:**
- Ubuntu 22.04 LTS x64
- SSH access (password or key)
- Sudo privileges
- Internet connection

**Local Machine:**
- PostgreSQL installed and running
- Fish shell (commands provided in fish syntax)

---

## Step 0: Initial Setup

### Create and Setup Database
```fish
# Create database (as postgres user)
sudo -u postgres createdb compliance

# Apply schema (as postgres user)
sudo -u postgres psql -d compliance -f compliance_schema.sql

# Verify tables were created
sudo -u postgres psql -d compliance -c "\dt"
# Should show: nodes, scans, scan_results, remediations, etc.
```

### Configure Environment
```fish
# Verify .env file exists with correct settings
cat .env
# Should show: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME=compliance, etc.

# Edit .env if needed
nano .env
```

### Build and Start the Server
```fish
# This script builds the binary, loads environment variables, and starts the server
./start.fish
```

**Expected Output:**
```
🔨 Building compliance-monitor...
✓ Build successful
✓ Environment variables loaded from .env
🚀 Starting compliance-monitor...

✓ Connected to PostgreSQL
🚀 Server starting on :8080

Available endpoints:
  POST   /add-node
  GET    /nodes
  ...
```

Keep this terminal running. Open a **new terminal** for testing.

---

## Step 1: Health Check

```fish
curl http://localhost:8080/health
```

**Expected Response:**
```json
{"status":"ok","service":"compliance-monitor"}
```

✅ **Verify:** Status is "ok"

---

## Step 2: Add Node

Replace with your actual Ubuntu 22.04 server credentials:

```fish
curl -X POST http://localhost:8080/add-node \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ubuntu-test-node",
    "hostname": "YOUR_SERVER_IP",
    "port": 22,
    "username": "YOUR_USERNAME",
    "auth_type": "password",
    "password": "YOUR_PASSWORD",
    "description": "Ubuntu 22.04 test server"
  }'
```

**Expected Response:**
```json
{
  "success": true,
  "message": "Node added successfully",
  "data": {
    "id": 1,
    "name": "ubuntu-test-node",
    "hostname": "YOUR_SERVER_IP",
    "port": 22,
    "username": "YOUR_USERNAME",
    "auth_type": "password",
    "description": "Ubuntu 22.04 test server",
    "os_type": "Ubuntu 22.04",
    "is_active": true,
    "created_at": "2025-11-11T..."
  }
}
```

✅ **Verify:** 
- `success: true`
- Node `id` is returned (use this ID for subsequent steps)
- SSH connection was tested successfully

### Verify in Database
```fish
sudo -u postgres psql -d compliance -c "SELECT id, name, hostname, os_type, is_active FROM nodes;"
```

**Expected:**
```
 id |       name        |    hostname     |    os_type    | is_active 
----+-------------------+-----------------+---------------+-----------
  1 | ubuntu-test-node  | YOUR_SERVER_IP  | Ubuntu 22.04  | t
```

✅ **Verify:** Node appears in database with correct details

---

## Step 3: List Nodes

```fish
curl http://localhost:8080/nodes
```

**Expected Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "ubuntu-test-node",
      "hostname": "YOUR_SERVER_IP",
      ...
    }
  ]
}
```

✅ **Verify:** Your node appears in the list

---

## Step 4: Install OpenSCAP

```fish
curl -X POST "http://localhost:8080/install-openscap?node_id=1"
```

**Takes:** 1-2 minutes

**Expected Response:**
```json
{
  "success": true,
  "message": "OpenSCAP installed successfully on ubuntu-test-node",
  "data": {
    "node_id": "1",
    "output": "INFO: Starting OpenSCAP installation\nINFO: Detected OS: Ubuntu 22.04 LTS...\nSUCCESS: OpenSCAP installed: OpenSCAP 1.3.6\nSUCCESS: SCAP content found: /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
  }
}
```

✅ **Verify:** 
- `success: true`
- Output shows "Ubuntu 22.04" detected
- Output shows "ssg-ubuntu2204-ds.xml" found

### Verify on Target Server (Optional)
```fish
ssh YOUR_USERNAME@YOUR_SERVER_IP "oscap --version"
ssh YOUR_USERNAME@YOUR_SERVER_IP "ls -l /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
```

---

## Step 5: Run Compliance Scan

```fish
curl -X POST "http://localhost:8080/scan?node_id=1"
```

**Takes:** 3-5 minutes

**Expected Response:**
```json
{
  "success": true,
  "message": "Scan completed on ubuntu-test-node",
  "data": {
    "scan_id": 1,
    "compliance_score": 75.23,
    "total_rules": 200,
    "passed_rules": 150,
    "failed_rules": 45,
    "error_rules": 5
  }
}
```

✅ **Verify:**
- `success: true`
- `scan_id` is returned (use for next steps)
- Compliance score is between 0-100
- Rule counts are reasonable

### Verify in Database
```fish
# Check scan record
sudo -u postgres psql -d compliance -c "SELECT id, node_id, status, compliance_score, passed_rules, failed_rules FROM scans;"

# Check node was updated with scan results
sudo -u postgres psql -d compliance -c "SELECT id, name, current_compliance_score, current_status, last_scan_at FROM nodes WHERE id=1;"

# Count failed rules stored
sudo -u postgres psql -d compliance -c "SELECT COUNT(*) as failed_count FROM scan_results WHERE scan_id=1 AND result='fail';"
```

**Expected:**
```
Scans table:
 id | node_id |  status   | compliance_score | passed_rules | failed_rules 
----+---------+-----------+------------------+--------------+--------------
  1 |       1 | completed |            75.23 |          150 |           45

Nodes table:
 id |       name       | current_compliance_score | current_status |     last_scan_at      
----+------------------+--------------------------+----------------+-----------------------
  1 | ubuntu-test-node |                    75.23 | warning        | 2025-11-11 12:00:00

Failed rules count:
 failed_count 
--------------
           45
```

✅ **Verify:** 
- Scan status is "completed"
- Node's `current_compliance_score` was updated
- Node's `current_status` is set (healthy/warning/critical)
- Failed rules are stored in `scan_results` table

---

## Step 6: Get Scan Status

```fish
curl "http://localhost:8080/scan/1"
```

**Expected Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "node_id": 1,
    "node_name": "ubuntu-test-node",
    "profile": "xccdf_org.ssgproject.content_profile_standard",
    "status": "completed",
    "started_at": "2025-11-11T12:00:00Z",
    "completed_at": "2025-11-11T12:05:30Z",
    "duration_seconds": 330,
    "compliance_score": 75.23,
    "total_rules": 200,
    "passed_rules": 150,
    "failed_rules": 45,
    "error_rules": 5
  }
}
```

✅ **Verify:** Status is "completed" and all details are present

---

## Step 7: Get Results with Failed Rules

```fish
curl "http://localhost:8080/results?node_id=1" | jq .
```

**Expected Response:**
```json
{
  "success": true,
  "data": {
    "node_id": 1,
    "name": "ubuntu-test-node",
    "hostname": "YOUR_SERVER_IP",
    "compliance_score": 75.23,
    "status": "warning",
    "last_scan_at": "2025-11-11T12:05:30Z",
    "latest_scan": {
      "scan_id": 1,
      "profile": "xccdf_org.ssgproject.content_profile_standard",
      "status": "completed",
      "compliance_score": 75.23,
      "total_rules": 200,
      "passed_rules": 150,
      "failed_rules": 45,
      "error_rules": 5
    },
    "failed_rules": [
      {
        "rule_id": "accounts_password_minlen_login_defs",
        "result": "fail"
      },
      {
        "rule_id": "package_aide_installed",
        "result": "fail"
      },
      ...
    ],
    "scan_history": [
      {
        "scan_id": 1,
        "status": "completed",
        "started_at": "2025-11-11T12:00:00Z",
        "compliance_score": 75.23,
        "failed_rules": 45,
        "total_rules": 200
      }
    ]
  }
}
```

✅ **Verify:**
- Lists all failed rules with rule IDs
- Shows scan history
- Compliance score matches

**Copy some failed rule IDs from the response for the next step!**

---

## Step 8: Remediate Failed Rules

Pick 2-3 rule IDs from the failed rules list above:

```fish
curl -X POST http://localhost:8080/remediate \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": 1,
    "rule_ids": [
      "accounts_password_minlen_login_defs",
      "package_aide_installed"
    ]
  }'
```

**Takes:** 1-3 minutes

**Expected Response:**
```json
{
  "success": true,
  "message": "Remediation completed: 2 fixed, 0 failed",
  "data": {
    "node_id": 1,
    "fixed": 2,
    "failed": 0,
    "results": [
      {
        "rule_id": "accounts_password_minlen_login_defs",
        "success": true,
        "message": "Remediation successful"
      },
      {
        "rule_id": "package_aide_installed",
        "success": true,
        "message": "Remediation successful"
      }
    ]
  }
}
```

✅ **Verify:**
- `success: true`
- At least some rules show `success: true`
- Fixed count > 0

### Verify in Database
```fish
sudo -u postgres psql -d compliance -c "SELECT id, node_id, rule_id, status, executed_at FROM remediations ORDER BY executed_at DESC LIMIT 5;"
```

**Expected:**
```
 id | node_id |               rule_id                | status  |     executed_at      
----+---------+--------------------------------------+---------+----------------------
  2 |       1 | package_aide_installed               | success | 2025-11-11 12:10:00
  1 |       1 | accounts_password_minlen_login_defs  | success | 2025-11-11 12:09:00
```

✅ **Verify:** Remediation records are stored

---

## Step 9: Rescan to Verify Fixes

```fish
curl -X POST "http://localhost:8080/scan?node_id=1"
```

**Takes:** 3-5 minutes

**Expected Response:**
```json
{
  "success": true,
  "message": "Scan completed on ubuntu-test-node",
  "data": {
    "scan_id": 2,
    "compliance_score": 78.50,
    "total_rules": 200,
    "passed_rules": 157,
    "failed_rules": 38,
    "error_rules": 5
  }
}
```

✅ **Verify:**
- `scan_id` is incremented (now 2)
- Compliance score **improved** (was 75.23, now 78.50)
- Failed rules **decreased** (was 45, now 38)

### Verify Score Improvement in Database
```fish
sudo -u postgres psql -d compliance -c "SELECT id, node_id, compliance_score, failed_rules, created_at FROM scans ORDER BY id;"
```

**Expected:**
```
 id | node_id | compliance_score | failed_rules |     created_at      
----+---------+------------------+--------------+---------------------
  1 |       1 |            75.23 |           45 | 2025-11-11 12:00:00
  2 |       1 |            78.50 |           38 | 2025-11-11 12:15:00
```

✅ **Verify:** Second scan shows improvement

---

## Step 10: Get All Results

```fish
curl "http://localhost:8080/results" | jq .
```

**Expected Response:**
```json
{
  "success": true,
  "data": [
    {
      "node_id": 1,
      "name": "ubuntu-test-node",
      "hostname": "YOUR_SERVER_IP",
      "compliance_score": 78.50,
      "status": "warning",
      "last_scan_at": "2025-11-11T12:20:00Z",
      "failed_rules": 38,
      "total_rules": 200
    }
  ]
}
```

✅ **Verify:** Shows updated compliance score from second scan

---

## Complete Database Verification

Run these queries to verify the complete workflow:

```fish
# Check all nodes
sudo -u postgres psql -d compliance -c "SELECT id, name, current_compliance_score, current_status FROM nodes;"

# Check all scans
sudo -u postgres psql -d compliance -c "SELECT id, node_id, status, compliance_score, failed_rules FROM scans ORDER BY id;"

# Check scan results count
sudo -u postgres psql -d compliance -c "SELECT scan_id, result, COUNT(*) FROM scan_results GROUP BY scan_id, result ORDER BY scan_id, result;"

# Check remediations
sudo -u postgres psql -d compliance -c "SELECT rule_id, status FROM remediations;"

# Check if triggers updated the node
sudo -u postgres psql -d compliance -c "SELECT id, name, last_scan_id, current_compliance_score, last_scan_at FROM nodes WHERE id=1;"
```

✅ **Verify:**
- Nodes table has updated compliance score
- Scans table has 2 completed scans
- Scan_results has entries for both scans
- Remediations table has your remediation attempts
- Node's `last_scan_id` points to the latest scan

---

## Error Testing

### Test Invalid Node ID
```fish
curl -X POST "http://localhost:8080/scan?node_id=999"
```

**Expected:**
```json
{"success":false,"error":"Node not found"}
```

### Test Missing Parameters
```fish
curl -X POST http://localhost:8080/add-node \
  -H "Content-Type: application/json" \
  -d '{"name":"incomplete"}'
```

**Expected:**
```json
{"success":false,"error":"name, hostname, and username are required"}
```

### Test Bad SSH Credentials
```fish
curl -X POST http://localhost:8080/add-node \
  -H "Content-Type: application/json" \
  -d '{
    "name": "bad-node",
    "hostname": "192.168.1.999",
    "username": "invalid",
    "auth_type": "password",
    "password": "wrong"
  }'
```

**Expected:**
```json
{"success":false,"error":"SSH connection failed: ..."}
```

---

## Summary Checklist

After completing all steps, verify:

- [ ] Backend server starts without errors
- [ ] Health endpoint returns OK
- [ ] Node can be added with SSH validation
- [ ] Node appears in database `nodes` table
- [ ] OpenSCAP installs successfully (detects Ubuntu 22.04)
- [ ] First scan completes and stores results
- [ ] Scan appears in `scans` table with status "completed"
- [ ] Failed rules stored in `scan_results` table
- [ ] Node's `current_compliance_score` updated by trigger
- [ ] Results endpoint returns scan data and failed rules
- [ ] Remediation executes and stores in `remediations` table
- [ ] Second scan shows improved compliance score
- [ ] Database triggers work correctly
- [ ] Error handling works (invalid IDs, bad credentials)

---

## Quick Reference Commands

```fish
# Start server (builds, loads env, and starts)
./start.fish

# Health check
curl http://localhost:8080/health

# Add node
curl -X POST http://localhost:8080/add-node -H "Content-Type: application/json" -d '{...}'

# Install OpenSCAP
curl -X POST "http://localhost:8080/install-openscap?node_id=1"

# Scan
curl -X POST "http://localhost:8080/scan?node_id=1"

# Results
curl "http://localhost:8080/results?node_id=1" | jq .

# Remediate
curl -X POST http://localhost:8080/remediate -H "Content-Type: application/json" -d '{...}'

# Check database
sudo -u postgres psql -d compliance -c "SELECT * FROM nodes;"
sudo -u postgres psql -d compliance -c "SELECT * FROM scans ORDER BY id;"
```

---

## Troubleshooting

**Backend won't start:**
- Check PostgreSQL is running: `systemctl status postgresql`
- Verify .env has DB_PASSWORD set
- Check port 8080 is not in use: `lsof -i :8080`

**SSH connection fails:**
- Test SSH manually: `ssh username@hostname`
- Verify firewall allows SSH (port 22)
- Check credentials are correct

**Installation fails:**
- Verify target is Ubuntu 22.04: `ssh user@host "cat /etc/os-release"`
- Check sudo works: `ssh user@host "sudo whoami"`
- Verify internet access: `ssh user@host "ping -c 2 google.com"`

**Scan fails:**
- Ensure OpenSCAP installed first
- Check SCAP content exists: `ssh user@host "ls /usr/share/xml/scap/ssg/content/"`
- Look at backend console for error messages

---

**Testing Complete!** 

After running all these steps, report any issues or unexpected behavior.
