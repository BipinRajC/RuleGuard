-- OpenSCAP Security Hardening Service - Central Database Schema
-- PostgreSQL 12+
-- 
-- Architecture: Central database on admin node, services on each compute node
-- Purpose: Track compliance, store scan history, enable checkpoint/rollback

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Table: nodes
-- Represents each compute node running the openscap-service
CREATE TABLE nodes (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL UNIQUE, -- Unique identifier for the node
    ip_address VARCHAR(45),                 -- IPv4 or IPv6
    os_type VARCHAR(50),                    -- 'rhel-8', 'ubuntu-22.04', etc.
    os_version VARCHAR(50),                 -- Full OS version string
    
    -- Service configuration
    scan_profile VARCHAR(255) DEFAULT 'xccdf_org.ssgproject.content_profile_cis',
    scan_interval_minutes INTEGER DEFAULT 180, -- 3 hours
    
    -- Current state (denormalized for quick CLI queries)
    last_scan_id INTEGER,
    current_compliance_score DECIMAL(5,2),
    current_status VARCHAR(50) DEFAULT 'unknown', -- 'healthy', 'warning', 'critical', 'unknown'
    last_scan_at TIMESTAMP,
    
    -- Service metadata
    service_version VARCHAR(20),            -- Version of openscap-service installed
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: scans
-- Each compliance scan execution
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,         -- Denormalized for easier queries
    profile VARCHAR(255) NOT NULL,
    
    -- Scan execution
    status VARCHAR(50) NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    
    -- Summary statistics
    compliance_score DECIMAL(5,2),
    total_rules INTEGER,
    passed_rules INTEGER,
    failed_rules INTEGER,
    error_rules INTEGER,
    notapplicable_rules INTEGER,
    
    -- Severity breakdown
    critical_failures INTEGER DEFAULT 0,
    high_failures INTEGER DEFAULT 0,
    medium_failures INTEGER DEFAULT 0,
    low_failures INTEGER DEFAULT 0,
    
    -- Report storage
    report_html_path TEXT,                  -- Local path on node: /home/user/openscap-reports/scan_123.html
    report_pdf_path TEXT,                   -- Local path on node: /home/user/openscap-reports/scan_123.pdf
    report_xml_path TEXT,                   -- Local path on node: /home/user/openscap-reports/scan_123.xml
    
    error_message TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: rules_baseline
-- Static rule definitions (OpenSCAP rule metadata)
CREATE TABLE rules_baseline (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    rationale TEXT,
    severity VARCHAR(20) CHECK (severity IN ('unknown', 'info', 'low', 'medium', 'high', 'critical')),
    
    -- Remediation information
    remediation TEXT,
    remediation_complexity VARCHAR(20),     -- 'low', 'medium', 'high'
    can_auto_remediate BOOLEAN DEFAULT false,
    requires_reboot BOOLEAN DEFAULT false,
    requires_sudo BOOLEAN DEFAULT true,     -- Most remediations need sudo
    
    -- Affected files (for checkpoint creation)
    affected_files TEXT[],                  -- Array of file paths that this rule modifies
    affected_packages TEXT[],               -- Array of packages affected
    affected_services TEXT[],               -- Array of services affected
    
    -- Identifiers
    identifiers JSONB,                      -- {"cce": "CCE-80222-5", "cis": "5.2.13"}
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: scan_results
-- Individual rule results for each scan
CREATE TABLE scan_results (
    id BIGSERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    
    -- Result
    result VARCHAR(20) NOT NULL CHECK (result IN (
        'pass', 'fail', 'error', 'notapplicable', 
        'notchecked', 'notselected', 'informational', 'fixed'
    )),
    
    -- Optional details
    check_output TEXT,                      -- Only for failures
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT idx_unique_scan_result UNIQUE (scan_id, rule_id)
);

-- Table: compliance_changes
-- Track when rules change status (for historical analysis)
CREATE TABLE compliance_changes (
    id BIGSERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    
    previous_result VARCHAR(20),
    current_result VARCHAR(20) NOT NULL,
    
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity VARCHAR(20),
    
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- CHECKPOINT & ROLLBACK TABLES
-- ============================================================================

-- Table: checkpoints
-- Snapshots of system state before remediations
CREATE TABLE checkpoints (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    
    -- Checkpoint metadata
    name VARCHAR(255) NOT NULL,             -- User-friendly name or auto-generated
    description TEXT,
    checkpoint_type VARCHAR(50) NOT NULL CHECK (checkpoint_type IN ('auto', 'manual')),
    
    -- System state at checkpoint
    compliance_score DECIMAL(5,2),
    total_failures INTEGER,
    critical_failures INTEGER,
    high_failures INTEGER,
    
    -- What was backed up
    files_count INTEGER DEFAULT 0,
    packages_count INTEGER DEFAULT 0,
    services_count INTEGER DEFAULT 0,
    
    -- Status
    is_active BOOLEAN DEFAULT true,
    
    created_by VARCHAR(100) DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT idx_unique_checkpoint_name UNIQUE (node_id, name)
);

-- Table: checkpoint_files
-- File backups before remediation
CREATE TABLE checkpoint_files (
    id BIGSERIAL PRIMARY KEY,
    checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
    
    file_path TEXT NOT NULL,
    file_content TEXT NOT NULL,             -- Full file content (base64 for binary)
    file_permissions VARCHAR(10),           -- e.g., '0644'
    file_owner VARCHAR(100),                -- e.g., 'root:root'
    file_size INTEGER,
    file_hash VARCHAR(64),                  -- SHA-256 for integrity
    is_binary BOOLEAN DEFAULT false,
    
    backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT idx_unique_checkpoint_file UNIQUE (checkpoint_id, file_path)
);

-- Table: checkpoint_packages
-- Package state snapshots
CREATE TABLE checkpoint_packages (
    id SERIAL PRIMARY KEY,
    checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
    
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100),
    package_state VARCHAR(20) NOT NULL CHECK (package_state IN ('installed', 'not_installed')),
    package_manager VARCHAR(20),            -- 'yum', 'dnf', 'apt', etc.
    
    backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT idx_unique_checkpoint_package UNIQUE (checkpoint_id, package_name)
);

-- Table: checkpoint_services
-- Service state snapshots
CREATE TABLE checkpoint_services (
    id SERIAL PRIMARY KEY,
    checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
    
    service_name VARCHAR(255) NOT NULL,
    service_enabled BOOLEAN,
    service_running BOOLEAN,
    service_manager VARCHAR(20) DEFAULT 'systemd',
    
    backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT idx_unique_checkpoint_service UNIQUE (checkpoint_id, service_name)
);

-- ============================================================================
-- REMEDIATION TABLES
-- ============================================================================

-- Table: remediations
-- Track remediation attempts
CREATE TABLE remediations (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    checkpoint_id INTEGER REFERENCES checkpoints(id) ON DELETE SET NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    
    -- What was remediated
    rules_remediated TEXT[],                -- Array of rule_ids
    rules_count INTEGER DEFAULT 0,
    
    method VARCHAR(50) NOT NULL CHECK (method IN ('openscap_auto', 'manual')),
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'partial', 'failed')),
    
    -- Results
    successful_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    
    execution_output TEXT,
    error_message TEXT,
    
    executed_by VARCHAR(100) DEFAULT 'interactive-user',
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: remediation_actions
-- Detailed log of each remediation action
CREATE TABLE remediation_actions (
    id BIGSERIAL PRIMARY KEY,
    remediation_id INTEGER NOT NULL REFERENCES remediations(id) ON DELETE CASCADE,
    checkpoint_id INTEGER REFERENCES checkpoints(id) ON DELETE SET NULL,
    
    rule_id VARCHAR(255) NOT NULL,
    rule_title TEXT,
    
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN (
        'file_modify', 'file_create', 'file_delete',
        'package_install', 'package_remove',
        'service_start', 'service_stop', 'service_enable', 'service_disable',
        'command_execute', 'permission_change', 'ownership_change'
    )),
    
    target_path TEXT,                       -- File/package/service affected
    
    status VARCHAR(50) NOT NULL CHECK (status IN ('success', 'failed', 'skipped')),
    output TEXT,
    error_message TEXT,
    
    execution_order INTEGER,                -- For ordered rollback
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: restore_operations
-- Track checkpoint restore/rollback operations
CREATE TABLE restore_operations (
    id SERIAL PRIMARY KEY,
    checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    
    restore_type VARCHAR(50) NOT NULL CHECK (restore_type IN ('full', 'partial', 'selective')),
    items_to_restore JSONB,                 -- For partial restores
    
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'partial')),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    
    items_restored INTEGER DEFAULT 0,
    items_failed INTEGER DEFAULT 0,
    error_log TEXT,
    
    initiated_by VARCHAR(100) NOT NULL,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Nodes indexes
CREATE INDEX idx_nodes_hostname ON nodes(hostname);
CREATE INDEX idx_nodes_active ON nodes(is_active) WHERE is_active = true;
CREATE INDEX idx_nodes_last_scan ON nodes(last_scan_at DESC);
CREATE INDEX idx_nodes_status ON nodes(current_status);

-- Scans indexes
CREATE INDEX idx_scans_node ON scans(node_id, created_at DESC);
CREATE INDEX idx_scans_hostname ON scans(hostname, created_at DESC);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_completed ON scans(completed_at DESC) WHERE status = 'completed';

-- Scan results indexes
CREATE INDEX idx_scan_results_scan ON scan_results(scan_id);
CREATE INDEX idx_scan_results_node ON scan_results(node_id);
CREATE INDEX idx_scan_results_rule ON scan_results(rule_id);
CREATE INDEX idx_scan_results_failed ON scan_results(result) WHERE result IN ('fail', 'error');

-- Rules baseline indexes
CREATE INDEX idx_rules_baseline_severity ON rules_baseline(severity);
CREATE INDEX idx_rules_baseline_rule_id ON rules_baseline(rule_id);
CREATE INDEX idx_rules_baseline_auto_remediate ON rules_baseline(can_auto_remediate) WHERE can_auto_remediate = true;

-- Compliance changes indexes
CREATE INDEX idx_changes_node ON compliance_changes(node_id, detected_at DESC);
CREATE INDEX idx_changes_detected ON compliance_changes(detected_at DESC);

-- Checkpoints indexes
CREATE INDEX idx_checkpoints_node ON checkpoints(node_id, created_at DESC);
CREATE INDEX idx_checkpoints_active ON checkpoints(node_id, is_active) WHERE is_active = true;

-- Checkpoint files indexes
CREATE INDEX idx_checkpoint_files_checkpoint ON checkpoint_files(checkpoint_id);

-- Remediations indexes
CREATE INDEX idx_remediations_node ON remediations(node_id, created_at DESC);
CREATE INDEX idx_remediations_checkpoint ON remediations(checkpoint_id);
CREATE INDEX idx_remediations_status ON remediations(status);

-- Remediation actions indexes
CREATE INDEX idx_remediation_actions_remediation ON remediation_actions(remediation_id);
CREATE INDEX idx_remediation_actions_rule ON remediation_actions(rule_id);

-- Restore operations indexes
CREATE INDEX idx_restore_operations_checkpoint ON restore_operations(checkpoint_id);
CREATE INDEX idx_restore_operations_node ON restore_operations(node_id, created_at DESC);

-- ============================================================================
-- TRIGGERS AND FUNCTIONS
-- ============================================================================

-- Function: Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER trigger_nodes_updated_at 
    BEFORE UPDATE ON nodes
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_rules_updated_at 
    BEFORE UPDATE ON rules_baseline
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Function: Update node state after scan completes
CREATE OR REPLACE FUNCTION update_node_state()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND (OLD.status IS NULL OR OLD.status != 'completed') THEN
        UPDATE nodes SET
            last_scan_id = NEW.id,
            current_compliance_score = NEW.compliance_score,
            current_status = CASE
                WHEN NEW.critical_failures > 0 THEN 'critical'
                WHEN NEW.high_failures > 5 THEN 'warning'
                WHEN NEW.compliance_score < 70 THEN 'warning'
                ELSE 'healthy'
            END,
            last_scan_at = NEW.completed_at,
            last_heartbeat = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.node_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_node_state
    AFTER INSERT OR UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_node_state();

-- Function: Detect compliance changes
CREATE OR REPLACE FUNCTION detect_compliance_changes()
RETURNS TRIGGER AS $$
DECLARE
    prev_result VARCHAR(20);
    rule_severity VARCHAR(20);
    node_hostname VARCHAR(255);
BEGIN
    -- Get node hostname
    SELECT hostname INTO node_hostname
    FROM nodes
    WHERE id = NEW.node_id;
    
    -- Get previous result for this node+rule
    SELECT sr.result INTO prev_result
    FROM scan_results sr
    WHERE sr.node_id = NEW.node_id
        AND sr.rule_id = NEW.rule_id
        AND sr.scan_id != NEW.scan_id
    ORDER BY sr.created_at DESC
    LIMIT 1;
    
    -- If result changed, log it
    IF prev_result IS NOT NULL AND prev_result != NEW.result THEN
        -- Get rule severity
        SELECT severity INTO rule_severity
        FROM rules_baseline
        WHERE rule_id = NEW.rule_id;
        
        INSERT INTO compliance_changes (
            node_id, hostname, rule_id, previous_result, 
            current_result, scan_id, severity, detected_at
        ) VALUES (
            NEW.node_id, node_hostname, NEW.rule_id, prev_result,
            NEW.result, NEW.scan_id, rule_severity, CURRENT_TIMESTAMP
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_detect_changes
    AFTER INSERT ON scan_results
    FOR EACH ROW
    EXECUTE FUNCTION detect_compliance_changes();

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Function: Register or update node (called by service on startup)
CREATE OR REPLACE FUNCTION register_node(
    p_hostname VARCHAR(255),
    p_ip_address VARCHAR(45),
    p_os_type VARCHAR(50),
    p_os_version VARCHAR(50),
    p_service_version VARCHAR(20)
) RETURNS INTEGER AS $$
DECLARE
    v_node_id INTEGER;
BEGIN
    INSERT INTO nodes (hostname, ip_address, os_type, os_version, service_version, last_heartbeat)
    VALUES (p_hostname, p_ip_address, p_os_type, p_os_version, p_service_version, CURRENT_TIMESTAMP)
    ON CONFLICT (hostname) DO UPDATE SET
        ip_address = EXCLUDED.ip_address,
        os_type = EXCLUDED.os_type,
        os_version = EXCLUDED.os_version,
        service_version = EXCLUDED.service_version,
        last_heartbeat = CURRENT_TIMESTAMP,
        is_active = true
    RETURNING id INTO v_node_id;
    
    RETURN v_node_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Create automatic checkpoint before remediation
CREATE OR REPLACE FUNCTION create_auto_checkpoint(
    p_node_id INTEGER,
    p_scan_id INTEGER,
    p_description TEXT DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_checkpoint_id INTEGER;
    v_checkpoint_name VARCHAR(255);
    v_compliance_score DECIMAL(5,2);
    v_hostname VARCHAR(255);
BEGIN
    -- Get node info
    SELECT hostname, current_compliance_score INTO v_hostname, v_compliance_score
    FROM nodes WHERE id = p_node_id;
    
    -- Generate checkpoint name
    v_checkpoint_name := 'auto_' || TO_CHAR(NOW(), 'YYYYMMDD_HH24MISS');
    
    -- Create checkpoint
    INSERT INTO checkpoints (
        node_id, hostname, scan_id, name, checkpoint_type,
        compliance_score, description, created_by
    ) VALUES (
        p_node_id, v_hostname, p_scan_id, v_checkpoint_name, 'auto',
        v_compliance_score, 
        COALESCE(p_description, 'Auto-checkpoint before remediation'),
        'system'
    ) RETURNING id INTO v_checkpoint_id;
    
    RETURN v_checkpoint_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Get restore commands for a checkpoint
CREATE OR REPLACE FUNCTION get_restore_commands(p_checkpoint_id INTEGER)
RETURNS TABLE(
    command_order INTEGER,
    command_type VARCHAR(50),
    restore_command TEXT,
    target_path TEXT
) AS $$
BEGIN
    RETURN QUERY
    -- File restorations
    SELECT 
        1 as command_order,
        'file_restore'::VARCHAR(50),
        'echo "' || REPLACE(cf.file_content, '"', '\"') || '" > ' || cf.file_path || 
        ' && chmod ' || cf.file_permissions || ' ' || cf.file_path ||
        ' && chown ' || cf.file_owner || ' ' || cf.file_path as restore_command,
        cf.file_path as target_path
    FROM checkpoint_files cf
    WHERE cf.checkpoint_id = p_checkpoint_id
    
    UNION ALL
    
    -- Package restorations
    SELECT 
        2 as command_order,
        'package_restore'::VARCHAR(50),
        CASE 
            WHEN cp.package_state = 'installed' THEN 
                cp.package_manager || ' install -y ' || cp.package_name || 
                CASE WHEN cp.package_version IS NOT NULL 
                     THEN '-' || cp.package_version 
                     ELSE '' END
            ELSE 
                cp.package_manager || ' remove -y ' || cp.package_name
        END as restore_command,
        cp.package_name as target_path
    FROM checkpoint_packages cp
    WHERE cp.checkpoint_id = p_checkpoint_id
    
    UNION ALL
    
    -- Service restorations
    SELECT 
        3 as command_order,
        'service_restore'::VARCHAR(50),
        'systemctl ' || 
        CASE WHEN cs.service_enabled THEN 'enable' ELSE 'disable' END || ' ' || cs.service_name ||
        ' && systemctl ' ||
        CASE WHEN cs.service_running THEN 'start' ELSE 'stop' END || ' ' || cs.service_name as restore_command,
        cs.service_name as target_path
    FROM checkpoint_services cs
    WHERE cs.checkpoint_id = p_checkpoint_id
    
    ORDER BY command_order, target_path;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- VIEWS FOR CLI QUERIES
-- ============================================================================

-- View: Node summary (for "openscap-service status" command)
CREATE VIEW v_node_summary AS
SELECT
    n.id,
    n.hostname,
    n.os_type,
    n.current_compliance_score,
    n.current_status,
    n.last_scan_at,
    n.scan_interval_minutes,
    s.critical_failures,
    s.high_failures,
    s.medium_failures,
    s.low_failures,
    s.total_rules,
    s.failed_rules,
    s.duration_seconds as last_scan_duration,
    -- Next scan estimate
    n.last_scan_at + (n.scan_interval_minutes || ' minutes')::INTERVAL as next_scan_at
FROM nodes n
LEFT JOIN scans s ON n.last_scan_id = s.id
WHERE n.is_active = true;

-- View: Failed rules for a node (for remediation menu)
CREATE VIEW v_node_failed_rules AS
SELECT
    n.hostname,
    sr.node_id,
    sr.scan_id,
    sr.rule_id,
    rb.title,
    rb.severity,
    rb.description,
    rb.rationale,
    rb.remediation,
    rb.can_auto_remediate,
    rb.requires_reboot,
    rb.requires_sudo,
    rb.remediation_complexity,
    sr.result,
    sr.check_output
FROM scan_results sr
JOIN nodes n ON sr.node_id = n.id AND n.last_scan_id = sr.scan_id
JOIN rules_baseline rb ON sr.rule_id = rb.rule_id
WHERE sr.result IN ('fail', 'error')
ORDER BY 
    CASE rb.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    rb.title;

-- View: Available checkpoints for rollback
CREATE VIEW v_available_checkpoints AS
SELECT
    c.id,
    c.node_id,
    c.hostname,
    c.name,
    c.description,
    c.checkpoint_type,
    c.compliance_score,
    c.critical_failures,
    c.high_failures,
    c.created_at,
    c.files_count,
    c.packages_count,
    c.services_count,
    -- Check if already restored
    EXISTS(
        SELECT 1 FROM restore_operations 
        WHERE checkpoint_id = c.id AND status = 'completed'
    ) as has_been_restored,
    -- Most recent restore
    (SELECT completed_at FROM restore_operations 
     WHERE checkpoint_id = c.id AND status = 'completed'
     ORDER BY completed_at DESC LIMIT 1) as last_restore_at
FROM checkpoints c
WHERE c.is_active = true
ORDER BY c.created_at DESC;

-- View: Remediation history
CREATE VIEW v_remediation_history AS
SELECT
    r.id,
    r.hostname,
    r.rules_count,
    r.successful_count,
    r.failed_count,
    r.status,
    r.executed_by,
    r.executed_at,
    c.name as checkpoint_name,
    s.compliance_score as scan_score_before
FROM remediations r
LEFT JOIN checkpoints c ON r.checkpoint_id = c.id
LEFT JOIN scans s ON r.scan_id = s.id
ORDER BY r.executed_at DESC;

-- ============================================================================
-- CLEANUP & MAINTENANCE
-- ============================================================================

-- Function: Cleanup old data (run periodically)
CREATE OR REPLACE FUNCTION cleanup_old_data(
    p_scans_retention_days INTEGER DEFAULT 180,
    p_changes_retention_days INTEGER DEFAULT 90,
    p_checkpoints_retention_days INTEGER DEFAULT 365
) RETURNS void AS $$
BEGIN
    -- Delete old compliance changes
    DELETE FROM compliance_changes
    WHERE detected_at < CURRENT_TIMESTAMP - (p_changes_retention_days || ' days')::INTERVAL;
    
    -- Mark old checkpoints as inactive (don't delete, for audit)
    UPDATE checkpoints
    SET is_active = false
    WHERE created_at < CURRENT_TIMESTAMP - (p_checkpoints_retention_days || ' days')::INTERVAL
        AND is_active = true;
    
    -- Archive old scans (consider exporting before deletion)
    DELETE FROM scans
    WHERE created_at < CURRENT_TIMESTAMP - (p_scans_retention_days || ' days')::INTERVAL;
    
    -- Vacuum to reclaim space
    VACUUM ANALYZE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS (Documentation)
-- ============================================================================

COMMENT ON TABLE nodes IS 'Compute nodes running openscap-service';
COMMENT ON TABLE scans IS 'Compliance scan execution history';
COMMENT ON TABLE rules_baseline IS 'OpenSCAP rule definitions and metadata';
COMMENT ON TABLE scan_results IS 'Individual rule results per scan';
COMMENT ON TABLE checkpoints IS 'System state snapshots before remediations';
COMMENT ON TABLE checkpoint_files IS 'File backups for rollback capability';
COMMENT ON TABLE remediations IS 'Remediation execution tracking';
COMMENT ON TABLE restore_operations IS 'Checkpoint restore/rollback history';

COMMENT ON COLUMN nodes.hostname IS 'Unique identifier for the node (from hostname command)';
COMMENT ON COLUMN nodes.last_heartbeat IS 'Updated every scan to detect inactive nodes';
COMMENT ON COLUMN scans.report_html_path IS 'Local path on node, e.g., /home/user/openscap-reports/scan_123.html';
COMMENT ON COLUMN rules_baseline.affected_files IS 'Files modified by this rule (for checkpoint creation)';
COMMENT ON COLUMN checkpoint_files.file_content IS 'Full file content (base64 for binary files)';

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================