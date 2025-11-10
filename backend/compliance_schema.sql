-- Compliance Monitoring Framework Schema (Production - Without Checkpoints)
-- PostgreSQL 12+

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Table: nodes
-- Stores target servers/PCs to be monitored
CREATE TABLE nodes (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 22,
    username VARCHAR(100) NOT NULL,
    auth_type VARCHAR(20) NOT NULL CHECK (auth_type IN ('password', 'key')),
    credentials TEXT, -- Encrypted SSH key path or password
    description TEXT,
    os_type VARCHAR(50), -- e.g., 'rhel-8', 'ubuntu-22.04'
    is_active BOOLEAN DEFAULT true,
    
    -- Monitoring configuration
    scan_profile VARCHAR(255) DEFAULT 'xccdf_org.ssgproject.content_profile_cis',
    scan_interval_minutes INTEGER DEFAULT 180, -- Default: 3 hours
    
    -- Current state (denormalized for fast dashboard queries)
    last_scan_id INTEGER,
    current_compliance_score DECIMAL(5,2),
    current_status VARCHAR(50) DEFAULT 'unknown', -- 'healthy', 'warning', 'critical', 'unknown'
    last_scan_at TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: scans
-- Each full compliance scan execution (stores summary only)
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    profile VARCHAR(255) NOT NULL,
    
    -- Scan execution
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
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
    
    -- Critical metrics for alerting
    critical_failures INTEGER DEFAULT 0,
    high_failures INTEGER DEFAULT 0,
    medium_failures INTEGER DEFAULT 0,
    
    -- Storage
    report_path TEXT, -- Path to full XML report on disk/S3
    error_message TEXT, -- Error details if status = 'failed'
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: rules_baseline
-- Static rule definitions (populated once, referenced many times)
-- This prevents storing rule metadata repeatedly for each scan
CREATE TABLE rules_baseline (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL UNIQUE, -- OpenSCAP rule identifier
    title TEXT NOT NULL,
    description TEXT,
    rationale TEXT,
    severity VARCHAR(20) CHECK (severity IN ('unknown', 'info', 'low', 'medium', 'high', 'critical')),
    
    -- Remediation information
    remediation TEXT,
    can_auto_remediate BOOLEAN DEFAULT false,
    requires_reboot BOOLEAN DEFAULT false,
    
    -- Identifiers (CCE, CVE, CIS, etc.)
    identifiers JSONB,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: scan_results
-- Individual rule results for each scan
-- Only stores result, references rules_baseline for static data
CREATE TABLE scan_results (
    id BIGSERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL, -- References rules_baseline(rule_id)
    
    -- Result (the only thing that changes between scans)
    result VARCHAR(20) NOT NULL CHECK (result IN (
        'pass', 'fail', 'error', 'notapplicable', 
        'notchecked', 'notselected', 'informational', 'fixed'
    )),
    
    -- Optional: Store check output only for failures
    check_output TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: compliance_changes
-- Track when rules change status (pass->fail or vice versa)
-- THIS IS WHAT DASHBOARD SHOWS IN REAL-TIME
CREATE TABLE compliance_changes (
    id BIGSERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    
    previous_result VARCHAR(20),
    current_result VARCHAR(20) NOT NULL,
    
    -- Context
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity VARCHAR(20), -- Denormalized for quick filtering
    
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- For alerting/acknowledgment
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP
);

-- Table: remediations
-- Track remediation attempts
CREATE TABLE remediations (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    
    method VARCHAR(50) NOT NULL CHECK (method IN ('openscap_auto', 'manual_script', 'manual')),
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'success', 'failed', 'requires_reboot')),
    
    execution_output TEXT,
    error_message TEXT,
    
    executed_by VARCHAR(100),
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: scan_schedule
-- Track scheduled scans and their status (for distributed workers)
CREATE TABLE scan_schedule (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    
    next_scan_at TIMESTAMP NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    
    -- Prevent concurrent scans (distributed locking)
    is_running BOOLEAN DEFAULT false,
    locked_at TIMESTAMP,
    locked_by VARCHAR(100), -- Worker/process ID
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT idx_unique_node_schedule UNIQUE (node_id)
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Nodes indexes
CREATE INDEX idx_nodes_active ON nodes(is_active) WHERE is_active = true;
CREATE INDEX idx_nodes_last_scan ON nodes(last_scan_at DESC);
CREATE INDEX idx_nodes_status ON nodes(current_status);
CREATE INDEX idx_nodes_name ON nodes(name);

-- Scans indexes
CREATE INDEX idx_scans_node_created ON scans(node_id, created_at DESC);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_completed ON scans(completed_at DESC) WHERE status = 'completed';

-- Scan results indexes
CREATE INDEX idx_scan_results_scan ON scan_results(scan_id);
CREATE INDEX idx_scan_results_rule ON scan_results(rule_id);
CREATE INDEX idx_scan_results_result ON scan_results(result) WHERE result IN ('fail', 'error');
CREATE UNIQUE INDEX idx_scan_results_unique ON scan_results(scan_id, rule_id);

-- Rules baseline indexes
CREATE INDEX idx_rules_baseline_severity ON rules_baseline(severity);
CREATE INDEX idx_rules_baseline_rule_id ON rules_baseline(rule_id);

-- Compliance changes indexes
CREATE INDEX idx_changes_node_detected ON compliance_changes(node_id, detected_at DESC);
CREATE INDEX idx_changes_unacknowledged ON compliance_changes(acknowledged) WHERE acknowledged = false;
CREATE INDEX idx_changes_severity ON compliance_changes(severity);
CREATE INDEX idx_changes_detected ON compliance_changes(detected_at DESC);

-- Remediations indexes
CREATE INDEX idx_remediations_node ON remediations(node_id, created_at DESC);
CREATE INDEX idx_remediations_status ON remediations(status);
CREATE INDEX idx_remediations_rule ON remediations(rule_id);

-- Scan schedule indexes
CREATE INDEX idx_schedule_next_scan ON scan_schedule(next_scan_at) 
    WHERE is_enabled = true AND is_running = false;

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

-- Trigger: Update nodes updated_at
CREATE TRIGGER trigger_nodes_updated_at 
    BEFORE UPDATE ON nodes
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger: Update rules_baseline updated_at
CREATE TRIGGER trigger_rules_updated_at 
    BEFORE UPDATE ON rules_baseline
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger: Update scan_schedule updated_at
CREATE TRIGGER trigger_schedule_updated_at 
    BEFORE UPDATE ON scan_schedule
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Function: Update node state after scan completes
CREATE OR REPLACE FUNCTION update_node_state()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' THEN
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
BEGIN
    -- Get previous result for this node+rule from most recent scan
    SELECT sr.result INTO prev_result
    FROM scan_results sr
    JOIN scans s ON sr.scan_id = s.id
    WHERE s.node_id = (SELECT node_id FROM scans WHERE id = NEW.scan_id)
        AND sr.rule_id = NEW.rule_id
        AND s.id != NEW.scan_id
        AND s.status = 'completed'
    ORDER BY s.completed_at DESC
    LIMIT 1;
    
    -- If result changed, log it
    IF prev_result IS NOT NULL AND prev_result != NEW.result THEN
        -- Get rule severity from baseline
        SELECT severity INTO rule_severity
        FROM rules_baseline
        WHERE rule_id = NEW.rule_id;
        
        INSERT INTO compliance_changes (
            node_id, rule_id, previous_result, current_result, 
            scan_id, severity, detected_at
        )
        SELECT 
            (SELECT node_id FROM scans WHERE id = NEW.scan_id),
            NEW.rule_id,
            prev_result,
            NEW.result,
            NEW.scan_id,
            rule_severity,
            CURRENT_TIMESTAMP;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_detect_changes
    AFTER INSERT ON scan_results
    FOR EACH ROW
    EXECUTE FUNCTION detect_compliance_changes();

-- Function: Update scan schedule after scan completes
CREATE OR REPLACE FUNCTION update_scan_schedule()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status IN ('completed', 'failed') AND OLD.status != NEW.status THEN
        UPDATE scan_schedule SET
            next_scan_at = CURRENT_TIMESTAMP + 
                (SELECT scan_interval_minutes FROM nodes WHERE id = NEW.node_id) * INTERVAL '1 minute',
            is_running = false,
            locked_at = NULL,
            locked_by = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE node_id = NEW.node_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_schedule
    AFTER UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_scan_schedule();

-- ============================================================================
-- VIEWS FOR DASHBOARD
-- ============================================================================

-- View: Current node compliance status (MAIN DASHBOARD VIEW)
CREATE VIEW v_node_status AS
SELECT
    n.id,
    n.name,
    n.hostname,
    n.os_type,
    n.current_compliance_score as compliance_score,
    n.current_status as status,
    n.last_scan_at,
    n.scan_interval_minutes,
    s.critical_failures,
    s.high_failures,
    s.medium_failures,
    s.failed_rules,
    s.total_rules,
    s.duration_seconds as last_scan_duration,
    ss.next_scan_at,
    ss.is_running as scan_in_progress
FROM nodes n
LEFT JOIN scans s ON n.last_scan_id = s.id
LEFT JOIN scan_schedule ss ON n.id = ss.node_id
WHERE n.is_active = true
ORDER BY n.current_status DESC, n.current_compliance_score ASC;

-- View: Recent compliance changes (ACTIVITY FEED)
CREATE VIEW v_recent_changes AS
SELECT
    cc.id,
    cc.node_id,
    n.name as node_name,
    cc.rule_id,
    rb.title as rule_title,
    cc.severity,
    cc.previous_result,
    cc.current_result,
    cc.detected_at,
    cc.acknowledged,
    cc.acknowledged_by,
    cc.acknowledged_at,
    s.compliance_score as scan_score
FROM compliance_changes cc
JOIN nodes n ON cc.node_id = n.id
JOIN scans s ON cc.scan_id = s.id
LEFT JOIN rules_baseline rb ON cc.rule_id = rb.rule_id
ORDER BY cc.detected_at DESC;

-- View: Nodes needing attention (ALERTS)
CREATE VIEW v_nodes_attention AS
SELECT
    n.id,
    n.name,
    n.hostname,
    n.current_compliance_score,
    n.current_status,
    n.last_scan_at,
    s.critical_failures,
    s.high_failures,
    COUNT(cc.id) as unacknowledged_changes
FROM nodes n
LEFT JOIN scans s ON n.last_scan_id = s.id
LEFT JOIN compliance_changes cc ON n.id = cc.node_id AND cc.acknowledged = false
WHERE n.is_active = true
    AND (
        n.current_status IN ('warning', 'critical') 
        OR n.current_compliance_score < 80
        OR n.last_scan_at < CURRENT_TIMESTAMP - (n.scan_interval_minutes * 2) * INTERVAL '1 minute'
    )
GROUP BY n.id, n.name, n.hostname, n.current_compliance_score, 
         n.current_status, n.last_scan_at, s.critical_failures, s.high_failures
ORDER BY n.current_compliance_score ASC;

-- View: Failed rules for a node (NODE DETAIL VIEW)
CREATE OR REPLACE VIEW v_node_failed_rules AS
SELECT
    n.id as node_id,
    n.name as node_name,
    n.last_scan_id as scan_id,
    sr.rule_id,
    rb.title,
    rb.severity,
    rb.description,
    rb.rationale,
    rb.remediation,
    rb.can_auto_remediate,
    rb.requires_reboot,
    sr.result,
    sr.check_output,
    rb.identifiers
FROM nodes n
JOIN scan_results sr ON n.last_scan_id = sr.scan_id
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

-- View: Scan history summary
CREATE VIEW v_scan_history AS
SELECT
    s.id as scan_id,
    s.node_id,
    n.name as node_name,
    s.profile,
    s.started_at,
    s.completed_at,
    s.duration_seconds,
    s.status,
    s.compliance_score,
    s.total_rules,
    s.passed_rules,
    s.failed_rules,
    s.critical_failures,
    s.high_failures,
    s.medium_failures
FROM scans s
JOIN nodes n ON s.node_id = n.id
ORDER BY s.started_at DESC;

-- ============================================================================
-- MATERIALIZED VIEW FOR COMPLIANCE TRENDS
-- ============================================================================

CREATE MATERIALIZED VIEW mv_compliance_trends AS
SELECT
    n.id as node_id,
    n.name as node_name,
    DATE_TRUNC('hour', s.completed_at) as hour,
    AVG(s.compliance_score) as avg_score,
    MIN(s.compliance_score) as min_score,
    MAX(s.compliance_score) as max_score,
    COUNT(*) as scan_count,
    AVG(s.failed_rules) as avg_failed_rules,
    AVG(s.critical_failures) as avg_critical_failures
FROM scans s
JOIN nodes n ON s.node_id = n.id
WHERE s.status = 'completed'
    AND s.completed_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
GROUP BY n.id, n.name, DATE_TRUNC('hour', s.completed_at)
ORDER BY hour DESC;

CREATE INDEX idx_mv_trends_node_hour ON mv_compliance_trends(node_id, hour DESC);

-- Function: Refresh compliance trends (call from cron every 15 min)
CREATE OR REPLACE FUNCTION refresh_compliance_trends()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_compliance_trends;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Function: Initialize scan schedule for a node
CREATE OR REPLACE FUNCTION init_scan_schedule(p_node_id INTEGER)
RETURNS void AS $$
BEGIN
    INSERT INTO scan_schedule (node_id, next_scan_at, is_enabled)
    VALUES (p_node_id, CURRENT_TIMESTAMP, true)
    ON CONFLICT (node_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Function: Claim next scan (for distributed workers)
CREATE OR REPLACE FUNCTION claim_next_scan(p_worker_id VARCHAR(100))
RETURNS TABLE(node_id INTEGER, node_name VARCHAR(255), hostname VARCHAR(255), 
              port INTEGER, username VARCHAR(100), auth_type VARCHAR(20), 
              credentials TEXT, os_type VARCHAR(50), scan_profile VARCHAR(255)) AS $$
BEGIN
    RETURN QUERY
    UPDATE scan_schedule
    SET is_running = true, 
        locked_by = p_worker_id, 
        locked_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    WHERE scan_schedule.node_id = (
        SELECT scan_schedule.node_id 
        FROM scan_schedule
        JOIN nodes ON scan_schedule.node_id = nodes.id
        WHERE scan_schedule.next_scan_at <= CURRENT_TIMESTAMP 
            AND scan_schedule.is_enabled = true 
            AND scan_schedule.is_running = false
            AND nodes.is_active = true
        ORDER BY scan_schedule.next_scan_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    RETURNING 
        nodes.id, nodes.name, nodes.hostname, nodes.port, 
        nodes.username, nodes.auth_type, nodes.credentials, 
        nodes.os_type, nodes.scan_profile
    FROM nodes 
    WHERE nodes.id = scan_schedule.node_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- INITIAL DATA / SEED
-- ============================================================================

-- Add common profile mappings if needed
-- INSERT INTO ... (can be added later)

-- ============================================================================
-- COMMENTS (Documentation)
-- ============================================================================

COMMENT ON TABLE nodes IS 'Target servers/PCs to be monitored for compliance';
COMMENT ON TABLE scans IS 'Compliance scan execution history (summary data only)';
COMMENT ON TABLE rules_baseline IS 'Static rule definitions from OpenSCAP content';
COMMENT ON TABLE scan_results IS 'Individual rule results for each scan';
COMMENT ON TABLE compliance_changes IS 'Tracks when rule status changes (for real-time dashboard)';
COMMENT ON TABLE remediations IS 'Tracks remediation attempts and results';
COMMENT ON TABLE scan_schedule IS 'Manages scan scheduling for distributed workers';

COMMENT ON COLUMN nodes.credentials IS 'Encrypted SSH credentials or key path';
COMMENT ON COLUMN nodes.current_compliance_score IS 'Denormalized from last scan for fast queries';
COMMENT ON COLUMN nodes.scan_interval_minutes IS 'How often to scan this node (default: 180 = 3 hours)';
COMMENT ON COLUMN scans.report_path IS 'Path to full XML report (stored on disk/S3, not in DB)';
COMMENT ON COLUMN rules_baseline.identifiers IS 'JSON object with CCE, CVE, CIS identifiers';
COMMENT ON COLUMN scan_results.check_output IS 'Only populated for failed checks (to save space)';

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================