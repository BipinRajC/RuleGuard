#!/bin/bash
# OpenSCAP Compliance Scan Script - Backend Automation
# Optimized for: Ubuntu 22.04 LTS (primary), Ubuntu 18.04+
# Non-interactive, returns structured output for API parsing

set -e

# Detect OS and find SCAP content
if [ ! -f /etc/os-release ]; then
    echo "ERROR:Cannot detect OS - /etc/os-release not found"
    exit 1
fi

. /etc/os-release
OS_NAME=$ID
OS_VERSION=$VERSION_ID

# Determine SCAP content file based on OS
if [ "$OS_NAME" = "arch" ]; then
    # Arch Linux - use generic content or skip for testing
    # For testing purposes, create a mock scan
    echo "WARNING:Arch Linux detected - using test mode (no actual scan)"
    CONTENT="TEST_MODE"
elif [ "$OS_NAME" = "ubuntu" ]; then
    case "$OS_VERSION" in
        22.04)
            CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
            ;;
        20.04)
            CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml"
            ;;
        18.04)
            CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml"
            ;;
        24.04)
            # Use 22.04 content for 24.04 until official content is available
            CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
            ;;
        *)
            echo "ERROR:No SCAP content for Ubuntu version $OS_VERSION"
            exit 1
            ;;
    esac
else
    echo "ERROR:Unsupported OS: $OS_NAME"
    echo "ERROR:Currently supported: Ubuntu (18.04, 20.04, 22.04, 24.04), Arch (test mode)"
    exit 1
fi

# Verify SCAP content exists (skip for test mode)
if [ "$CONTENT" != "TEST_MODE" ]; then
    if [ ! -f "$CONTENT" ]; then
        echo "ERROR:SCAP content not found: $CONTENT"
        echo "ERROR:Please run install-openscap first"
        exit 1
    fi

    # Verify oscap command is available
    if ! command -v oscap &> /dev/null; then
        echo "ERROR:oscap command not found"
        echo "ERROR:Please run install-openscap first"
        exit 1
    fi
fi

# Setup output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/tmp/oscap_scan_$TIMESTAMP"
mkdir -p "$REPORT_DIR" || {
    echo "ERROR:Failed to create report directory: $REPORT_DIR"
    exit 1
}

RESULTS_XML="$REPORT_DIR/results.xml"
REPORT_HTML="$REPORT_DIR/report.html"

# Use standard profile (works for all Ubuntu versions)
PROFILE="xccdf_org.ssgproject.content_profile_standard"

# Output scan start information
echo "SCAN_START"
echo "TIMESTAMP:$TIMESTAMP"
echo "REPORT_DIR:$REPORT_DIR"
echo "OS_NAME:$OS_NAME"
echo "OS_VERSION:$OS_VERSION"
echo "CONTENT:$CONTENT"
echo "PROFILE:$PROFILE"

# Run scan (real or test mode)
if [ "$CONTENT" = "TEST_MODE" ]; then
    # Test mode for unsupported OS - generate mock results
    echo "INFO:Running in test mode - generating mock scan results"
    
    # Create mock XML file with rule IDs
    cat > "$RESULTS_XML" << 'MOCKXML'
<?xml version="1.0" encoding="UTF-8"?>
<test-results>
    <rule-result idref="xccdf_org.ssgproject.content_rule_test_pass_1"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_test_pass_2"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_test_pass_3"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_test_fail_1"><result>fail</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_test_fail_2"><result>fail</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_test_notapplicable"><result>notapplicable</result></rule-result>
</test-results>
MOCKXML

    # Create mock HTML report
    echo "<html><body><h1>Mock Scan Report - Test Mode</h1><p>This is a test scan for $OS_NAME $OS_VERSION</p></body></html>" > "$REPORT_HTML"
    
else
    # Real OpenSCAP scan
    oscap xccdf eval \
        --profile "$PROFILE" \
        --results "$RESULTS_XML" \
        --report "$REPORT_HTML" \
        "$CONTENT" > /dev/null 2>&1 || true
fi

# Verify scan produced results
if [ ! -f "$RESULTS_XML" ]; then
    echo "ERROR:Scan failed - no results file generated"
    echo "ERROR:Check if OpenSCAP is properly installed"
    exit 1
fi

# Parse results from XML
PASSED=$(grep -c '<result>pass</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
FAILED=$(grep -c '<result>fail</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
ERROR=$(grep -c '<result>error</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
NOTAPPLICABLE=$(grep -c '<result>notapplicable</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
NOTCHECKED=$(grep -c '<result>notchecked</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
NOTSELECTED=$(grep -c '<result>notselected</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
TOTAL=$(grep -c '<rule-result' "$RESULTS_XML" 2>/dev/null || echo "0")

# Calculate compliance score
# Only count applicable rules (exclude notapplicable, notchecked, notselected)
APPLICABLE=$((TOTAL - NOTAPPLICABLE - NOTCHECKED - NOTSELECTED))

if [ "$APPLICABLE" -gt 0 ]; then
    SCORE=$(awk "BEGIN {printf \"%.2f\", ($PASSED / $APPLICABLE) * 100}")
else
    SCORE="0.00"
fi

# Output results in structured format for backend parsing
echo "SCAN_COMPLETE"
echo "SCORE:$SCORE"
echo "PASSED:$PASSED"
echo "FAILED:$FAILED"
echo "ERROR:$ERROR"
echo "NOTAPPLICABLE:$NOTAPPLICABLE"
echo "TOTAL:$TOTAL"
echo "APPLICABLE:$APPLICABLE"
echo "RESULTS_XML:$RESULTS_XML"
echo "REPORT_HTML:$REPORT_HTML"

# Extract and output failed rule IDs for remediation
if [ "$FAILED" -gt 0 ]; then
    echo "FAILED_RULES_START"
    # Extract rule IDs, removing the xccdf_org.ssgproject.content_rule_ prefix
    grep -B1 '<result>fail</result>' "$RESULTS_XML" 2>/dev/null | \
        grep 'rule-result idref=' | \
        sed 's/.*idref="xccdf_org.ssgproject.content_rule_\([^"]*\)".*/\1/' || true
    echo "FAILED_RULES_END"
fi

# Success - exit 0 even if there are failed rules (scan itself succeeded)
exit 0

