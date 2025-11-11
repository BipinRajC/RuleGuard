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

# Determine SCAP content file based on OS version
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
        echo "ERROR:No SCAP content for OS version $OS_VERSION"
        exit 1
        ;;
esac

# Verify SCAP content exists
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
echo "OS_VERSION:$OS_VERSION"
echo "CONTENT:$CONTENT"
echo "PROFILE:$PROFILE"

# Run OpenSCAP scan
# Note: oscap exits with non-zero even on successful scans with failures
# so we use || true and check for output files instead
oscap xccdf eval \
    --profile "$PROFILE" \
    --results "$RESULTS_XML" \
    --report "$REPORT_HTML" \
    "$CONTENT" > /dev/null 2>&1 || true

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

