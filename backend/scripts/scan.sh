#!/bin/bash
# OpenSCAP Compliance Scan Script
# Generates XML and HTML reports

set -e

# Detect OS and find SCAP content
if [ ! -f /etc/os-release ]; then
    echo "ERROR: Cannot detect OS"
    exit 1
fi

. /etc/os-release
OS_VERSION=$VERSION_ID

case "$OS_VERSION" in
    22.04) CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml" ;;
    20.04) CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml" ;;
    18.04) CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml" ;;
    24.04) CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml" ;;
    *) echo "ERROR: No SCAP content for version $OS_VERSION"; exit 1 ;;
esac

if [ ! -f "$CONTENT" ]; then
    echo "ERROR: SCAP content not found: $CONTENT"
    exit 1
fi

# Setup output
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/tmp/oscap_scan_$TIMESTAMP"
mkdir -p "$REPORT_DIR"

RESULTS_XML="$REPORT_DIR/results.xml"
REPORT_HTML="$REPORT_DIR/report.html"
PROFILE="xccdf_org.ssgproject.content_profile_standard"

echo "SCAN_START"
echo "TIMESTAMP:$TIMESTAMP"
echo "REPORT_DIR:$REPORT_DIR"

# Run scan
oscap xccdf eval \
    --profile "$PROFILE" \
    --results "$RESULTS_XML" \
    --report "$REPORT_HTML" \
    "$CONTENT" > /dev/null 2>&1 || true

if [ ! -f "$RESULTS_XML" ]; then
    echo "ERROR: Scan failed"
    exit 1
fi

# Parse results
PASSED=$(grep -c '<result>pass</result>' "$RESULTS_XML" || echo "0")
FAILED=$(grep -c '<result>fail</result>' "$RESULTS_XML" || echo "0")
ERROR=$(grep -c '<result>error</result>' "$RESULTS_XML" || echo "0")
NOTAPPLICABLE=$(grep -c '<result>notapplicable</result>' "$RESULTS_XML" || echo "0")
NOTCHECKED=$(grep -c '<result>notchecked</result>' "$RESULTS_XML" || echo "0")
NOTSELECTED=$(grep -c '<result>notselected</result>' "$RESULTS_XML" || echo "0")
TOTAL=$(grep -c '<rule-result' "$RESULTS_XML" || echo "0")

APPLICABLE=$((TOTAL - NOTAPPLICABLE - NOTCHECKED - NOTSELECTED))
if [ "$APPLICABLE" -gt 0 ]; then
    SCORE=$(awk "BEGIN {printf \"%.2f\", ($PASSED / $APPLICABLE) * 100}")
else
    SCORE="0.00"
fi

# Output results in parseable format
echo "SCAN_COMPLETE"
echo "SCORE:$SCORE"
echo "PASSED:$PASSED"
echo "FAILED:$FAILED"
echo "ERROR:$ERROR"
echo "TOTAL:$TOTAL"
echo "RESULTS_XML:$RESULTS_XML"
echo "REPORT_HTML:$REPORT_HTML"

# Output failed rules
if [ "$FAILED" -gt 0 ]; then
    echo "FAILED_RULES_START"
    grep -B1 '<result>fail</result>' "$RESULTS_XML" | \
        grep 'rule-result idref=' | \
        sed 's/.*idref="xccdf_org.ssgproject.content_rule_\([^"]*\)".*/\1/'
    echo "FAILED_RULES_END"
fi

