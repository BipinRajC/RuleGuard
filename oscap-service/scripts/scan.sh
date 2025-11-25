#!/bin/bash
# OpenSCAP Compliance Scan Script - HPC Cluster Deployment
# Supported OS: RHEL/CentOS/Rocky/AlmaLinux (7-9), SLES (12-15), Ubuntu LTS (18.04-24.04)
# Non-interactive, structured output for scaprun parsing

set -e

# Get profile from command line argument (user selection)
USER_PROFILE="$1"

# Detect OS and find SCAP content
if [ ! -f /etc/os-release ]; then
    echo "ERROR:Cannot detect OS - /etc/os-release not found"
    exit 1
fi

. /etc/os-release
OS_ID=$ID
OS_VERSION_ID=$VERSION_ID

# Determine SCAP content file based on OS
case "$OS_ID" in
    rhel|centos|rocky|almalinux)
        # RHEL family - profiles vary by version
        MAJOR_VERSION=$(echo "$OS_VERSION_ID" | cut -d. -f1)
        case "$MAJOR_VERSION" in
            7)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel7-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-centos7-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="cis_server_l1"
                ;;
            8)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel8-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-centos8-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="cis_server_l1"
                ;;
            9)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-centos9-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel9-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-centos9-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="cis_server_l1"
                ;;
            *)
                echo "ERROR:No SCAP content for RHEL family version $MAJOR_VERSION"
                exit 1
                ;;
        esac
        ;;
    
    sles|sles_sap|suse)
        # SLES - uses standard or stig profiles
        MAJOR_VERSION=$(echo "$OS_VERSION_ID" | cut -d. -f1)
        case "$MAJOR_VERSION" in
            12)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-sle12-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-sle12-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="standard"
                ;;
            15)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-sle15-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="standard"
                ;;
            *)
                echo "ERROR:No SCAP content for SLES version $MAJOR_VERSION"
                exit 1
                ;;
        esac
        ;;
    
    ubuntu)
        # Ubuntu - standard profile is most common
        case "$OS_VERSION_ID" in
            18.04)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu1804-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="standard"
                ;;
            20.04)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu2004-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="standard"
                ;;
            22.04)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu2204-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="standard"
                ;;
            24.04)
                # Use 22.04 content for 24.04 until official content is available
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu2204-ds.xml"
                # Default profile if none specified
                [ -z "$USER_PROFILE" ] && USER_PROFILE="standard"
                ;;
            *)
                echo "ERROR:No SCAP content for Ubuntu version $OS_VERSION_ID"
                exit 1
                ;;
        esac
        ;;
    
    *)
        echo "ERROR:Unsupported OS: $OS_ID"
        echo "ERROR:Supported: RHEL/CentOS/Rocky/AlmaLinux 7-9, SLES 12-15, Ubuntu 18.04-24.04 LTS"
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

# Build full profile ID (prepend xccdf prefix if not already present)
if [[ "$USER_PROFILE" == xccdf_* ]]; then
    # Profile already has full ID
    PROFILE="$USER_PROFILE"
else
    # Add xccdf prefix
    PROFILE="xccdf_org.ssgproject.content_profile_${USER_PROFILE}"
fi

# Verify profile exists in the content
if ! oscap info "$CONTENT" 2>/dev/null | grep -q "Id: $PROFILE"; then
    echo "WARNING:Profile $PROFILE not found in content"
    echo "INFO:Available profiles:"
    oscap info "$CONTENT" 2>/dev/null | grep "Profile" | head -10
    echo "ERROR:Selected profile not available for this OS version"
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

# Output scan start information
echo "SCAN_START"
echo "TIMESTAMP:$TIMESTAMP"
echo "REPORT_DIR:$REPORT_DIR"
echo "OS_ID:$OS_ID"
echo "OS_VERSION:$OS_VERSION_ID"
echo "CONTENT:$CONTENT"
echo "PROFILE:$PROFILE"

# Run OpenSCAP scan
echo "DEBUG:About to run oscap with CONTENT=$CONTENT and PROFILE=$PROFILE"

# Temporarily disable exit-on-error since oscap returns 2 for rule failures
set +e

# Run scan - oscap returns:
# 0 = success (all rules passed)
# 1 = error
# 2 = success but some rules failed (NORMAL!)
oscap xccdf eval \
    --profile "$PROFILE" \
    --results "$RESULTS_XML" \
    --report "$REPORT_HTML" \
    "$CONTENT" > /dev/null 2>&1
SCAN_EXIT_CODE=$?

# Re-enable exit-on-error
set -e

echo "DEBUG:Scan exit code: $SCAN_EXIT_CODE"

# Exit codes 0 and 2 are acceptable (2 means rules failed, which is expected)
if [ $SCAN_EXIT_CODE -ne 0 ] && [ $SCAN_EXIT_CODE -ne 2 ]; then
    echo "ERROR:OpenSCAP scan failed with exit code $SCAN_EXIT_CODE"
    echo "ERROR:Exit code 1 means error, checking for results anyway..."
fi

# Check if results file was created (this is the real indicator of success)
if [ ! -f "$RESULTS_XML" ]; then
    echo "ERROR:Scan results file not created: $RESULTS_XML"
    echo "ERROR:This usually means oscap failed to run or profile doesn't exist"
    echo "ERROR:Exit code was: $SCAN_EXIT_CODE"
    echo "ERROR:Trying to list available profiles..."
    oscap info "$CONTENT" 2>&1 | grep -A5 "Profiles:" | head -15 || true
    exit 1
fi

echo "DEBUG:Results file created successfully: $RESULTS_XML"

# Parse results from XML
PASSED=$(grep -c '<result>pass</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
PASSED=$(echo "$PASSED" | tr -d '\n\r' | awk '{print $NF}')

FAILED=$(grep -c '<result>fail</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
FAILED=$(echo "$FAILED" | tr -d '\n\r' | awk '{print $NF}')

ERROR=$(grep -c '<result>error</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
ERROR=$(echo "$ERROR" | tr -d '\n\r' | awk '{print $NF}')

NOTAPPLICABLE=$(grep -c '<result>notapplicable</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
NOTAPPLICABLE=$(echo "$NOTAPPLICABLE" | tr -d '\n\r' | awk '{print $NF}')

NOTCHECKED=$(grep -c '<result>notchecked</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
NOTCHECKED=$(echo "$NOTCHECKED" | tr -d '\n\r' | awk '{print $NF}')

NOTSELECTED=$(grep -c '<result>notselected</result>' "$RESULTS_XML" 2>/dev/null || echo "0")
NOTSELECTED=$(echo "$NOTSELECTED" | tr -d '\n\r' | awk '{print $NF}')

TOTAL=$(grep -c '<rule-result' "$RESULTS_XML" 2>/dev/null || echo "0")
TOTAL=$(echo "$TOTAL" | tr -d '\n\r' | awk '{print $NF}')

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
echo "NOTCHECKED:$NOTCHECKED"
echo "NOTSELECTED:$NOTSELECTED"
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

