#!/bin/bash
# OpenSCAP Remediation Script
# Usage: remediate.sh <rule_id1> [rule_id2] ...

set -e

if [ $# -eq 0 ]; then
    echo "ERROR: No rules specified"
    exit 1
fi

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
    *) echo "ERROR: No SCAP content"; exit 1 ;;
esac

PROFILE="xccdf_org.ssgproject.content_profile_standard"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "REMEDIATION_START"
echo "TIMESTAMP:$TIMESTAMP"
echo "RULES_COUNT:$#"

FIXED=0
FAILED=0

for RULE_SHORT in "$@"; do
    RULE_ID="xccdf_org.ssgproject.content_rule_${RULE_SHORT}"
    TEMP_DIR="/tmp/rem_${RULE_SHORT}_${TIMESTAMP}"
    mkdir -p "$TEMP_DIR"
    
    echo "RULE_START:$RULE_SHORT"
    
    # Try remediation
    oscap xccdf eval \
        --profile "$PROFILE" \
        --remediate \
        --rule "$RULE_ID" \
        --results "$TEMP_DIR/result.xml" \
        "$CONTENT" > "$TEMP_DIR/output.log" 2>&1 || true
    
    # Check result
    if grep -q '<result>pass</result>' "$TEMP_DIR/result.xml" 2>/dev/null; then
        echo "RULE_SUCCESS:$RULE_SHORT"
        FIXED=$((FIXED + 1))
    else
        # Verify
        oscap xccdf eval \
            --profile "$PROFILE" \
            --rule "$RULE_ID" \
            --results "$TEMP_DIR/verify.xml" \
            "$CONTENT" > /dev/null 2>&1 || true
        
        if grep -q '<result>pass</result>' "$TEMP_DIR/verify.xml" 2>/dev/null; then
            echo "RULE_SUCCESS:$RULE_SHORT"
            FIXED=$((FIXED + 1))
        else
            echo "RULE_FAILED:$RULE_SHORT"
            FAILED=$((FAILED + 1))
        fi
    fi
    
    rm -rf "$TEMP_DIR"
    echo "RULE_END:$RULE_SHORT"
done

echo "REMEDIATION_COMPLETE"
echo "FIXED:$FIXED"
echo "FAILED:$FAILED"

