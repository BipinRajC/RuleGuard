package reports

import (
	"encoding/xml"
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"
	"time"
)

// XCCDF Benchmark XML structures for full OpenSCAP results

// XCCDFBenchmark is the root element containing rule definitions and test results
type XCCDFBenchmark struct {
	XMLName     xml.Name          `xml:"Benchmark"`
	ID          string            `xml:"id,attr"`
	Title       string            `xml:"title"`
	Description string            `xml:"description"`
	Groups      []XCCDFGroup      `xml:"Group"`
	Rules       []XCCDFRule       `xml:"Rule"`
	Profiles    []XCCDFProfile    `xml:"Profile"`
	TestResults []XCCDFTestResult `xml:"TestResult"`
}

// XCCDFProfile contains profile metadata
type XCCDFProfile struct {
	ID          string `xml:"id,attr"`
	Title       string `xml:"title"`
	Description string `xml:"description"`
}

// XCCDFGroup can contain nested groups and rules
type XCCDFGroup struct {
	ID          string       `xml:"id,attr"`
	Title       string       `xml:"title"`
	Description string       `xml:"description"`
	Groups      []XCCDFGroup `xml:"Group"`
	Rules       []XCCDFRule  `xml:"Rule"`
}

// XCCDFRule contains full rule definition
type XCCDFRule struct {
	ID          string       `xml:"id,attr"`
	Severity    string       `xml:"severity,attr"`
	Selected    string       `xml:"selected,attr"`
	Title       string       `xml:"title"`
	Description string       `xml:"description"`
	Rationale   string       `xml:"rationale"`
	References  []XCCDFRef   `xml:"reference"`
	Fixes       []XCCDFFix   `xml:"fix"`
	Idents      []XCCDFIdent `xml:"ident"`
}

// XCCDFRef contains reference information
type XCCDFRef struct {
	Href  string `xml:"href,attr"`
	Value string `xml:",chardata"`
}

// XCCDFFix contains remediation scripts
type XCCDFFix struct {
	ID         string `xml:"id,attr"`
	System     string `xml:"system,attr"`
	Complexity string `xml:"complexity,attr"`
	Disruption string `xml:"disruption,attr"`
	Strategy   string `xml:"strategy,attr"`
	Content    string `xml:",chardata"`
}

// XCCDFIdent contains identifiers like CCE
type XCCDFIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// XCCDFTestResult contains the actual scan results
type XCCDFTestResult struct {
	ID          string            `xml:"id,attr"`
	StartTime   string            `xml:"start-time,attr"`
	EndTime     string            `xml:"end-time,attr"`
	Profile     XCCDFProfileRef   `xml:"profile"`
	Target      string            `xml:"target"`
	RuleResults []XCCDFRuleResult `xml:"rule-result"`
	Scores      []XCCDFScore      `xml:"score"`
}

// XCCDFProfileRef references the profile used
type XCCDFProfileRef struct {
	IDRef string `xml:"idref,attr"`
}

// XCCDFRuleResult contains individual rule results
type XCCDFRuleResult struct {
	IDRef    string `xml:"idref,attr"`
	Severity string `xml:"severity,attr"`
	Time     string `xml:"time,attr"`
	Weight   string `xml:"weight,attr"`
	Result   string `xml:"result"`
}

// XCCDFScore contains the compliance score
type XCCDFScore struct {
	System  string  `xml:"system,attr"`
	Maximum float64 `xml:"maximum,attr"`
	Value   float64 `xml:",chardata"`
}

// ARF (Asset Reporting Format) XML structures
type ARFReport struct {
	XMLName xml.Name `xml:"asset-report-collection"`
	Reports struct {
		Report struct {
			Content struct {
				TestResult XCCDFTestResult `xml:"TestResult"`
			} `xml:"content"`
		} `xml:"report"`
	} `xml:"reports"`
}

// ParsedReport is our internal representation of scan results
type ParsedReport struct {
	// Metadata
	ScanID       int
	NodeName     string
	NodeHost     string
	NodeOS       string
	ProfileID    string
	ProfileTitle string
	ScanTime     time.Time
	EndTime      time.Time
	Duration     time.Duration

	// Scores
	ComplianceScore float64
	MaxScore        float64
	ScorePercent    float64

	// Rule counts
	TotalRules    int
	PassedRules   int
	FailedRules   int
	ErrorRules    int
	NotApplicable int
	NotChecked    int
	NotSelected   int
	Informational int

	// Risk assessment
	RiskScore int    // 0-100
	RiskLevel string // Critical, High, Medium, Low

	// Severity breakdown of failures
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	UnknownCount  int

	// Rule details
	FailedRuleDetails []RuleDetail
	PassedRuleDetails []RuleDetail
	OtherRuleDetails  []RuleDetail
	AllRuleDetails    []RuleDetail

	// Historical data (from DB)
	PreviousScans  []HistoricalScan
	TrendDirection string // "up", "down", "stable"
}

// RuleDetail contains detailed rule information
type RuleDetail struct {
	RuleID       string
	Title        string
	Description  string
	Rationale    string
	Severity     string
	Result       string
	CCE          string
	References   []Reference
	Remediations []Remediation
	CheckTime    time.Time
}

// Reference contains a hyperlinked reference
type Reference struct {
	Href  string
	Title string
}

// Remediation contains fix script information
type Remediation struct {
	Type       string // ansible, shell, puppet
	Complexity string
	Disruption string
	Strategy   string
	Content    string
}

// HistoricalScan for trend analysis
type HistoricalScan struct {
	ScanTime time.Time
	Score    float64
}

// ParseXMLReport parses an OpenSCAP result XML file
func ParseXMLReport(xmlPath string) (*ParsedReport, error) {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read XML file: %w", err)
	}

	return ParseXMLData(data)
}

// ParseXMLData parses XML data bytes
func ParseXMLData(data []byte) (*ParsedReport, error) {
	// Try parsing as full XCCDF Benchmark (contains rule definitions + results)
	var benchmark XCCDFBenchmark
	if err := xml.Unmarshal(data, &benchmark); err == nil {
		if len(benchmark.TestResults) > 0 {
			return parseXCCDFBenchmark(&benchmark)
		}
	}

	// Try parsing as ARF format
	var arf ARFReport
	if err := xml.Unmarshal(data, &arf); err == nil && len(arf.Reports.Report.Content.TestResult.RuleResults) > 0 {
		return parseARFReport(&arf)
	}

	// Try parsing as standalone TestResult
	var testResult XCCDFTestResult
	if err := xml.Unmarshal(data, &testResult); err == nil && len(testResult.RuleResults) > 0 {
		return parseTestResultOnly(&testResult)
	}

	return nil, fmt.Errorf("unable to parse XML: unrecognized format")
}

// parseXCCDFBenchmark extracts data from full XCCDF Benchmark format
func parseXCCDFBenchmark(benchmark *XCCDFBenchmark) (*ParsedReport, error) {
	// Build a map of rule definitions
	ruleMap := make(map[string]*XCCDFRule)
	collectRules(benchmark.Groups, benchmark.Rules, ruleMap)

	// Use first test result
	if len(benchmark.TestResults) == 0 {
		return nil, fmt.Errorf("no test results found")
	}

	tr := benchmark.TestResults[0]

	report := &ParsedReport{
		ProfileID:    tr.Profile.IDRef,
		ProfileTitle: extractProfileTitle(tr.Profile.IDRef),
		NodeHost:     tr.Target,
	}

	// Parse times
	if tr.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, tr.StartTime); err == nil {
			report.ScanTime = t
		}
	}
	if tr.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, tr.EndTime); err == nil {
			report.EndTime = t
		}
	}
	if !report.ScanTime.IsZero() && !report.EndTime.IsZero() {
		report.Duration = report.EndTime.Sub(report.ScanTime)
	}

	// Parse scores
	for _, score := range tr.Scores {
		if strings.Contains(score.System, "flat") || score.System == "" || strings.Contains(score.System, "urn:xccdf:scoring:default") {
			report.ComplianceScore = score.Value
			report.MaxScore = score.Maximum
			break
		}
	}
	if report.MaxScore > 0 {
		report.ScorePercent = (report.ComplianceScore / report.MaxScore) * 100
	}

	// Process rule results with full metadata
	for _, rr := range tr.RuleResults {
		detail := RuleDetail{
			RuleID:   rr.IDRef,
			Severity: normalizeSeverity(rr.Severity),
			Result:   strings.ToLower(rr.Result),
		}

		// Parse time
		if rr.Time != "" {
			if t, err := time.Parse(time.RFC3339, rr.Time); err == nil {
				detail.CheckTime = t
			}
		}

		// Enrich with rule definition data
		if ruleDef, ok := ruleMap[rr.IDRef]; ok {
			detail.Title = cleanXMLContent(ruleDef.Title)
			detail.Description = cleanXMLContent(ruleDef.Description)
			detail.Rationale = cleanXMLContent(ruleDef.Rationale)

			// Use severity from rule definition if not set
			if detail.Severity == "unknown" && ruleDef.Severity != "" {
				detail.Severity = normalizeSeverity(ruleDef.Severity)
			}

			// Extract CCE
			for _, ident := range ruleDef.Idents {
				if strings.Contains(strings.ToLower(ident.System), "cce") {
					detail.CCE = ident.Value
					break
				}
			}

			// Extract references
			for _, ref := range ruleDef.References {
				detail.References = append(detail.References, Reference{
					Href:  ref.Href,
					Title: strings.TrimSpace(ref.Value),
				})
			}

			// Extract remediation scripts
			for _, fix := range ruleDef.Fixes {
				fixType := "shell"
				if strings.Contains(fix.System, "ansible") {
					fixType = "ansible"
				} else if strings.Contains(fix.System, "puppet") {
					fixType = "puppet"
				} else if strings.Contains(fix.System, "blueprint") {
					fixType = "blueprint"
				}

				detail.Remediations = append(detail.Remediations, Remediation{
					Type:       fixType,
					Complexity: fix.Complexity,
					Disruption: fix.Disruption,
					Strategy:   fix.Strategy,
					Content:    cleanFixContent(fix.Content),
				})
			}
		} else {
			// Fallback: generate title from ID
			detail.Title = extractRuleTitle(rr.IDRef)
		}

		report.AllRuleDetails = append(report.AllRuleDetails, detail)
		report.TotalRules++

		switch detail.Result {
		case "pass":
			report.PassedRules++
			report.PassedRuleDetails = append(report.PassedRuleDetails, detail)
		case "fail":
			report.FailedRules++
			report.FailedRuleDetails = append(report.FailedRuleDetails, detail)
			countBySeverity(report, detail.Severity)
		case "error":
			report.ErrorRules++
			report.OtherRuleDetails = append(report.OtherRuleDetails, detail)
		case "notapplicable":
			report.NotApplicable++
			report.OtherRuleDetails = append(report.OtherRuleDetails, detail)
		case "notchecked":
			report.NotChecked++
			report.OtherRuleDetails = append(report.OtherRuleDetails, detail)
		case "notselected":
			report.NotSelected++
		case "informational":
			report.Informational++
			report.OtherRuleDetails = append(report.OtherRuleDetails, detail)
		default:
			report.OtherRuleDetails = append(report.OtherRuleDetails, detail)
		}
	}

	// Calculate risk score
	report.calculateRiskScore()

	return report, nil
}

// collectRules recursively collects all rules from groups
func collectRules(groups []XCCDFGroup, rules []XCCDFRule, ruleMap map[string]*XCCDFRule) {
	// Add direct rules
	for i := range rules {
		ruleMap[rules[i].ID] = &rules[i]
	}

	// Recurse into groups
	for _, group := range groups {
		for i := range group.Rules {
			ruleMap[group.Rules[i].ID] = &group.Rules[i]
		}
		collectRules(group.Groups, nil, ruleMap)
	}
}

// parseARFReport extracts data from ARF format
func parseARFReport(arf *ARFReport) (*ParsedReport, error) {
	return parseTestResultOnly(&arf.Reports.Report.Content.TestResult)
}

// parseTestResultOnly handles standalone TestResult without rule definitions
func parseTestResultOnly(tr *XCCDFTestResult) (*ParsedReport, error) {
	report := &ParsedReport{
		ProfileID:    tr.Profile.IDRef,
		ProfileTitle: extractProfileTitle(tr.Profile.IDRef),
		NodeHost:     tr.Target,
	}

	// Parse times
	if tr.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, tr.StartTime); err == nil {
			report.ScanTime = t
		}
	}
	if tr.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, tr.EndTime); err == nil {
			report.EndTime = t
		}
	}
	if !report.ScanTime.IsZero() && !report.EndTime.IsZero() {
		report.Duration = report.EndTime.Sub(report.ScanTime)
	}

	// Parse score
	for _, score := range tr.Scores {
		report.ComplianceScore = score.Value
		report.MaxScore = score.Maximum
		break
	}
	if report.MaxScore > 0 {
		report.ScorePercent = (report.ComplianceScore / report.MaxScore) * 100
	}

	// Process rule results
	for _, rr := range tr.RuleResults {
		detail := RuleDetail{
			RuleID:   rr.IDRef,
			Title:    extractRuleTitle(rr.IDRef),
			Severity: normalizeSeverity(rr.Severity),
			Result:   strings.ToLower(rr.Result),
		}

		// Parse time
		if rr.Time != "" {
			if t, err := time.Parse(time.RFC3339, rr.Time); err == nil {
				detail.CheckTime = t
			}
		}

		report.AllRuleDetails = append(report.AllRuleDetails, detail)
		report.TotalRules++

		switch detail.Result {
		case "pass":
			report.PassedRules++
			report.PassedRuleDetails = append(report.PassedRuleDetails, detail)
		case "fail":
			report.FailedRules++
			report.FailedRuleDetails = append(report.FailedRuleDetails, detail)
			countBySeverity(report, detail.Severity)
		case "error":
			report.ErrorRules++
		case "notapplicable":
			report.NotApplicable++
		case "notchecked":
			report.NotChecked++
		case "notselected":
			report.NotSelected++
		case "informational":
			report.Informational++
		}
	}

	report.calculateRiskScore()

	return report, nil
}

// countBySeverity increments the appropriate severity counter
func countBySeverity(report *ParsedReport, severity string) {
	switch severity {
	case "critical":
		report.CriticalCount++
	case "high":
		report.HighCount++
	case "medium":
		report.MediumCount++
	case "low":
		report.LowCount++
	default:
		report.UnknownCount++
	}
}

// calculateRiskScore computes a weighted risk score
func (r *ParsedReport) calculateRiskScore() {
	// Weighted scoring: Critical=40, High=20, Medium=10, Low=5
	weightedScore := (r.CriticalCount * 40) + (r.HighCount * 20) + (r.MediumCount * 10) + (r.LowCount * 5)

	// Normalize to 0-100 (cap at 100)
	r.RiskScore = weightedScore
	if r.RiskScore > 100 {
		r.RiskScore = 100
	}

	// Determine risk level
	switch {
	case r.CriticalCount > 0 || r.RiskScore >= 80:
		r.RiskLevel = "Critical"
	case r.HighCount > 2 || r.RiskScore >= 50:
		r.RiskLevel = "High"
	case r.RiskScore >= 25:
		r.RiskLevel = "Medium"
	default:
		r.RiskLevel = "Low"
	}
}

// cleanXMLContent cleans XML content for HTML display
func cleanXMLContent(content string) string {
	// Remove XML namespace prefixes
	content = regexp.MustCompile(`<html:[^>]*>`).ReplaceAllString(content, "")
	content = regexp.MustCompile(`</html:[^>]*>`).ReplaceAllString(content, "")
	content = regexp.MustCompile(`xmlns:[^=]*="[^"]*"`).ReplaceAllString(content, "")

	// Convert common XHTML elements
	content = strings.ReplaceAll(content, "<html:br/>", "<br>")
	content = strings.ReplaceAll(content, "<html:br />", "<br>")
	content = regexp.MustCompile(`<html:code[^>]*>`).ReplaceAllString(content, "<code>")
	content = strings.ReplaceAll(content, "</html:code>", "</code>")
	content = regexp.MustCompile(`<html:pre[^>]*>`).ReplaceAllString(content, "<pre>")
	content = strings.ReplaceAll(content, "</html:pre>", "</pre>")
	content = regexp.MustCompile(`<html:a[^>]*href="([^"]*)"[^>]*>`).ReplaceAllString(content, `<a href="$1" target="_blank">`)
	content = strings.ReplaceAll(content, "</html:a>", "</a>")
	content = regexp.MustCompile(`<html:em[^>]*>`).ReplaceAllString(content, "<em>")
	content = strings.ReplaceAll(content, "</html:em>", "</em>")

	// Clean up whitespace
	content = strings.TrimSpace(content)

	return content
}

// cleanFixContent cleans remediation script content
func cleanFixContent(content string) string {
	// Unescape HTML entities
	content = html.UnescapeString(content)
	// Trim whitespace
	content = strings.TrimSpace(content)
	return content
}

// extractProfileTitle extracts readable title from profile ID
func extractProfileTitle(profileID string) string {
	// xccdf_org.ssgproject.content_profile_cis_server_l1 -> CIS Server L1
	if strings.Contains(profileID, "_profile_") {
		parts := strings.Split(profileID, "_profile_")
		if len(parts) == 2 {
			name := parts[1]
			// Convert underscores to spaces and title case
			name = strings.ReplaceAll(name, "_", " ")
			return strings.Title(name)
		}
	}
	return profileID
}

// extractRuleTitle extracts readable title from rule ID
func extractRuleTitle(ruleID string) string {
	// xccdf_org.ssgproject.content_rule_sshd_disable_root_login -> SSH Disable Root Login
	if strings.Contains(ruleID, "_rule_") {
		parts := strings.Split(ruleID, "_rule_")
		if len(parts) == 2 {
			name := parts[1]
			name = strings.ReplaceAll(name, "_", " ")
			return strings.Title(name)
		}
	}
	return ruleID
}

// normalizeSeverity normalizes severity strings
func normalizeSeverity(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "critical", "very-high":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "unknown"
	}
}

// GetComplianceStatus returns status string based on score
func (r *ParsedReport) GetComplianceStatus() string {
	switch {
	case r.ScorePercent >= 90:
		return "Compliant"
	case r.ScorePercent >= 70:
		return "Partially Compliant"
	default:
		return "Non-Compliant"
	}
}

// GetStatusColor returns the color class for the compliance status
func (r *ParsedReport) GetStatusColor() string {
	switch {
	case r.ScorePercent >= 90:
		return "green"
	case r.ScorePercent >= 70:
		return "yellow"
	default:
		return "red"
	}
}

// SortFailedRulesBySeverity sorts failed rules by severity (critical first)
func (r *ParsedReport) SortFailedRulesBySeverity() {
	severityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"unknown":  4,
		"info":     5,
	}

	// Simple bubble sort
	for i := 0; i < len(r.FailedRuleDetails); i++ {
		for j := i + 1; j < len(r.FailedRuleDetails); j++ {
			if severityOrder[r.FailedRuleDetails[i].Severity] > severityOrder[r.FailedRuleDetails[j].Severity] {
				r.FailedRuleDetails[i], r.FailedRuleDetails[j] = r.FailedRuleDetails[j], r.FailedRuleDetails[i]
			}
		}
	}
}

// EnrichFromDatabase adds additional data from database
func (r *ParsedReport) EnrichFromDatabase(scanID int, nodeName, nodeHost, nodeOS string, historicalScans []HistoricalScan) {
	r.ScanID = scanID
	r.NodeName = nodeName
	r.NodeHost = nodeHost
	r.NodeOS = nodeOS
	r.PreviousScans = historicalScans

	// Calculate trend
	if len(historicalScans) >= 2 {
		latest := historicalScans[0].Score
		previous := historicalScans[1].Score

		if latest > previous+2 {
			r.TrendDirection = "up"
		} else if latest < previous-2 {
			r.TrendDirection = "down"
		} else {
			r.TrendDirection = "stable"
		}
	}
}

// FormatDuration formats duration in human-readable form
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return "< 1 second"
	}
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		return fmt.Sprintf("%d min %d sec", mins, secs)
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%d hr %d min", hours, mins)
}
