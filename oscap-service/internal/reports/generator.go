package reports

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

// ReportGenerator handles report generation
type ReportGenerator struct {
	template *template.Template
}

// TemplateData holds all data for the HTML template
type TemplateData struct {
	// Basic info
	ReportID         string
	GeneratedAt      string
	
	// Node info
	NodeName         string
	NodeHost         string
	NodeOS           string
	
	// Profile info
	ProfileID        string
	ProfileTitle     string
	
	// Scan info
	ScanID           int
	ScanDate         string
	Duration         string
	
	// Scores
	ScorePercent     float64
	ComplianceStatus string
	StatusColor      string
	
	// Counts
	TotalRules       int
	PassedRules      int
	FailedRules      int
	ErrorRules       int
	NotApplicable    int
	NotChecked       int
	NotSelected      int
	Informational    int
	
	// Severity
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	UnknownCount     int
	
	// Severity percentages (for bar widths)
	CriticalPercent  float64
	HighPercent      float64
	MediumPercent    float64
	LowPercent       float64
	
	// Risk
	RiskScore        int
	RiskLevel        string
	RiskLevelLower   string
	
	// Rule details (comprehensive)
	FailedRuleDetails  []RuleDetail
	PassedRuleDetails  []RuleDetail
	OtherRuleDetails   []RuleDetail
	AllRuleDetails     []RuleDetail
	
	// Trend data
	HasTrend  bool
	TrendData []TrendPoint
}

// TrendPoint represents a single point in the trend chart
type TrendPoint struct {
	Date   string
	Score  float64
	Height float64 // Percentage for bar height
}

// NewReportGenerator creates a new generator with loaded templates
func NewReportGenerator() (*ReportGenerator, error) {
	// Create template with custom functions
	funcMap := template.FuncMap{
		"subtract": func(a, b int) int { return a - b },
		"printf":   fmt.Sprintf,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
		"add":      func(a, b int) int { return a + b },
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "N/A"
			}
			return t.Format("2006-01-02 15:04:05")
		},
	}
	
	tmpl, err := template.New("report.html").Funcs(funcMap).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}
	
	return &ReportGenerator{
		template: tmpl,
	}, nil
}

// GenerateHTML generates an HTML report from parsed data
func (g *ReportGenerator) GenerateHTML(report *ParsedReport, outputPath string) error {
	// Prepare template data
	data := g.prepareTemplateData(report)
	
	// Execute template
	var buf bytes.Buffer
	if err := g.template.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Write file
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}
	
	return nil
}

// GeneratePDF generates a PDF from the HTML report
func (g *ReportGenerator) GeneratePDF(htmlPath, pdfPath string) error {
	// Try wkhtmltopdf first (most common)
	if _, err := exec.LookPath("wkhtmltopdf"); err == nil {
		cmd := exec.Command("wkhtmltopdf",
			"--enable-local-file-access",
			"--page-size", "A4",
			"--margin-top", "10mm",
			"--margin-bottom", "10mm",
			"--margin-left", "10mm",
			"--margin-right", "10mm",
			"--print-media-type",
			"--no-stop-slow-scripts",
			"--javascript-delay", "1000",
			htmlPath, pdfPath)
		
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("wkhtmltopdf failed: %w (output: %s)", err, string(output))
		}
		return nil
	}
	
	// Try chromium/chrome headless
	chromePaths := []string{
		"chromium-browser",
		"chromium",
		"google-chrome",
		"google-chrome-stable",
	}
	
	for _, chromePath := range chromePaths {
		if _, err := exec.LookPath(chromePath); err == nil {
			cmd := exec.Command(chromePath,
				"--headless",
				"--disable-gpu",
				"--no-sandbox",
				"--print-to-pdf="+pdfPath,
				"--print-to-pdf-no-header",
				htmlPath)
			
			output, err := cmd.CombinedOutput()
			if err != nil {
				continue // Try next browser
			}
			_ = output
			return nil
		}
	}
	
	return fmt.Errorf("no PDF converter found. Install wkhtmltopdf: sudo apt install wkhtmltopdf")
}

// GenerateReport generates both HTML and optionally PDF
func (g *ReportGenerator) GenerateReport(report *ParsedReport, basePath string, generatePDF bool) (htmlPath, pdfPath string, err error) {
	// Generate unique filename
	timestamp := time.Now().Format("20060102_150405")
	baseName := fmt.Sprintf("compliance_report_%s_%s", report.NodeName, timestamp)
	
	htmlPath = filepath.Join(basePath, baseName+".html")
	
	// Generate HTML
	if err := g.GenerateHTML(report, htmlPath); err != nil {
		return "", "", fmt.Errorf("failed to generate HTML: %w", err)
	}
	
	// Generate PDF if requested
	if generatePDF {
		pdfPath = filepath.Join(basePath, baseName+".pdf")
		if err := g.GeneratePDF(htmlPath, pdfPath); err != nil {
			// PDF generation failed but HTML is still available
			return htmlPath, "", err
		}
	}
	
	return htmlPath, pdfPath, nil
}

// prepareTemplateData converts ParsedReport to TemplateData
func (g *ReportGenerator) prepareTemplateData(report *ParsedReport) *TemplateData {
	data := &TemplateData{
		ReportID:         fmt.Sprintf("RPT-%d-%s", report.ScanID, time.Now().Format("20060102150405")),
		GeneratedAt:      time.Now().Format("January 2, 2006 at 15:04:05 MST"),
		
		NodeName:         report.NodeName,
		NodeHost:         report.NodeHost,
		NodeOS:           report.NodeOS,
		
		ProfileID:        report.ProfileID,
		ProfileTitle:     report.ProfileTitle,
		
		ScanID:           report.ScanID,
		ScanDate:         report.ScanTime.Format("January 2, 2006 at 15:04:05"),
		Duration:         FormatDuration(report.Duration),
		
		ScorePercent:     report.ScorePercent,
		ComplianceStatus: report.GetComplianceStatus(),
		StatusColor:      report.GetStatusColor(),
		
		TotalRules:       report.TotalRules,
		PassedRules:      report.PassedRules,
		FailedRules:      report.FailedRules,
		ErrorRules:       report.ErrorRules,
		NotApplicable:    report.NotApplicable,
		NotChecked:       report.NotChecked,
		NotSelected:      report.NotSelected,
		Informational:    report.Informational,
		
		CriticalCount:    report.CriticalCount,
		HighCount:        report.HighCount,
		MediumCount:      report.MediumCount,
		LowCount:         report.LowCount,
		UnknownCount:     report.UnknownCount,
		
		RiskScore:        report.RiskScore,
		RiskLevel:        report.RiskLevel,
		RiskLevelLower:   strings.ToLower(report.RiskLevel),
		
		FailedRuleDetails: report.FailedRuleDetails,
		PassedRuleDetails: report.PassedRuleDetails,
		OtherRuleDetails:  report.OtherRuleDetails,
		AllRuleDetails:    report.AllRuleDetails,
	}
	
	// Calculate severity percentages
	maxSeverity := max(report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)
	if maxSeverity > 0 {
		data.CriticalPercent = float64(report.CriticalCount) / float64(maxSeverity) * 100
		data.HighPercent = float64(report.HighCount) / float64(maxSeverity) * 100
		data.MediumPercent = float64(report.MediumCount) / float64(maxSeverity) * 100
		data.LowPercent = float64(report.LowCount) / float64(maxSeverity) * 100
	}
	
	// Prepare trend data
	if len(report.PreviousScans) > 1 {
		data.HasTrend = true
		data.TrendData = make([]TrendPoint, 0, len(report.PreviousScans))
		
		// Find max score for height calculation
		maxScore := 0.0
		for _, scan := range report.PreviousScans {
			if scan.Score > maxScore {
				maxScore = scan.Score
			}
		}
		
		// Reverse order (oldest first for chart)
		for i := len(report.PreviousScans) - 1; i >= 0; i-- {
			scan := report.PreviousScans[i]
			height := 20.0 // Minimum height
			if maxScore > 0 {
				height = (scan.Score / maxScore) * 100
				if height < 20 {
					height = 20
				}
			}
			
			data.TrendData = append(data.TrendData, TrendPoint{
				Date:   scan.ScanTime.Format("Jan 2"),
				Score:  scan.Score,
				Height: height,
			})
		}
	}
	
	// Sort failed rules by severity
	report.SortFailedRulesBySeverity()
	data.FailedRuleDetails = report.FailedRuleDetails
	
	return data
}

// max returns the maximum of integers
func max(nums ...int) int {
	if len(nums) == 0 {
		return 0
	}
	m := nums[0]
	for _, n := range nums[1:] {
		if n > m {
			m = n
		}
	}
	return m
}

// GenerateHTMLString generates HTML as a string (for remote transfer)
func (g *ReportGenerator) GenerateHTMLString(report *ParsedReport) (string, error) {
	data := g.prepareTemplateData(report)
	
	var buf bytes.Buffer
	if err := g.template.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	
	return buf.String(), nil
}
