package main

import (
	"fmt"
	"strings"
)

// ANSI Color Codes - HPE Theme (Green/Teal accent)
const (
	Reset     = "\033[0m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Purple    = "\033[35m"
	Cyan      = "\033[36m"
	Gray      = "\033[90m"
	White     = "\033[97m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	
	// HPE Brand Colors
	HPEGreen  = "\033[38;5;36m"  // Teal/Green accent
	HPEGreen2 = "\033[38;5;42m"  // Brighter green
	DarkGray  = "\033[38;5;240m"
	LightGray = "\033[38;5;250m"
)

// Box drawing characters
const (
	BoxHorizontal = "─"
	BoxVertical   = "│"
	BoxTopLeft    = "┌"
	BoxTopRight   = "┐"
	BoxBottomLeft = "└"
	BoxBottomRight= "┘"
	BoxTeeLeft    = "├"
	BoxTeeRight   = "┤"
)

// PrintBanner displays the HPE ScapRun ASCII art banner
func PrintBanner() {
	// HPE-styled banner with green accent
	banner := `
` + HPEGreen + Bold + `
██╗  ██╗██████╗ ███████╗    ███████╗ ██████╗ █████╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗
██║  ██║██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║   ██║████╗  ██║
███████║██████╔╝█████╗      ███████╗██║     ███████║██████╔╝██████╔╝██║   ██║██╔██╗ ██║
██╔══██║██╔═══╝ ██╔══╝      ╚════██║██║     ██╔══██║██╔═══╝ ██╔══██╗██║   ██║██║╚██╗██║
██║  ██║██║     ███████╗    ███████║╚██████╗██║  ██║██║     ██║  ██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝     ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝` + Reset + `

` + White + `                     =[ ` + HPEGreen + `OpenSCAP Compliance & Remediation Framework` + White + ` ]=` + Reset + `
` + DarkGray + `          + -- --=[ ` + White + `Profiles: Dynamic` + DarkGray + ` - ` + White + `Targets: Local/Remote` + DarkGray + ` ]=-- -- +` + Reset + `

` + Yellow + `  [!]` + White + ` Enterprise Security Compliance Tool` + Reset + `
`
	fmt.Print(banner)
}

// PrintMainMenu displays the categorized main menu
func PrintMainMenu() {
	width := 60
	
	// Target Management Section
	printMenuSection("TARGET MANAGEMENT", width)
	printMenuItem("1", "target", "Select Target Node")
	printMenuItem("2", "install", "Install OpenSCAP on Target")
	printMenuSectionEnd(width)
	
	// Compliance Operations Section
	printMenuSection("COMPLIANCE OPERATIONS", width)
	printMenuItem("3", "profile", "Select Compliance Profile")
	printMenuItem("4", "scan", "Run Compliance Scan")
	printMenuItem("5", "status", "View Current Status")
	printMenuSectionEnd(width)
	
	// Remediation Section
	printMenuSection("REMEDIATION", width)
	printMenuItem("6", "remediate", "Auto-Remediate Failed Rules")
	printMenuItem("7", "rollback", "Rollback to Checkpoint")
	printMenuSectionEnd(width)
	
	// Core Commands Section
	printMenuSection("CORE COMMANDS", width)
	printMenuItem("8", "reports", "Download Reports")
	printMenuItem("9", "clear", "Clear Screen")
	printMenuItem("0", "exit", "Exit Framework")
	printMenuSectionEnd(width)
	
	fmt.Println()
}

// printMenuSection prints a section header with box drawing
func printMenuSection(title string, width int) {
	padding := (width - len(title) - 2) / 2
	fmt.Printf("\n%s%s%s%s%s\n", 
		DarkGray, BoxTopLeft, strings.Repeat(BoxHorizontal, width-2), BoxTopRight, Reset)
	fmt.Printf("%s%s%s%s%s%s%s\n",
		DarkGray, BoxVertical, Reset,
		strings.Repeat(" ", padding) + HPEGreen + Bold + title + Reset + strings.Repeat(" ", width-2-padding-len(title)),
		DarkGray, BoxVertical, Reset)
	fmt.Printf("%s%s%s%s%s\n",
		DarkGray, BoxTeeLeft, strings.Repeat(BoxHorizontal, width-2), BoxTeeRight, Reset)
}

// printMenuSectionEnd prints the bottom of a menu section
func printMenuSectionEnd(width int) {
	fmt.Printf("%s%s%s%s%s\n",
		DarkGray, BoxBottomLeft, strings.Repeat(BoxHorizontal, width-2), BoxBottomRight, Reset)
}

// printMenuItem prints a single menu item
func printMenuItem(num, cmd, desc string) {
	fmt.Printf("%s%s%s  %s[%s]%s %-12s %s- %s%s\n",
		DarkGray, BoxVertical, Reset,
		HPEGreen, num, Reset,
		Bold + cmd + Reset,
		DarkGray, White + desc, Reset)
}

// PrintPrompt displays the command prompt
func PrintPrompt(context string) {
	if context != "" {
		fmt.Printf("\n%shpe%s %s(%s)%s > ", HPEGreen+Bold, Reset, Red, context, Reset)
	} else {
		fmt.Printf("\n%shpe%s scaprun%s(%s*%s)%s > ", HPEGreen+Bold, Reset, White, Red, White, Reset)
	}
}

// PrintStatusTable prints a status table like in the reference
func PrintStatusTable(headers []string, rows [][]string) {
	// Calculate column widths
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}
	
	// Print headers
	fmt.Println()
	for i, h := range headers {
		fmt.Printf("%s%-*s%s  ", Bold+White, colWidths[i], h, Reset)
	}
	fmt.Println()
	
	// Print separator
	for _, w := range colWidths {
		fmt.Printf("%s%s%s  ", DarkGray, strings.Repeat("─", w), Reset)
	}
	fmt.Println()
	
	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			color := White
			// Color code based on content
			cellLower := strings.ToLower(cell)
			if strings.Contains(cellLower, "active") || strings.Contains(cellLower, "pass") || 
			   strings.Contains(cellLower, "compliant") || strings.Contains(cellLower, "success") ||
			   strings.Contains(cellLower, "connected") {
				color = Green
			} else if strings.Contains(cellLower, "fail") || strings.Contains(cellLower, "error") ||
			          strings.Contains(cellLower, "non_compliant") || strings.Contains(cellLower, "critical") {
				color = Red
			} else if strings.Contains(cellLower, "partial") || strings.Contains(cellLower, "warning") ||
			          strings.Contains(cellLower, "medium") {
				color = Yellow
			}
			if i < len(colWidths) {
				fmt.Printf("%s%-*s%s  ", color, colWidths[i], cell, Reset)
			}
		}
		fmt.Println()
	}
}

// Helper functions for colored output
func PrintInfo(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[*]%s %s\n", Blue, Reset, msg)
}

func PrintSuccess(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[+]%s %s\n", Green, Reset, msg)
}

func PrintError(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[-]%s %s\n", Red, Reset, msg)
}

func PrintWarning(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[!]%s %s\n", Yellow, Reset, msg)
}

func PrintSection(title string) {
	width := 60
	padding := (width - len(title) - 4) / 2
	fmt.Printf("\n%s%s %s%s%s %s%s\n",
		DarkGray, strings.Repeat("─", padding),
		HPEGreen + Bold, strings.ToUpper(title), Reset,
		DarkGray, strings.Repeat("─", width-padding-len(title)-4) + Reset)
}

func PrintKeyValue(key, value string) {
	fmt.Printf("   %s%-15s%s : %s%s%s\n", HPEGreen, key, Reset, White, value, Reset)
}

// PrintBox prints content inside a box
func PrintBox(title string, lines []string) {
	width := 58
	
	// Top border with title
	titlePadding := (width - len(title) - 4) / 2
	fmt.Printf("%s%s%s%s%s%s%s\n",
		DarkGray, BoxTopLeft, strings.Repeat(BoxHorizontal, titlePadding),
		HPEGreen + " " + title + " " + Reset,
		DarkGray, strings.Repeat(BoxHorizontal, width-titlePadding-len(title)-4), BoxTopRight + Reset)
	
	// Content lines
	for _, line := range lines {
		displayLen := len(line)
		// Account for ANSI codes in padding calculation
		padding := width - 2 - displayLen
		if padding < 0 {
			padding = 0
		}
		fmt.Printf("%s%s%s %s%s%s%s\n",
			DarkGray, BoxVertical, Reset,
			line, strings.Repeat(" ", padding),
			DarkGray, BoxVertical + Reset)
	}
	
	// Bottom border
	fmt.Printf("%s%s%s%s%s\n",
		DarkGray, BoxBottomLeft, strings.Repeat(BoxHorizontal, width-2), BoxBottomRight, Reset)
}

// ClearScreen clears the terminal
func ClearScreen() {
	fmt.Print("\033[2J\033[H")
}
