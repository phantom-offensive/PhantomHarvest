package harvest

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
)

// Category colors
var catColors = map[string]string{
	"Auth":      colorRed,
	"Database":  colorYellow,
	"Cloud":     colorCyan,
	"SSH":       colorGreen,
	"Git":       colorPurple,
	"API":       colorBlue,
	"History":   colorDim,
	"Web App":   colorRed,
	"Container": colorCyan,
	"IaC":       colorYellow,
	"CI/CD":     colorPurple,
	"System":    colorRed,
	"Mail":      colorBlue,
	"Hash":             colorYellow,
	"Config":           colorDim,
	"File Scan":        colorDim,
	"Browser":          colorCyan,
	"Password Manager": colorRed,
	"WiFi":             colorGreen,
	"RDP":              colorYellow,
	"DPAPI":            colorRed,
	"Windows":          colorBlue,
	"Crypto":           colorPurple,
}

var confColors = map[string]string{
	"HIGH":   colorRed,
	"MEDIUM": colorYellow,
	"LOW":    colorDim,
}

// OutputTable prints findings as a formatted terminal table.
func OutputTable(findings []Finding) {
	if len(findings) == 0 {
		fmt.Printf("  %s[-]%s No credentials found.\n", colorRed, colorReset)
		return
	}

	// Group by category
	grouped := make(map[string][]Finding)
	for _, f := range findings {
		grouped[f.Category] = append(grouped[f.Category], f)
	}

	// Sort categories
	var cats []string
	for c := range grouped {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	// Count by confidence
	confCounts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range findings {
		confCounts[f.Confidence]++
	}

	// Print summary
	fmt.Printf("  %s╔═══════════════════════════════════════════════════════════╗%s\n", colorPurple, colorReset)
	fmt.Printf("  %s║  SCAN SUMMARY                                             ║%s\n", colorPurple, colorReset)
	fmt.Printf("  %s╠═══════════════════════════════════════════════════════════╣%s\n", colorPurple, colorReset)
	fmt.Printf("  %s║%s  %sHIGH%s: %-4d  %sMEDIUM%s: %-4d  %sLOW%s: %-4d  TOTAL: %-4d     %s║%s\n",
		colorPurple, colorReset,
		colorRed, colorReset, confCounts["HIGH"],
		colorYellow, colorReset, confCounts["MEDIUM"],
		colorDim, colorReset, confCounts["LOW"],
		len(findings),
		colorPurple, colorReset)
	fmt.Printf("  %s╠═══════════════════════════════════════════════════════════╣%s\n", colorPurple, colorReset)
	for _, cat := range cats {
		color := catColors[cat]
		if color == "" {
			color = colorDim
		}
		fmt.Printf("  %s║%s  %-20s %s%3d findings%s                          %s║%s\n",
			colorPurple, colorReset, cat, color, len(grouped[cat]), colorReset, colorPurple, colorReset)
	}
	fmt.Printf("  %s╚═══════════════════════════════════════════════════════════╝%s\n\n", colorPurple, colorReset)

	// Print details per category
	for _, cat := range cats {
		color := catColors[cat]
		if color == "" {
			color = colorDim
		}

		fmt.Printf("  %s%s── %s (%d) ──%s\n\n", color, colorBold, cat, len(grouped[cat]), colorReset)

		for _, f := range grouped[cat] {
			// Confidence badge
			confColor := confColors[f.Confidence]
			if confColor == "" {
				confColor = colorDim
			}
			badge := fmt.Sprintf("[%s]", f.Confidence)

			// File path
			fmt.Printf("    %s%-8s%s %s%s%s", confColor, badge, colorReset, colorDim, f.File, colorReset)
			if f.Line > 0 {
				fmt.Printf("%s:%d%s", colorDim, f.Line, colorReset)
			}
			fmt.Println()

			// Key = Value
			displayKey := f.Key
			if len(displayKey) > 40 {
				displayKey = displayKey[:40] + "..."
			}

			valueColor := colorGreen
			if f.Category == "Hash" {
				valueColor = colorYellow
			}
			if strings.Contains(f.Value, "UNENCRYPTED") || f.Confidence == "HIGH" {
				valueColor = colorRed
			}

			fmt.Printf("             %s%-20s%s %s→%s %s%s%s\n\n",
				colorCyan, displayKey, colorReset,
				colorDim, colorReset,
				valueColor, f.Value, colorReset)
		}
	}
}

// OutputJSON prints findings as JSON to stdout.
func OutputJSON(findings []Finding) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]interface{}{
		"v":       "1.0.0",
		"count":   len(findings),
		"results": findings,
	})
}

// OutputJSONFile writes findings as JSON to a file.
func OutputJSONFile(findings []Finding, path string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]interface{}{
		"v":       "1.0.0",
		"count":   len(findings),
		"results": findings,
	})
	fmt.Printf("  \033[32m[+]\033[0m Exported JSON: %s (%d findings)\n", path, len(findings))
}

// OutputCSV writes findings as CSV to a file.
func OutputCSV(findings []Finding, path string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return
	}
	defer f.Close()

	// Header
	f.WriteString("Confidence,Category,Type,File,Line,Key,Value\n")

	for _, finding := range findings {
		// Escape CSV fields
		key := csvEscape(finding.Key)
		value := csvEscape(finding.Value)
		file := csvEscape(finding.File)

		line := ""
		if finding.Line > 0 {
			line = fmt.Sprintf("%d", finding.Line)
		}

		f.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s\n",
			finding.Confidence, finding.Category, finding.Type,
			file, line, key, value))
	}

	fmt.Printf("  \033[32m[+]\033[0m Exported CSV: %s (%d findings)\n", path, len(findings))
}

// OutputTXT writes findings as a readable text report.
func OutputTXT(findings []Finding, path string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return
	}
	defer f.Close()

	// Count by confidence
	confCounts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, finding := range findings {
		confCounts[finding.Confidence]++
	}

	f.WriteString("================================================================\n")
	f.WriteString("  SCAN REPORT\n")
	f.WriteString("================================================================\n\n")
	f.WriteString(fmt.Sprintf("  Total Findings: %d\n", len(findings)))
	f.WriteString(fmt.Sprintf("  HIGH: %d | MEDIUM: %d | LOW: %d\n\n", confCounts["HIGH"], confCounts["MEDIUM"], confCounts["LOW"]))
	f.WriteString("================================================================\n\n")

	// Group by category
	grouped := make(map[string][]Finding)
	for _, finding := range findings {
		grouped[finding.Category] = append(grouped[finding.Category], finding)
	}

	var cats []string
	for c := range grouped {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	for _, cat := range cats {
		f.WriteString(fmt.Sprintf("--- %s (%d) ---\n\n", cat, len(grouped[cat])))
		for _, finding := range grouped[cat] {
			loc := finding.File
			if finding.Line > 0 {
				loc = fmt.Sprintf("%s:%d", finding.File, finding.Line)
			}
			f.WriteString(fmt.Sprintf("  [%s] %s\n", finding.Confidence, loc))
			f.WriteString(fmt.Sprintf("    %s = %s\n\n", finding.Key, finding.Value))
		}
	}

	fmt.Printf("  \033[32m[+]\033[0m Exported TXT: %s (%d findings)\n", path, len(findings))
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
