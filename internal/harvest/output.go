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
	fmt.Printf("  %s║  HARVEST SUMMARY                                          ║%s\n", colorPurple, colorReset)
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

// OutputJSON prints findings as JSON.
func OutputJSON(findings []Finding) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]interface{}{
		"tool":     "PhantomHarvest",
		"version":  "1.0.0",
		"count":    len(findings),
		"findings": findings,
	})
}
