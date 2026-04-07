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
	"Environment":      colorRed,
	"App Token":        colorCyan,
	"FTP Client":       colorYellow,
	"DB Client":        colorYellow,
	"VPN":              colorGreen,
	"Certificate":      colorRed,
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
	if err := OutputJSONWriter(findings, ScanMeta{}, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error encoding JSON: %v\n", err)
	}
}

// OutputJSONWriter writes JSON to any writer.
func OutputJSONWriter(findings []Finding, meta ScanMeta, w *os.File) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{
		"v":       "1.0.0",
		"meta":    meta,
		"count":   len(findings),
		"results": findings,
	})
}

// OutputJSONFile writes findings as JSON to a file.
func OutputJSONFile(findings []Finding, path string) error {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return err
	}
	defer f.Close()
	if err := OutputJSONWriter(findings, ScanMeta{}, f); err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error encoding JSON to %s: %v\n", path, err)
		return err
	}
	fmt.Printf("  \033[32m[+]\033[0m Exported JSON: %s (%d findings)\n", path, len(findings))
	return nil
}

// OutputCSV writes findings as CSV to a file.
func OutputCSV(findings []Finding, path string) error {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return err
	}
	defer f.Close()

	write := func(s string) error {
		_, err := f.WriteString(s)
		return err
	}

	if err := write("Confidence,Category,Type,File,Line,Key,Value\n"); err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return err
	}

	for _, finding := range findings {
		key := csvEscape(finding.Key)
		value := csvEscape(finding.Value)
		file := csvEscape(finding.File)

		line := ""
		if finding.Line > 0 {
			line = fmt.Sprintf("%d", finding.Line)
		}

		if err := write(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s\n",
			finding.Confidence, finding.Category, finding.Type,
			file, line, key, value)); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
			return err
		}
	}

	fmt.Printf("  \033[32m[+]\033[0m Exported CSV: %s (%d findings)\n", path, len(findings))
	return nil
}

// OutputTXT writes findings as a readable text report.
func OutputTXT(findings []Finding, path string) error {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return err
	}
	defer f.Close()

	var firstErr error
	write := func(s string) {
		if firstErr != nil {
			return
		}
		if _, err := f.WriteString(s); err != nil {
			firstErr = err
		}
	}

	confCounts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, finding := range findings {
		confCounts[finding.Confidence]++
	}

	write("================================================================\n")
	write("  SCAN REPORT\n")
	write("================================================================\n\n")
	write(fmt.Sprintf("  Total Findings: %d\n", len(findings)))
	write(fmt.Sprintf("  HIGH: %d | MEDIUM: %d | LOW: %d\n\n", confCounts["HIGH"], confCounts["MEDIUM"], confCounts["LOW"]))
	write("================================================================\n\n")

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
		write(fmt.Sprintf("--- %s (%d) ---\n\n", cat, len(grouped[cat])))
		for _, finding := range grouped[cat] {
			loc := finding.File
			if finding.Line > 0 {
				loc = fmt.Sprintf("%s:%d", finding.File, finding.Line)
			}
			write(fmt.Sprintf("  [%s] %s\n", finding.Confidence, loc))
			write(fmt.Sprintf("    %s = %s\n\n", finding.Key, finding.Value))
		}
	}

	if firstErr != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, firstErr)
		return firstErr
	}
	fmt.Printf("  \033[32m[+]\033[0m Exported TXT: %s (%d findings)\n", path, len(findings))
	return nil
}

// OutputHTML writes a styled HTML report.
func OutputHTML(findings []Finding, meta ScanMeta, path string) error {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, err)
		return err
	}
	defer f.Close()

	var firstErr error
	write := func(s string) {
		if firstErr != nil {
			return
		}
		if _, err := f.WriteString(s); err != nil {
			firstErr = err
		}
	}

	confCounts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, finding := range findings {
		confCounts[finding.Confidence]++
	}

	grouped := make(map[string][]Finding)
	for _, finding := range findings {
		grouped[finding.Category] = append(grouped[finding.Category], finding)
	}
	var cats []string
	for c := range grouped {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Scan Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#e0e7ff;font-family:'Segoe UI',system-ui,sans-serif;padding:20px}
.header{background:linear-gradient(135deg,#1e1b4b,#0f172a);border:1px solid #3730a3;border-radius:12px;padding:24px;text-align:center;margin-bottom:20px}
.header h1{color:#818cf8;font-size:24px}
.header .sub{color:#6366f1;font-size:12px;text-transform:uppercase;letter-spacing:2px;margin-top:4px}
.meta{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:14px;margin-bottom:20px;font-size:12px;color:#9ca3af;display:flex;gap:24px;flex-wrap:wrap}
.meta span{color:#e0e7ff}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:16px;text-align:center}
.stat .val{font-size:28px;font-weight:700}
.stat .lbl{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.high .val{color:#ef4444} .med .val{color:#f59e0b} .low .val{color:#6b7280} .total .val{color:#818cf8}
.cat{background:#111827;border:1px solid #1f2937;border-radius:8px;margin-bottom:12px;overflow:hidden}
.cat-head{padding:12px 16px;border-bottom:1px solid #1f2937;font-weight:600;color:#c7d2fe;font-size:14px}
.finding{padding:10px 16px;border-bottom:1px solid #0f172a;font-size:12px}
.finding:hover{background:rgba(99,102,241,.05)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;margin-right:8px}
.badge-HIGH{background:rgba(239,68,68,.15);color:#ef4444}
.badge-MEDIUM{background:rgba(245,158,11,.15);color:#f59e0b}
.badge-LOW{background:rgba(107,114,128,.15);color:#6b7280}
.file{color:#6b7280;font-size:11px;margin-bottom:2px}
.key{color:#38bdf8;font-weight:600}
.val-text{color:#10b981}
.footer{text-align:center;padding:20px;color:#374151;font-size:11px;margin-top:20px}
</style></head><body>
`)

	write(`<div class="header"><h1>Scan Report</h1><div class="sub">Post-Exploitation Credential Analysis</div></div>`)

	// Metadata
	write(fmt.Sprintf(`<div class="meta">
<div>Host: <span>%s</span></div>
<div>OS: <span>%s</span></div>
<div>User: <span>%s</span></div>
<div>Path: <span>%s</span></div>
<div>Time: <span>%s</span></div>
</div>`, meta.Hostname, meta.OS, meta.User, meta.ScanPath, meta.Timestamp))

	// Stats
	write(fmt.Sprintf(`<div class="stats">
<div class="stat high"><div class="val">%d</div><div class="lbl">High</div></div>
<div class="stat med"><div class="val">%d</div><div class="lbl">Medium</div></div>
<div class="stat low"><div class="val">%d</div><div class="lbl">Low</div></div>
<div class="stat total"><div class="val">%d</div><div class="lbl">Total</div></div>
</div>`, confCounts["HIGH"], confCounts["MEDIUM"], confCounts["LOW"], len(findings)))

	// Findings by category
	for _, cat := range cats {
		write(fmt.Sprintf(`<div class="cat"><div class="cat-head">%s (%d)</div>`, cat, len(grouped[cat])))
		for _, finding := range grouped[cat] {
			loc := finding.File
			if finding.Line > 0 {
				loc = fmt.Sprintf("%s:%d", finding.File, finding.Line)
			}
			write(fmt.Sprintf(`<div class="finding">
<span class="badge badge-%s">%s</span>
<span class="file">%s</span><br>
<span class="key">%s</span> &rarr; <span class="val-text">%s</span>
</div>`, finding.Confidence, finding.Confidence, loc, finding.Key, finding.Value))
		}
		write(`</div>`)
	}

	write(`<div class="footer">Generated by PhantomHarvest</div></body></html>`)

	if firstErr != nil {
		fmt.Fprintf(os.Stderr, "  [-] Error writing %s: %v\n", path, firstErr)
		return firstErr
	}
	fmt.Printf("  \033[32m[+]\033[0m Exported HTML: %s (%d findings)\n", path, len(findings))
	return nil
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
