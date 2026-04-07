package harvest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// absPath returns the absolute version of p, or p unchanged on failure.
// Used so the "Exported …" success line always shows where the file
// actually landed, not whatever relative path the user typed.
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

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

// Column widths for the findings table. Inner content width is the sum
// plus 3 chars (" │ ") between each column plus 2 chars ("│ " / " │") at
// the outer edges — change this together with drawTableBorder/drawRow.
const (
	colConf  = 6  // "HIGH  " / "MEDIUM" / "LOW   "
	colKey   = 28 // credential name / finding key
	colValue = 46 // credential value (the meat)
	colFile  = 36 // file path + :line
)

// tableInner is the visible width of content (all columns + separators).
const tableInner = colConf + 3 + colKey + 3 + colValue + 3 + colFile

// truncRunes trims s to n visible runes, adding an ellipsis if cut.
// We count runes rather than bytes so multibyte characters don't blow
// column alignment.
func truncRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	if n <= 1 {
		return string(rs[:n])
	}
	return string(rs[:n-1]) + "…"
}

// padRunes right-pads s with spaces so it has exactly n visible runes.
func padRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(rs))
}

// cell renders a table cell: truncate to width, pad to width, wrap in
// color codes. The ANSI escapes are added *after* padding so that
// sprintf-style width formatting lines up correctly.
func cell(s string, width int, color string) string {
	s = truncRunes(s, width)
	s = padRunes(s, width)
	return color + s + colorReset
}

// border produces a full horizontal rule with column separators at the
// right positions. `left`, `mid`, `right` pick the corner characters;
// pass "├", "┼", "┤" for a cross-row separator or "╭", "┬", "╮" for a
// top rule with columns.
func border(left, fill, mid, right string, widths ...int) string {
	var b strings.Builder
	b.WriteString(colorDim)
	b.WriteString(left)
	for i, w := range widths {
		b.WriteString(strings.Repeat(fill, w+2))
		if i < len(widths)-1 {
			b.WriteString(mid)
		}
	}
	b.WriteString(right)
	b.WriteString(colorReset)
	return b.String()
}

// catHeader draws the titled top rule of a category block, like:
//
//	╭─ Browser (2822 findings) ───────────────────...───╮
func catHeader(cat string, count int, catColor string) string {
	title := fmt.Sprintf(" %s%s%s (%d findings) ", catColor, cat, colorReset, count)
	// Visible width of the title (without ANSI).
	visible := len(cat) + len(fmt.Sprintf(" (%d findings) ", count))
	// tableInner + 2 (outer " "s) = full inner width of the box.
	total := tableInner + 2
	dashes := total - visible - 3 // minus ╭─ and ╮
	if dashes < 0 {
		dashes = 0
	}
	return fmt.Sprintf("%s%s─%s%s%s%s%s",
		colorDim, "╭", colorReset,
		title,
		colorDim, strings.Repeat("─", dashes)+"╮", colorReset)
}

// catFooter closes a category block.
func catFooter() string {
	total := tableInner + 2
	return colorDim + "╰" + strings.Repeat("─", total-2) + "╯" + colorReset
}

// cleanOneLine flattens any embedded newlines/tabs/control chars into
// single spaces so a single finding never blows up the box alignment.
// Also collapses runs of whitespace.
func cleanOneLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		if r == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// row formats one finding as a table row.
func row(f Finding) string {
	confColor := confColors[f.Confidence]
	if confColor == "" {
		confColor = colorDim
	}

	// Pick the value color. Highest-confidence real creds are bold red;
	// hashes yellow; everything else green so the colour guides the eye
	// straight to the dangerous ones.
	valueColor := colorGreen
	if f.Category == "Hash" {
		valueColor = colorYellow
	}
	if f.Confidence == "HIGH" || strings.Contains(f.Value, "UNENCRYPTED") {
		valueColor = colorBold + colorRed
	} else if f.Confidence == "MEDIUM" {
		valueColor = colorYellow
	} else {
		valueColor = colorDim
	}

	// Build the file-location string (path + optional :line, trimmed to
	// show the tail of the path which is the identifying part).
	loc := f.File
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", loc, f.Line)
	}
	if rs := []rune(loc); len(rs) > colFile {
		loc = "…" + string(rs[len(rs)-colFile+1:])
	}

	bar := colorDim + "│" + colorReset
	return fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
		bar, cell(cleanOneLine(f.Confidence), colConf, colorBold+confColor),
		bar, cell(cleanOneLine(f.Key), colKey, colorCyan),
		bar, cell(cleanOneLine(f.Value), colValue, valueColor),
		bar, cell(cleanOneLine(loc), colFile, colorDim),
		bar)
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

	// Print one bordered table per category. Inside each table, sort so
	// HIGH confidence rows come first — the user should see the
	// dangerous stuff at the top of each block.
	confRank := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2}
	for _, cat := range cats {
		catColor := catColors[cat]
		if catColor == "" {
			catColor = colorDim
		}
		rows := grouped[cat]
		sort.SliceStable(rows, func(i, j int) bool {
			return confRank[rows[i].Confidence] < confRank[rows[j].Confidence]
		})

		fmt.Println()
		fmt.Println("  " + catHeader(cat, len(rows), catColor+colorBold))
		// Column-header row.
		fmt.Println("  " + row(Finding{
			Confidence: "CONF",
			Key:        "KEY",
			Value:      "VALUE",
			File:       "LOCATION",
		}))
		fmt.Println("  " + border("├", "─", "┼", "┤", colConf, colKey, colValue, colFile))
		for _, f := range rows {
			fmt.Println("  " + row(f))
		}
		fmt.Println("  " + catFooter())
	}

	// Print the final SCAN SUMMARY block. Uses the same bordered style
	// as the per-category tables so the whole report looks consistent.
	// The summary is a single-column table whose cell width equals the
	// full inner content width of a category row (so borders line up).
	summaryInner := tableInner // full content width, no column splits

	fmt.Println()
	// Top rule with title.
	title := fmt.Sprintf(" %sSCAN SUMMARY%s ", colorBold+colorPurple, colorReset)
	visible := len(" SCAN SUMMARY ")
	dashes := summaryInner + 2 - visible - 3
	if dashes < 0 {
		dashes = 0
	}
	fmt.Printf("  %s╭─%s%s%s%s%s\n",
		colorDim, colorReset, title,
		colorDim, strings.Repeat("─", dashes)+"╮", colorReset)

	// Stat row. Build the text without colour, measure its rune length
	// for padding, then inject colour around the numbers.
	bar := colorDim + "│" + colorReset
	plainStat := fmt.Sprintf("  HIGH: %-4d   MEDIUM: %-4d   LOW: %-4d   TOTAL: %-4d",
		confCounts["HIGH"], confCounts["MEDIUM"], confCounts["LOW"], len(findings))
	coloredStat := fmt.Sprintf("  %sHIGH%s: %s%-4d%s   %sMEDIUM%s: %s%-4d%s   %sLOW%s: %s%-4d%s   %sTOTAL%s: %s%-4d%s",
		colorBold+colorRed, colorReset, colorRed, confCounts["HIGH"], colorReset,
		colorBold+colorYellow, colorReset, colorYellow, confCounts["MEDIUM"], colorReset,
		colorBold+colorDim, colorReset, colorDim, confCounts["LOW"], colorReset,
		colorBold, colorReset, colorBold, len(findings), colorReset)
	pad := summaryInner - len([]rune(plainStat))
	if pad < 0 {
		pad = 0
	}
	fmt.Printf("  %s %s%s %s\n", bar, coloredStat, strings.Repeat(" ", pad), bar)

	// Mid rule.
	fmt.Println("  " + colorDim + "├" + strings.Repeat("─", summaryInner+2) + "┤" + colorReset)

	// Per-category tally rows.
	for _, cat := range cats {
		color := catColors[cat]
		if color == "" {
			color = colorDim
		}
		plain := fmt.Sprintf("  %-24s  %4d findings", cat, len(grouped[cat]))
		colored := fmt.Sprintf("  %s%-24s%s  %s%4d findings%s",
			color+colorBold, cat, colorReset,
			color, len(grouped[cat]), colorReset)
		pad := summaryInner - len([]rune(plain))
		if pad < 0 {
			pad = 0
		}
		fmt.Printf("  %s %s%s %s\n", bar, colored, strings.Repeat(" ", pad), bar)
	}

	// Bottom rule.
	fmt.Println("  " + colorDim + "╰" + strings.Repeat("─", summaryInner+2) + "╯" + colorReset)
	fmt.Println()
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
	fmt.Printf("  \033[32m[+]\033[0m Exported JSON: %s (%d findings)\n", absPath(path), len(findings))
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

	fmt.Printf("  \033[32m[+]\033[0m Exported CSV: %s (%d findings)\n", absPath(path), len(findings))
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
	fmt.Printf("  \033[32m[+]\033[0m Exported TXT: %s (%d findings)\n", absPath(path), len(findings))
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
	fmt.Printf("  \033[32m[+]\033[0m Exported HTML: %s (%d findings)\n", absPath(path), len(findings))
	return nil
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
