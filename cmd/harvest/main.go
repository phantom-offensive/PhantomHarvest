package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/phantom-offensive/PhantomHarvest/internal/decrypt"
	"github.com/phantom-offensive/PhantomHarvest/internal/harvest"
	"github.com/phantom-offensive/PhantomHarvest/internal/obfuscate"
)

var version = "1.0.0"

func main() {
	rootDir := flag.String("path", "/", "Root directory to scan")
	outputJSON := flag.Bool("json", false, "Output as JSON")
	outputCSV := flag.String("csv", "", "Export to CSV file (e.g. -csv loot.csv)")
	outputTXT := flag.String("txt", "", "Export to TXT file (e.g. -txt loot.txt)")
	outputHTML := flag.String("html", "", "Export to HTML report (e.g. -html report.html)")
	outputFile := flag.String("o", "", "Export to file (auto-detect: .json, .csv, .txt, .html)")
	quiet := flag.Bool("quiet", false, "Only show found credentials (no banner)")
	highOnly := flag.Bool("high-only", false, "Only show HIGH confidence findings")
	maxDepth := flag.Int("depth", 20, "Maximum directory depth")
	exclude := flag.String("exclude", "", "Comma-separated paths to exclude (e.g. TikTok,Discord)")
	decryptBrowsers := flag.Bool("decrypt-browsers", false, "Inline-decrypt browser passwords/cookies/cards (requires -tags decrypt build)")
	flag.Parse()

	if !*quiet {
		printBanner()
	}

	scanner := harvest.NewScanner(*rootDir, *maxDepth)
	if *exclude != "" {
		scanner.AddExcludes(strings.Split(*exclude, ","))
	}
	if *decryptBrowsers {
		if !decrypt.Enabled() {
			fmt.Fprintln(os.Stderr, "[!] Decryption support not compiled in. Rebuild with: make build-full")
		}
		scanner.DecryptBrowsers = true
	}
	results := scanner.Run()

	if *highOnly {
		var filtered []harvest.Finding
		for _, f := range results {
			if f.Confidence == harvest.ConfHigh {
				filtered = append(filtered, f)
			}
		}
		results = filtered
	}

	// Determine output file from -o flag (auto-detect format)
	if *outputFile != "" {
		lower := strings.ToLower(*outputFile)
		if strings.HasSuffix(lower, ".csv") {
			*outputCSV = *outputFile
		} else if strings.HasSuffix(lower, ".txt") {
			*outputTXT = *outputFile
		} else if strings.HasSuffix(lower, ".html") {
			harvest.OutputHTML(results, scanner.Meta, *outputFile)
			harvest.OutputTable(results)
			if len(results) == 0 {
				fmt.Fprintln(os.Stderr, "[*] Scan complete. 0 findings.")
			}
			return
		} else {
			harvest.OutputJSONFile(results, *outputFile)
			harvest.OutputTable(results)
			if len(results) == 0 {
				fmt.Fprintln(os.Stderr, "[*] Scan complete. 0 findings.")
			}
			return
		}
	}

	// Export to CSV
	if *outputCSV != "" {
		harvest.OutputCSV(results, *outputCSV)
	}

	// Export to TXT
	if *outputTXT != "" {
		harvest.OutputTXT(results, *outputTXT)
	}

	// Export to HTML
	if *outputHTML != "" {
		harvest.OutputHTML(results, scanner.Meta, *outputHTML)
	}

	// Terminal output
	if *outputJSON {
		harvest.OutputJSON(results)
	} else {
		harvest.OutputTable(results)
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "[*] Scan complete. 0 findings.")
	}
}

func printBanner() {
	name := obfuscate.BannerName()
	sub := obfuscate.BannerSub()
	fmt.Print("\033[35m")
	fmt.Printf(`
    ╔═══════════════════════════════════════╗
    ║   %s — %s  ║
    ║   v%s                             ║
    ╚═══════════════════════════════════════╝`, name, sub, version)
	fmt.Print("\033[0m\n")
	fmt.Printf("  OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()
}
