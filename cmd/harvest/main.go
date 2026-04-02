package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/phantom-offensive/PhantomHarvest/internal/harvest"
	"github.com/phantom-offensive/PhantomHarvest/internal/obfuscate"
)

var version = "1.0.0"

func main() {
	rootDir := flag.String("path", "/", "Root directory to scan")
	outputJSON := flag.Bool("json", false, "Output as JSON")
	outputCSV := flag.String("csv", "", "Export to CSV file (e.g. -csv loot.csv)")
	outputTXT := flag.String("txt", "", "Export to TXT file (e.g. -txt loot.txt)")
	outputFile := flag.String("o", "", "Export to file (auto-detect format by extension: .json, .csv, .txt)")
	quiet := flag.Bool("quiet", false, "Only show found credentials (no banner)")
	highOnly := flag.Bool("high-only", false, "Only show HIGH confidence findings")
	maxDepth := flag.Int("depth", 20, "Maximum directory depth")
	exclude := flag.String("exclude", "", "Comma-separated paths to exclude (e.g. TikTok,Discord)")
	flag.Parse()

	if !*quiet {
		printBanner()
	}

	scanner := harvest.NewScanner(*rootDir, *maxDepth)
	if *exclude != "" {
		scanner.AddExcludes(strings.Split(*exclude, ","))
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
		} else {
			// Default to JSON for any other extension
			harvest.OutputJSONFile(results, *outputFile)
			harvest.OutputTable(results)
			if len(results) == 0 {
				os.Exit(1)
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

	// Terminal output
	if *outputJSON {
		harvest.OutputJSON(results)
	} else {
		harvest.OutputTable(results)
	}

	if len(results) == 0 {
		os.Exit(1)
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
