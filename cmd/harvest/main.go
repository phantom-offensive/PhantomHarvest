package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/phantom-offensive/PhantomHarvest/internal/harvest"
)

var version = "1.0.0"

func main() {
	rootDir := flag.String("path", "/", "Root directory to scan")
	outputJSON := flag.Bool("json", false, "Output as JSON")
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
	fmt.Print("\033[35m")
	fmt.Println(`
    ╔═══════════════════════════════════════╗
    ║   PhantomHarvest — Credential Reaper  ║
    ║   v` + version + `                             ║
    ╚═══════════════════════════════════════╝`)
	fmt.Print("\033[0m")
	fmt.Printf("  OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()
}
