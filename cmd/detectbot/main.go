package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/heartblast/detect_bot/internal/banner"
	"github.com/heartblast/detect_bot/internal/config"
	"github.com/heartblast/detect_bot/internal/consolelog"
	"github.com/heartblast/detect_bot/internal/input"
	"github.com/heartblast/detect_bot/internal/report"
	"github.com/heartblast/detect_bot/internal/root"
	"github.com/heartblast/detect_bot/internal/rules"
	"github.com/heartblast/detect_bot/internal/scan"
	"github.com/heartblast/detect_bot/internal/systeminfo"
)

// Version and build metadata (set via ldflags when available).
var (
	Version   = "v1.1.3"
	BuildTime = ""
	Commit    = ""
)

func printFlagGroup(title string, names []string) {
	fmt.Fprintf(os.Stderr, "%s:\n", title)
	for _, n := range names {
		if f := flag.Lookup(n); f != nil {
			fmt.Fprintf(os.Stderr, "  --%s\t%s\n", f.Name, f.Usage)
		}
	}
	fmt.Fprintln(os.Stderr)
}

func main() {
	fmt.Fprint(os.Stderr, banner.Get())
	ver := Version
	if ver == "" {
		ver = "unknown"
	}
	fmt.Fprintf(os.Stderr, "Version: %s\n\n", ver)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "NICE INFORMATION SERVICE\n")
		fmt.Fprintf(os.Stderr, "Detect Bot\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		printFlagGroup("INPUT OPTIONS", []string{"server-type", "nginx-dump", "apache-dump", "watch-dir", "config"})
		printFlagGroup("SCAN/DEPTH OPTIONS", []string{"scan", "exclude", "max-depth", "newer-than-h", "workers", "hash", "max-size-mb", "follow-symlink"})
		printFlagGroup("POLICY/RULE OPTIONS", []string{"allow-mime-prefix", "allow-ext", "enable-rules", "disable-rules", "preset"})
		printFlagGroup("CONTENT SCAN OPTIONS", []string{"content-scan", "content-max-bytes", "content-max-size-kb", "content-ext"})
		printFlagGroup("OUTPUT OPTIONS", []string{"out"})
		printFlagGroup("KAFKA OPTIONS", []string{"kafka-enabled", "kafka-brokers", "kafka-topic", "kafka-client-id", "kafka-tls", "kafka-sasl-enabled", "kafka-username", "kafka-password-env", "kafka-mask-sensitive"})
	}

	cfg := config.MustParseFlags()
	logger := consolelog.New(cfg.Output == "-")

	if err := validateInputCombination(cfg); err != nil {
		abort(logger, "invalid input combination", err)
	}

	started := time.Now()
	rep := report.Report{
		ReportVersion: "1.0",
		GeneratedAt:   started.Format(time.RFC3339),
		Host:          systeminfo.GetHostInfo(started),
		Inputs:        []string{},
		Config:        cfg,
	}
	rep.ScanStartedAt = started.Format(time.RFC3339)

	logger.Infof("Scan started at: %s", rep.ScanStartedAt)
	logger.Infof("Host: %s", formatHost(rep.Host))
	logger.Infof("Mode: %s", describeMode(cfg))
	logger.Infof("Output file: %s", formatOutput(cfg.Output))
	if rep.Host.Hostname == "unknown" || rep.Host.PrimaryIP == "" {
		logger.Warnf("Host metadata is partial; continuing with best-effort values")
	}

	roots := make([]root.RootEntry, 0, 32)

	if cfg.NginxDump != "" {
		if cfg.ServerType == "" {
			cfg.ServerType = "nginx"
		}
		logger.Infof("Resolving scan roots from nginx dump...")
		rep.Inputs = append(rep.Inputs, "nginx-dump:"+cfg.NginxDump)
		b, err := input.ReadAllMaybeStdin(cfg.NginxDump)
		if err != nil {
			abort(logger, "failed to parse nginx dump", err)
		}
		roots = append(roots, input.ParseNginxDump(b)...)
	}

	if cfg.ApacheDump != "" {
		if cfg.ServerType == "" {
			cfg.ServerType = "apache"
		}
		logger.Infof("Resolving scan roots from apache dump...")
		rep.Inputs = append(rep.Inputs, "apache-dump:"+cfg.ApacheDump)
		b, err := input.ReadAllMaybeStdin(cfg.ApacheDump)
		if err != nil {
			abort(logger, "failed to parse apache dump", err)
		}
		roots = append(roots, input.ParseApacheDump(b)...)
	}

	if len(cfg.WatchDirs) > 0 {
		logger.Infof("Adding watch-dir targets...")
		for _, d := range cfg.WatchDirs {
			roots = append(roots, root.RootEntry{
				Path:   d,
				Source: root.SourceManual,
			})
		}
	}

	roots = root.NormalizeRoots(roots)
	rep.Roots = roots
	rep.Stats.RootsCount = len(roots)

	if len(roots) == 0 {
		logger.Warnf("No scan roots discovered")
	} else {
		logger.Infof("Targets discovered: %d", len(roots))
	}

	if cfg.Scan {
		ruleSet := makeRuleSet(cfg)
		ruleNames := make([]string, 0, len(ruleSet))
		for _, r := range ruleSet {
			ruleNames = append(ruleNames, r.Name())
		}
		rep.ActiveRules = ruleNames

		logger.Infof("Starting filesystem scan...")
		for _, rt := range roots {
			logger.Infof("Scanning root: %s", rt.Path)
		}

		sc := scan.Scanner{
			Cfg:   cfg,
			Rules: ruleSet,
		}

		findings, scanned := sc.ScanRoots(roots)
		rep.Findings = findings
		rep.Stats.ScannedFiles = scanned
		rep.Stats.FindingsCount = len(findings)
	} else {
		logger.Infof("Scan disabled; reporting discovered roots only")
	}

	if err := report.Write(rep, cfg.Output); err != nil {
		abort(logger, "failed to write report", err)
	}

	if cfg.Kafka.Enabled {
		logger.Infof("Sending summarized event to Kafka...")
		if err := report.SendToKafka(rep, cfg.Kafka); err != nil {
			logger.Warnf("Kafka send failed: %v", err)
		} else {
			logger.Infof("Kafka event sent to: %s", cfg.Kafka.Topic)
		}
	}

	completed := time.Now()
	logger.Infof("Scan completed at: %s", completed.Format(time.RFC3339))
	logger.Infof("Duration: %s", completed.Sub(started).Round(time.Second))
	logger.Infof("Scan roots: %d", rep.Stats.RootsCount)
	logger.Infof("Findings: %d", rep.Stats.FindingsCount)
	logger.Summaryf("%s", formatSummary(rep))
	logger.Infof("Report written to: %s", formatOutput(cfg.Output))
}

func describeMode(cfg config.Config) string {
	parts := make([]string, 0, 4)
	if cfg.NginxDump != "" {
		parts = append(parts, "nginx-dump")
	}
	if cfg.ApacheDump != "" {
		parts = append(parts, "apache-dump")
	}
	if len(cfg.WatchDirs) > 0 {
		parts = append(parts, "watch-dir")
	}
	if cfg.Scan {
		parts = append(parts, "scan")
	} else {
		parts = append(parts, "discover-only")
	}
	if len(parts) == 0 {
		return "scan"
	}
	return strings.Join(parts, " + ")
}

func formatHost(info systeminfo.HostInfo) string {
	hostname := info.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	primaryIP := info.PrimaryIP
	if primaryIP == "" {
		primaryIP = "unknown"
	}
	osType := info.OSType
	if osType == "" {
		osType = "unknown"
	}
	return fmt.Sprintf("%s (%s, %s)", hostname, primaryIP, osType)
}

func formatOutput(out string) string {
	if strings.TrimSpace(out) == "-" {
		return "stdout"
	}
	return out
}

func formatSummary(rep report.Report) string {
	highRisk := 0
	largeFiles := 0
	allowlistViolations := 0

	for _, finding := range rep.Findings {
		for _, reason := range finding.Reasons {
			switch reason {
			case "high_risk_extension":
				highRisk++
			case "large_file", "large_file_in_web_path":
				largeFiles++
			case "mime_not_in_allowlist", "ext_not_in_allowlist":
				allowlistViolations++
			}
		}
	}

	parts := []string{
		fmt.Sprintf("roots=%d", rep.Stats.RootsCount),
		fmt.Sprintf("files_scanned=%d", rep.Stats.ScannedFiles),
		fmt.Sprintf("findings=%d", rep.Stats.FindingsCount),
	}
	if highRisk > 0 {
		parts = append(parts, fmt.Sprintf("high_risk=%d", highRisk))
	}
	if largeFiles > 0 {
		parts = append(parts, fmt.Sprintf("large_files=%d", largeFiles))
	}
	if allowlistViolations > 0 {
		parts = append(parts, fmt.Sprintf("allowlist_violations=%d", allowlistViolations))
	}
	return strings.Join(parts, " ")
}

func lowerSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

func validateInputCombination(cfg config.Config) error {
	if cfg.ServerType == "" {
		return nil
	}
	switch cfg.ServerType {
	case "nginx":
		if cfg.NginxDump == "" {
			return fmt.Errorf("server-type nginx requires --nginx-dump to be provided")
		}
		if cfg.ApacheDump != "" {
			return fmt.Errorf("server-type nginx cannot be used with --apache-dump")
		}
	case "apache":
		if cfg.ApacheDump == "" {
			return fmt.Errorf("server-type apache requires --apache-dump to be provided")
		}
		if cfg.NginxDump != "" {
			return fmt.Errorf("server-type apache cannot be used with --nginx-dump")
		}
	case "manual":
		if len(cfg.WatchDirs) == 0 {
			return fmt.Errorf("server-type manual requires at least one --watch-dir")
		}
	default:
		return fmt.Errorf("unknown server-type '%s'", cfg.ServerType)
	}
	return nil
}

func makeRuleSet(cfg config.Config) []rules.Rule {
	allowExt := map[string]bool{}
	for _, e := range cfg.AllowExt {
		allowExt[strings.ToLower(strings.TrimSpace(e))] = true
	}

	rulesList := []rules.Rule{
		&rules.AllowlistRule{
			AllowMimePrefixes: lowerSlice(cfg.AllowMimePref),
			AllowExt:          allowExt,
		},
		&rules.HighRiskExtRule{HighRisk: defaultHighRiskExt()},
		&rules.LargeFileRule{ThresholdBytes: 50 * 1024 * 1024},
		&rules.ExtMimeMismatchRule{},
	}

	if cfg.ContentScan {
		re := &rules.SecretPatternsRule{
			EnablePatterns: cfg.ContentScan,
			MaxSampleSize:  cfg.ContentMaxBytes,
			ContentExts:    make(map[string]bool),
		}
		for _, e := range cfg.ContentExts {
			re.ContentExts[strings.ToLower(strings.TrimSpace(e))] = true
		}
		rulesList = append(rulesList, re)
	}

	if cfg.PIIScan {
		piiRule := &rules.PIIPatternsRule{
			EnablePatterns:     cfg.PIIScan,
			MaxSampleSize:      cfg.PIIMaxBytes,
			ContentExts:        make(map[string]bool),
			MaxMatches:         cfg.PIIMaxMatches,
			MaskSensitive:      cfg.PIIMask,
			StoreSample:        cfg.PIIStoreSample,
			UseContextKeywords: cfg.PIIContextKeywords,
		}
		for _, e := range cfg.PIIExts {
			e = strings.ToLower(strings.TrimSpace(e))
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			piiRule.ContentExts[e] = true
		}
		rulesList = append(rulesList, piiRule)
	}

	if len(cfg.EnableRules) > 0 || len(cfg.DisableRules) > 0 {
		enabled := map[string]bool{}
		for _, r := range rulesList {
			enabled[r.Name()] = true
		}
		for _, r := range cfg.EnableRules {
			enabled[strings.TrimSpace(r)] = true
		}
		for _, r := range cfg.DisableRules {
			enabled[strings.TrimSpace(r)] = false
		}
		filtered := []rules.Rule{}
		for _, r := range rulesList {
			if enabled[r.Name()] {
				filtered = append(filtered, r)
			}
		}
		rulesList = filtered
	}

	return rulesList
}

func abort(logger consolelog.Logger, context string, err error) {
	if err != nil {
		logger.Errorf("%s: %v", context, err)
	} else {
		logger.Errorf("%s", context)
	}
	logger.Errorf("Scan aborted")
	os.Exit(1)
}

func defaultHighRiskExt() map[string]bool {
	return map[string]bool{
		".zip": true, ".tar": true, ".tgz": true, ".gz": true, ".7z": true, ".rar": true,
		".sql": true, ".csv": true, ".xlsx": true, ".xls": true, ".jsonl": true,
		".php": true, ".phtml": true, ".phar": true, ".cgi": true, ".pl": true, ".py": true, ".rb": true,
		".jsp": true, ".jspx": true, ".asp": true, ".aspx": true,
		".exe": true, ".dll": true, ".so": true, ".bin": true, ".sh": true,
	}
}
