package report

import (
	"github.com/heartblast/detect_bot/internal/root"
	"github.com/heartblast/detect_bot/internal/systeminfo"
)

// Finding stores a single suspicious file detected during scanning.
type Finding struct {
	Path                 string   `json:"path"`
	RealPath             string   `json:"real_path,omitempty"`
	Size                 int64    `json:"size_bytes"`
	ModTime              string   `json:"mod_time"`
	Perm                 string   `json:"perm"`
	Ext                  string   `json:"ext"`
	MimeSniff            string   `json:"mime_sniff"`
	Reasons              []string `json:"reasons"`
	SHA256               string   `json:"sha256,omitempty"`
	URLExposureHeuristic string   `json:"url_exposure_heuristic,omitempty"`
	RootMatched          string   `json:"root_matched,omitempty"`
	RootSource           string   `json:"root_source,omitempty"`
	Severity             string   `json:"severity,omitempty"`
	MatchedPatterns      []string `json:"matched_patterns,omitempty"`
	EvidenceMasked       []string `json:"evidence_masked,omitempty"`
	ContentFlags         string   `json:"content_flags,omitempty"`
}

// Report is the top-level JSON report schema.
type Report struct {
	ReportVersion string              `json:"report_version,omitempty"`
	GeneratedAt   string              `json:"generated_at"`
	ScanStartedAt string              `json:"scan_started_at,omitempty"`
	Host          systeminfo.HostInfo `json:"host"`
	Inputs        []string            `json:"inputs"`
	Config        interface{}         `json:"config,omitempty"`
	ActiveRules   []string            `json:"active_rules,omitempty"`
	Roots         []root.RootEntry    `json:"roots"`
	Findings      []Finding           `json:"findings"`
	Stats         struct {
		RootsCount    int `json:"roots_count"`
		ScannedFiles  int `json:"scanned_files"`
		FindingsCount int `json:"findings_count"`
	} `json:"stats"`
}
