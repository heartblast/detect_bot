package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MultiFlag accepts repeatable string flags.
type MultiFlag []string

func (m *MultiFlag) String() string { return strings.Join(*m, ",") }

func (m *MultiFlag) Set(s string) error {
	if s == "" {
		return nil
	}
	*m = append(*m, s)
	return nil
}

// stringSliceFlag accepts comma-separated or repeatable values.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(val string) error {
	if val == "" {
		return nil
	}
	for _, part := range strings.Split(val, ",") {
		if t := strings.TrimSpace(part); t != "" {
			*s = append(*s, t)
		}
	}
	return nil
}

type KafkaConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	Brokers       []string `yaml:"brokers" json:"brokers"`
	Topic         string   `yaml:"topic" json:"topic"`
	ClientID      string   `yaml:"client_id" json:"client_id"`
	TLSEnabled    bool     `yaml:"tls" json:"tls"`
	SASLEnabled   bool     `yaml:"sasl_enabled" json:"sasl_enabled"`
	Username      string   `yaml:"username" json:"username"`
	PasswordEnv   string   `yaml:"password_env" json:"password_env"`
	MaskSensitive bool     `yaml:"mask_sensitive" json:"mask_sensitive"`
}

type Config struct {
	NginxDump  string `yaml:"nginx_dump" json:"nginx_dump"`
	ApacheDump string `yaml:"apache_dump" json:"apache_dump"`
	ServerType string `yaml:"server_type" json:"server_type"`

	Scan       bool   `yaml:"scan" json:"scan"`
	Output     string `yaml:"out" json:"out"`
	MaxDepth   int    `yaml:"max_depth" json:"max_depth"`
	MaxSizeMB  int64  `yaml:"max_size_mb" json:"max_size_mb"`
	NewerThanH int    `yaml:"newer_than_h" json:"newer_than_h"`
	Preset     string `yaml:"preset" json:"preset"`
	ConfigFile string `yaml:"config,omitempty" json:"config,omitempty"`

	Exclude       MultiFlag `yaml:"exclude" json:"exclude"`
	AllowMimePref MultiFlag `yaml:"allow_mime_prefix" json:"allow_mime_prefix"`
	AllowExt      MultiFlag `yaml:"allow_ext" json:"allow_ext"`
	WatchDirs     MultiFlag `yaml:"watch_dirs" json:"watch_dirs"`

	ComputeHash   bool `yaml:"hash" json:"hash"`
	FollowSymlink bool `yaml:"follow_symlink" json:"follow_symlink"`

	EnableRules  MultiFlag `yaml:"enable_rules,omitempty" json:"enable_rules,omitempty"`
	DisableRules MultiFlag `yaml:"disable_rules,omitempty" json:"disable_rules,omitempty"`

	Rules struct {
		Enable  []string `yaml:"enable" json:"enable"`
		Disable []string `yaml:"disable" json:"disable"`
	} `yaml:"rules,omitempty" json:"rules,omitempty"`

	Kafka KafkaConfig `yaml:"kafka" json:"kafka"`

	Workers int `yaml:"workers" json:"workers"`

	ContentScan      bool      `yaml:"content_scan" json:"content_scan"`
	ContentMaxBytes  int       `yaml:"content_max_bytes" json:"content_max_bytes"`
	ContentMaxSizeKB int64     `yaml:"content_max_size_kb" json:"content_max_size_kb"`
	ContentExts      MultiFlag `yaml:"content_exts" json:"content_exts"`

	PIIScan            bool      `yaml:"pii_scan" json:"pii_scan"`
	PIIExts            MultiFlag `yaml:"pii_exts" json:"pii_exts"`
	PIIMaxSizeKB       int64     `yaml:"pii_max_size_kb" json:"pii_max_size_kb"`
	PIIMaxBytes        int       `yaml:"pii_max_bytes" json:"pii_max_bytes"`
	PIIMaxMatches      int       `yaml:"pii_max_matches" json:"pii_max_matches"`
	PIIMask            bool      `yaml:"pii_mask" json:"pii_mask"`
	PIIStoreSample     bool      `yaml:"pii_store_sample" json:"pii_store_sample"`
	PIIContextKeywords bool      `yaml:"pii_context_keywords" json:"pii_context_keywords"`

	// Compatibility aliases for UI/generated config payloads.
	WatchDir   MultiFlag `yaml:"watch_dir,omitempty" json:"watch_dir,omitempty"`
	ContentExt MultiFlag `yaml:"content_ext,omitempty" json:"content_ext,omitempty"`
	PIIExt     MultiFlag `yaml:"pii_ext,omitempty" json:"pii_ext,omitempty"`
	OutputPath string    `yaml:"output,omitempty" json:"output,omitempty"`
}

func MustParseFlags() Config {
	var cfg Config

	cfg.ConfigFile = scanArgValue("--config")
	if cfg.ConfigFile != "" {
		if err := cfg.LoadFromFile(cfg.ConfigFile); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to parse config file: %v\n", err)
			os.Exit(1)
		}
	}

	flag.StringVar(&cfg.Preset, "preset", cfg.Preset, "predefined option set (safe, balanced, deep, handover, offboarding)")
	flag.StringVar(&cfg.ServerType, "server-type", cfg.ServerType, "web server type (nginx|apache|manual)")
	flag.StringVar(&cfg.NginxDump, "nginx-dump", cfg.NginxDump, "path to nginx -T dump output file, or '-' for stdin")
	flag.StringVar(&cfg.ApacheDump, "apache-dump", cfg.ApacheDump, "path to apachectl -S dump output file, or '-' for stdin")
	flag.StringVar(&cfg.ConfigFile, "config", cfg.ConfigFile, "path to YAML/JSON configuration file")
	flag.BoolVar(&cfg.Scan, "scan", cfg.Scan, "scan discovered roots for suspicious files")
	flag.StringVar(&cfg.Output, "out", cfg.Output, "output JSON report path ('-' for stdout)")
	flag.IntVar(&cfg.MaxDepth, "max-depth", cfg.MaxDepth, "max directory recursion depth")
	flag.Int64Var(&cfg.MaxSizeMB, "max-size-mb", cfg.MaxSizeMB, "max file size (MB) to read for MIME sniff/hash")
	flag.IntVar(&cfg.NewerThanH, "newer-than-h", cfg.NewerThanH, "only flag files modified within last N hours (0=disable)")
	flag.Var(&cfg.Exclude, "exclude", "exclude path prefix (repeatable)")
	flag.Var(&cfg.AllowMimePref, "allow-mime-prefix", "allowed MIME prefixes (repeatable)")
	flag.Var(&cfg.AllowExt, "allow-ext", "allowed extensions (repeatable)")
	flag.Var(&cfg.WatchDirs, "watch-dir", "manual watch directory to include (repeatable)")
	flag.BoolVar(&cfg.ComputeHash, "hash", cfg.ComputeHash, "compute SHA256 for findings")
	flag.BoolVar(&cfg.FollowSymlink, "follow-symlink", cfg.FollowSymlink, "follow symlinks (not recommended)")
	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "number of scan workers (default 4)")
	flag.BoolVar(&cfg.ContentScan, "content-scan", cfg.ContentScan, "scan file content for sensitive information patterns")
	flag.IntVar(&cfg.ContentMaxBytes, "content-max-bytes", cfg.ContentMaxBytes, "max bytes to read per file for content scan (default 65536)")
	flag.Int64Var(&cfg.ContentMaxSizeKB, "content-max-size-kb", cfg.ContentMaxSizeKB, "max file size (KB) to scan for sensitive patterns (default 1024)")
	flag.Var(&cfg.ContentExts, "content-ext", "target extensions for content scan (repeatable, e.g. .yaml .json .env)")
	flag.BoolVar(&cfg.PIIScan, "pii-scan", cfg.PIIScan, "scan file content for personal information (PII) patterns")
	flag.Var(&cfg.PIIExts, "pii-ext", "target extensions for PII scan (repeatable, e.g. .yaml .json .env)")
	flag.Int64Var(&cfg.PIIMaxSizeKB, "pii-max-size-kb", cfg.PIIMaxSizeKB, "max file size (KB) to scan for PII patterns (default 256)")
	flag.IntVar(&cfg.PIIMaxBytes, "pii-max-bytes", cfg.PIIMaxBytes, "max bytes to read per file for PII scan (default 65536)")
	flag.IntVar(&cfg.PIIMaxMatches, "pii-max-matches", cfg.PIIMaxMatches, "max number of matches to store per rule (default 5)")
	flag.BoolVar(&cfg.PIIMask, "pii-mask", cfg.PIIMask, "mask sensitive PII values in results")
	flag.BoolVar(&cfg.PIIStoreSample, "pii-store-sample", cfg.PIIStoreSample, "store masked PII samples in results")
	flag.BoolVar(&cfg.PIIContextKeywords, "pii-context-keywords", cfg.PIIContextKeywords, "use context keywords to boost PII detection confidence")
	flag.Var(&cfg.EnableRules, "enable-rules", "explicitly enable rules (comma-separated or repeatable)")
	flag.Var(&cfg.DisableRules, "disable-rules", "explicitly disable rules (comma-separated or repeatable)")
	flag.BoolVar(&cfg.Kafka.Enabled, "kafka-enabled", cfg.Kafka.Enabled, "enable Kafka event sending")
	flag.Var((*stringSliceFlag)(&cfg.Kafka.Brokers), "kafka-brokers", "Kafka brokers list (comma-separated or repeatable)")
	flag.StringVar(&cfg.Kafka.Topic, "kafka-topic", cfg.Kafka.Topic, "Kafka topic to publish events to")
	flag.StringVar(&cfg.Kafka.ClientID, "kafka-client-id", cfg.Kafka.ClientID, "Kafka client id")
	flag.BoolVar(&cfg.Kafka.TLSEnabled, "kafka-tls", cfg.Kafka.TLSEnabled, "use TLS for Kafka connection")
	flag.BoolVar(&cfg.Kafka.SASLEnabled, "kafka-sasl-enabled", cfg.Kafka.SASLEnabled, "enable SASL authentication for Kafka")
	flag.StringVar(&cfg.Kafka.Username, "kafka-username", cfg.Kafka.Username, "username for SASL authentication")
	flag.StringVar(&cfg.Kafka.PasswordEnv, "kafka-password-env", cfg.Kafka.PasswordEnv, "environment variable name containing Kafka password")
	flag.BoolVar(&cfg.Kafka.MaskSensitive, "kafka-mask-sensitive", cfg.Kafka.MaskSensitive, "mask sensitive fields in Kafka events")

	flag.Parse()

	cfg.EnableRules = mergeStringSlices(cfg.EnableRules, cfg.Rules.Enable)
	cfg.DisableRules = mergeStringSlices(cfg.DisableRules, cfg.Rules.Disable)

	if cfg.Preset != "" {
		applyPreset(&cfg)
	}

	applyDefaults(&cfg)

	return cfg
}

func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func scanArgValue(name string) string {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == name {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(arg, name+"=") {
			return strings.SplitN(arg, "=", 2)[1]
		}
	}
	return ""
}

func (cfg *Config) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var fileCfg Config
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &fileCfg); err != nil {
			return err
		}
	case ".json":
		if err := json.Unmarshal(data, &fileCfg); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported config file extension: %s", path)
	}

	normalizeConfigAliases(&fileCfg)
	mergeConfig(cfg, &fileCfg)
	return nil
}

func normalizeConfigAliases(cfg *Config) {
	if cfg.Output == "" && cfg.OutputPath != "" {
		cfg.Output = cfg.OutputPath
	}
	if len(cfg.WatchDirs) == 0 && len(cfg.WatchDir) > 0 {
		cfg.WatchDirs = append(MultiFlag{}, cfg.WatchDir...)
	}
	if len(cfg.ContentExts) == 0 && len(cfg.ContentExt) > 0 {
		cfg.ContentExts = append(MultiFlag{}, cfg.ContentExt...)
	}
	if len(cfg.PIIExts) == 0 && len(cfg.PIIExt) > 0 {
		cfg.PIIExts = append(MultiFlag{}, cfg.PIIExt...)
	}
}

func mergeConfig(dst, src *Config) {
	if dst.Preset == "" {
		dst.Preset = src.Preset
	}
	if dst.ServerType == "" {
		dst.ServerType = src.ServerType
	}
	if dst.NginxDump == "" {
		dst.NginxDump = src.NginxDump
	}
	if dst.ApacheDump == "" {
		dst.ApacheDump = src.ApacheDump
	}
	if !dst.Scan && src.Scan {
		dst.Scan = true
	}
	if dst.Output == "" {
		dst.Output = src.Output
	}
	if dst.MaxDepth == 0 {
		dst.MaxDepth = src.MaxDepth
	}
	if dst.MaxSizeMB == 0 {
		dst.MaxSizeMB = src.MaxSizeMB
	}
	if dst.NewerThanH == 0 {
		dst.NewerThanH = src.NewerThanH
	}
	if len(dst.Exclude) == 0 && len(src.Exclude) > 0 {
		dst.Exclude = append(MultiFlag{}, src.Exclude...)
	}
	if len(dst.AllowMimePref) == 0 && len(src.AllowMimePref) > 0 {
		dst.AllowMimePref = append(MultiFlag{}, src.AllowMimePref...)
	}
	if len(dst.AllowExt) == 0 && len(src.AllowExt) > 0 {
		dst.AllowExt = append(MultiFlag{}, src.AllowExt...)
	}
	if len(dst.WatchDirs) == 0 && len(src.WatchDirs) > 0 {
		dst.WatchDirs = append(MultiFlag{}, src.WatchDirs...)
	}
	if !dst.ComputeHash && src.ComputeHash {
		dst.ComputeHash = true
	}
	if !dst.FollowSymlink && src.FollowSymlink {
		dst.FollowSymlink = true
	}
	if len(dst.EnableRules) == 0 {
		switch {
		case len(src.EnableRules) > 0:
			dst.EnableRules = append(MultiFlag{}, src.EnableRules...)
		case len(src.Rules.Enable) > 0:
			dst.EnableRules = append(MultiFlag{}, src.Rules.Enable...)
		}
	}
	if len(dst.DisableRules) == 0 {
		switch {
		case len(src.DisableRules) > 0:
			dst.DisableRules = append(MultiFlag{}, src.DisableRules...)
		case len(src.Rules.Disable) > 0:
			dst.DisableRules = append(MultiFlag{}, src.Rules.Disable...)
		}
	}
	if dst.Workers == 0 {
		dst.Workers = src.Workers
	}
	if !dst.ContentScan && src.ContentScan {
		dst.ContentScan = true
	}
	if dst.ContentMaxBytes == 0 {
		dst.ContentMaxBytes = src.ContentMaxBytes
	}
	if dst.ContentMaxSizeKB == 0 {
		dst.ContentMaxSizeKB = src.ContentMaxSizeKB
	}
	if len(dst.ContentExts) == 0 && len(src.ContentExts) > 0 {
		dst.ContentExts = append(MultiFlag{}, src.ContentExts...)
	}
	if !dst.PIIScan && src.PIIScan {
		dst.PIIScan = true
	}
	if len(dst.PIIExts) == 0 && len(src.PIIExts) > 0 {
		dst.PIIExts = append(MultiFlag{}, src.PIIExts...)
	}
	if dst.PIIMaxSizeKB == 0 {
		dst.PIIMaxSizeKB = src.PIIMaxSizeKB
	}
	if dst.PIIMaxBytes == 0 {
		dst.PIIMaxBytes = src.PIIMaxBytes
	}
	if dst.PIIMaxMatches == 0 {
		dst.PIIMaxMatches = src.PIIMaxMatches
	}
	if !dst.PIIMask && src.PIIMask {
		dst.PIIMask = true
	}
	if !dst.PIIStoreSample && src.PIIStoreSample {
		dst.PIIStoreSample = true
	}
	if !dst.PIIContextKeywords && src.PIIContextKeywords {
		dst.PIIContextKeywords = true
	}

	mergeKafkaConfig(&dst.Kafka, &src.Kafka)
}

func mergeKafkaConfig(dst, src *KafkaConfig) {
	if !dst.Enabled && src.Enabled {
		dst.Enabled = true
	}
	if len(dst.Brokers) == 0 && len(src.Brokers) > 0 {
		dst.Brokers = append([]string{}, src.Brokers...)
	}
	if dst.Topic == "" {
		dst.Topic = src.Topic
	}
	if dst.ClientID == "" {
		dst.ClientID = src.ClientID
	}
	if !dst.TLSEnabled && src.TLSEnabled {
		dst.TLSEnabled = true
	}
	if !dst.SASLEnabled && src.SASLEnabled {
		dst.SASLEnabled = true
	}
	if dst.Username == "" {
		dst.Username = src.Username
	}
	if dst.PasswordEnv == "" {
		dst.PasswordEnv = src.PasswordEnv
	}
	if !dst.MaskSensitive && src.MaskSensitive {
		dst.MaskSensitive = true
	}
}

func applyDefaults(cfg *Config) {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 12
	}
	if cfg.MaxSizeMB == 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.ContentMaxBytes == 0 {
		cfg.ContentMaxBytes = 65536
	}
	if cfg.ContentMaxSizeKB == 0 {
		cfg.ContentMaxSizeKB = 1024
	}
	if cfg.PIIMaxSizeKB == 0 {
		cfg.PIIMaxSizeKB = 256
	}
	if cfg.PIIMaxBytes == 0 {
		cfg.PIIMaxBytes = 65536
	}
	if cfg.PIIMaxMatches == 0 {
		cfg.PIIMaxMatches = 5
	}
	if len(cfg.AllowMimePref) == 0 {
		cfg.AllowMimePref = []string{
			"text/html", "text/css", "application/javascript", "text/javascript", "application/json",
			"image/", "font/", "application/font-",
			"application/xml", "text/plain",
		}
	}
	if len(cfg.AllowExt) == 0 {
		cfg.AllowExt = []string{
			".html", ".htm", ".css", ".js", ".mjs", ".json", ".xml", ".txt",
			".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
			".woff", ".woff2", ".ttf", ".otf", ".eot",
		}
	}
	if len(cfg.ContentExts) == 0 {
		cfg.ContentExts = []string{
			".yaml", ".yml", ".json", ".xml", ".properties", ".conf",
			".env", ".ini", ".txt", ".config", ".cfg", ".toml",
		}
	}
	if len(cfg.PIIExts) == 0 {
		cfg.PIIExts = []string{
			".yaml", ".yml", ".json", ".xml", ".properties", ".conf",
			".env", ".ini", ".txt", ".log", ".csv", ".tsv",
		}
	}
}

func applyPreset(cfg *Config) {
	var preset Config
	switch cfg.Preset {
	case "safe":
		preset.MaxDepth = 5
		preset.Scan = true
		preset.Workers = 2
		preset.ContentScan = false
	case "balanced":
		preset.MaxDepth = 12
		preset.Scan = true
		preset.Workers = 4
		preset.ContentScan = true
		preset.ContentMaxBytes = 65536
	case "deep":
		preset.MaxDepth = 0
		preset.Scan = true
		preset.Workers = 8
		preset.ContentScan = true
		preset.ContentMaxBytes = 131072
	case "handover":
		preset.MaxDepth = 8
		preset.Scan = true
		preset.Workers = 2
		preset.ContentScan = false
	case "offboarding":
		preset.MaxDepth = 20
		preset.Scan = true
		preset.Workers = 4
		preset.ContentScan = true
		preset.ContentMaxBytes = 65536
	default:
		return
	}

	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = preset.MaxDepth
	}
	if !cfg.Scan {
		cfg.Scan = preset.Scan
	}
	if cfg.Workers == 0 {
		cfg.Workers = preset.Workers
	}
	if !cfg.ContentScan {
		cfg.ContentScan = preset.ContentScan
	}
	if cfg.ContentMaxBytes == 0 {
		cfg.ContentMaxBytes = preset.ContentMaxBytes
	}
}
