package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFileYAMLWithStreamlitAliases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`server_type: nginx
nginx_dump: "-"
scan: true
watch_dir:
  - /var/www/html
allow_mime_prefix:
  - text/html
allow_ext:
  - .html
workers: 6
content_scan: true
content_max_bytes: 4096
content_max_size_kb: 128
content_ext:
  - .yaml
pii_scan: true
pii_ext:
  - .json
pii_max_size_kb: 64
pii_max_bytes: 2048
pii_max_matches: 3
pii_mask: true
pii_store_sample: true
pii_context_keywords: true
kafka:
  enabled: true
  brokers:
    - broker1:9092
  topic: dmz.scan.findings
  client_id: streamlit
  tls: true
  sasl_enabled: true
  username: scanner
  password_env: KAFKA_PASSWORD
  mask_sensitive: true
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	var cfg Config
	if err := cfg.LoadFromFile(path); err != nil {
		t.Fatalf("load yaml: %v", err)
	}

	if cfg.ServerType != "nginx" || cfg.NginxDump != "-" || !cfg.Scan {
		t.Fatalf("basic yaml fields not loaded: %+v", cfg)
	}
	if len(cfg.WatchDirs) != 1 || cfg.WatchDirs[0] != "/var/www/html" {
		t.Fatalf("watch_dir alias not merged: %+v", cfg.WatchDirs)
	}
	if cfg.Workers != 6 || !cfg.ContentScan || !cfg.PIIScan {
		t.Fatalf("scan settings not loaded: %+v", cfg)
	}
	if len(cfg.ContentExts) != 1 || cfg.ContentExts[0] != ".yaml" {
		t.Fatalf("content_ext alias not merged: %+v", cfg.ContentExts)
	}
	if len(cfg.PIIExts) != 1 || cfg.PIIExts[0] != ".json" {
		t.Fatalf("pii_ext alias not merged: %+v", cfg.PIIExts)
	}
	if !cfg.Kafka.Enabled || cfg.Kafka.ClientID != "streamlit" || !cfg.Kafka.MaskSensitive {
		t.Fatalf("kafka config not loaded: %+v", cfg.Kafka)
	}
}

func TestLoadFromFileJSONWithSnakeCaseKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{
  "server_type": "manual",
  "scan": true,
  "watch_dirs": ["/srv/www"],
  "workers": 2,
  "content_scan": true,
  "content_exts": [".env"],
  "pii_scan": true,
  "pii_exts": [".txt"],
  "kafka": {
    "enabled": true,
    "brokers": ["broker1:9092", "broker2:9092"],
    "topic": "dmz.scan.findings",
    "client_id": "json-client",
    "tls": true,
    "sasl_enabled": false,
    "username": "svc",
    "password_env": "KAFKA_PASSWORD",
    "mask_sensitive": true
  }
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}

	var cfg Config
	if err := cfg.LoadFromFile(path); err != nil {
		t.Fatalf("load json: %v", err)
	}

	if cfg.ServerType != "manual" || len(cfg.WatchDirs) != 1 || cfg.WatchDirs[0] != "/srv/www" {
		t.Fatalf("json watch_dirs not loaded: %+v", cfg)
	}
	if len(cfg.ContentExts) != 1 || cfg.ContentExts[0] != ".env" {
		t.Fatalf("json content_exts not loaded: %+v", cfg.ContentExts)
	}
	if len(cfg.PIIExts) != 1 || cfg.PIIExts[0] != ".txt" {
		t.Fatalf("json pii_exts not loaded: %+v", cfg.PIIExts)
	}
	if cfg.Kafka.Topic != "dmz.scan.findings" || cfg.Kafka.ClientID != "json-client" {
		t.Fatalf("json kafka not loaded: %+v", cfg.Kafka)
	}
}

func TestMergeConfigKeepsCLIOverrides(t *testing.T) {
	t.Parallel()

	dst := Config{
		Workers:            8,
		ContentScan:        true,
		ContentMaxBytes:    1024,
		ContentExts:        MultiFlag{".yaml"},
		PIIScan:            true,
		PIIExts:            MultiFlag{".json"},
		PIIMaxBytes:        512,
		PIIMaxSizeKB:       16,
		PIIMaxMatches:      1,
		PIIMask:            true,
		PIIStoreSample:     true,
		PIIContextKeywords: true,
		Kafka: KafkaConfig{
			Enabled:  true,
			Brokers:  []string{"cli-broker:9092"},
			Topic:    "cli-topic",
			ClientID: "cli-client",
		},
	}
	src := Config{
		Workers:         2,
		ContentScan:     true,
		ContentMaxBytes: 2048,
		ContentExts:     MultiFlag{".env"},
		PIIScan:         true,
		PIIExts:         MultiFlag{".txt"},
		PIIMaxBytes:     4096,
		PIIMaxSizeKB:    128,
		PIIMaxMatches:   5,
		Kafka: KafkaConfig{
			Enabled:  true,
			Brokers:  []string{"file-broker:9092"},
			Topic:    "file-topic",
			ClientID: "file-client",
		},
	}

	mergeConfig(&dst, &src)

	if dst.Workers != 8 || dst.ContentMaxBytes != 1024 || dst.PIIMaxBytes != 512 {
		t.Fatalf("cli numeric overrides were overwritten: %+v", dst)
	}
	if dst.Kafka.Topic != "cli-topic" || dst.Kafka.ClientID != "cli-client" || dst.Kafka.Brokers[0] != "cli-broker:9092" {
		t.Fatalf("cli kafka overrides were overwritten: %+v", dst.Kafka)
	}
	if dst.ContentExts[0] != ".yaml" || dst.PIIExts[0] != ".json" {
		t.Fatalf("cli slice overrides were overwritten: content=%v pii=%v", dst.ContentExts, dst.PIIExts)
	}
}

func TestScanArgValueSupportsBothForms(t *testing.T) {
	t.Parallel()

	orig := os.Args
	t.Cleanup(func() { os.Args = orig })

	os.Args = []string{"dmz_webroot_scanner", "--config", "sample_config.yaml"}
	if got := scanArgValue("--config"); got != "sample_config.yaml" {
		t.Fatalf("space-separated form failed: %q", got)
	}

	os.Args = []string{"dmz_webroot_scanner", "--config=sample_config.json"}
	if got := scanArgValue("--config"); got != "sample_config.json" {
		t.Fatalf("equals form failed: %q", got)
	}
}
