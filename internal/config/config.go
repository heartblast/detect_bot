package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MultiFlag: 명령줄 플래그에서 여러 번 입력된 값들을 저장하는 커스텀 타입
// 예: -watch-dir /var/www -watch-dir /home/user/web
type MultiFlag []string

// String: MultiFlag를 문자열로 변환하는 Stringer 인터페이스 구현
func (m *MultiFlag) String() string { return strings.Join(*m, ",") }

// Set: 플래그 파서가 각 입력값을 추가할 때 호출되는 메서드
func (m *MultiFlag) Set(s string) error {
	if s == "" {
		return nil
	}
	*m = append(*m, s) // 값을 슬라이스에 추가
	return nil
}

// stringSliceFlag: comma-separated or repeatable string list
// kafka-brokers 등에서 사용된다.
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

// KafkaConfig: Kafka 전송 관련 설정
// 민감정보는 MaskSensitive 플래그에 따라 이벤트에서 마스킹
// PasswordEnv에는 비밀번호가 저장된 환경변수 이름이 들어감.
// Brokers는 복수 호스트를 허용한다.
type KafkaConfig struct {
	Enabled       bool     // Kafka 전송 활성화
	Brokers       []string // broker list
	Topic         string   // 전송 토픽
	ClientID      string   // 클라이언트 식별자
	TLSEnabled    bool     // TLS 사용
	SASLEnabled   bool     // SASL 인증 사용
	Username      string   // SASL 사용자명
	PasswordEnv   string   // 비밀번호가 들어있는 환경변수 이름
	MaskSensitive bool     // 민감정보 마스킹 여부
}

// Config: 프로그램 실행에 필요한 모든 설정값을 담는 구조체
type Config struct {
	// 입력 소스
	NginxDump  string // Nginx -T 명령 출력 파일 경로 (또는 '-'로 stdin 사용)
	ApacheDump string // apachectl -S 명령 출력 파일 경로
	ServerType string // web server type (nginx|apache|manual); empty=auto detect

	// 스캔 옵션
	Scan       bool   // 실제 파일 시스템 스캔 실행 여부
	Output     string // 출력 JSON 리포트 파일 경로 (또는 '-'로 stdout 사용)
	MaxDepth   int    // 디렉토리 재귀 최대 깊이
	MaxSizeMB  int64  // MIME 탐지/해시 계산 시 읽을 파일 최대 크기 (MB)
	NewerThanH int    // 마지막 N시간 내 수정된 파일만 플래그 (0=disable)
	Preset     string // predefined option set (safe, balanced, deep, handover, offboarding)
	ConfigFile string // path to YAML/JSON configuration file (parsed before flags)

	// 필터 및 화이트리스트
	Exclude       MultiFlag // 제외할 경로 접두사 (반복 가능) 예: -exclude /tmp -exclude /proc
	AllowMimePref MultiFlag // 허용된 MIME 타입 프리픽스 (반복 가능)
	AllowExt      MultiFlag // 허용된 파일 확장자 (반복 가능)
	WatchDirs     MultiFlag // 수동으로 추가할 감시 디렉토리 (반복 가능)

	// 추가 기능
	ComputeHash   bool // 발견된 파일의 SHA256 해시 계산 여부
	FollowSymlink bool // 심볼릭 링크 따라가기 여부 (권장하지 않음)

	// 룰 제어
	EnableRules  MultiFlag // 명시적으로 활성화할 룰 목록 (comma-separated or repeatable)
	DisableRules MultiFlag // 명시적으로 비활성화할 룰 목록

	// 설정파일용 중첩 구조 (yaml/JSON) - CLI 플래그와 병합됨
	Rules struct {
		Enable  []string `yaml:"enable" json:"enable"`
		Disable []string `yaml:"disable" json:"disable"`
	} `yaml:"rules,omitempty" json:"rules,omitempty"`

	// Kafka 이벤트 전송 설정
	Kafka KafkaConfig

	// 성능 최적화
	Workers int // 파일 스캔 워커 스레드 수 (기본값 4)

	// 민감정보 콘텐츠 스캔 옵션
	ContentScan      bool      // 파일 본문에서 민감정보 패턴 탐지 활성화
	ContentMaxBytes  int       // 콘텐츠 샘플 최대 읽기 바이트 수
	ContentMaxSizeKB int64     // 콘텐츠 스캔 대상 파일 최대 크기 (KB)
	ContentExts      MultiFlag // 콘텐츠 스캔 대상 확장자 (yaml, json, env, conf 등)

	// 개인정보(PII) 탐지 옵션
	PIIScan            bool      // 개인정보 유출위험 패턴 탐지 활성화
	PIIExts            MultiFlag // PII 탐지 대상 확장자
	PIIMaxSizeKB       int64     // PII 탐지 대상 파일 최대 크기 (KB)
	PIIMaxBytes        int       // PII 탐지 시 최대 읽기 바이트 수
	PIIMaxMatches      int       // 규칙별 최대 저장 샘플 수
	PIIMask            bool      // 결과값 마스킹 저장
	PIIStoreSample     bool      // 샘플 저장 여부 제어
	PIIContextKeywords bool      // 문맥 기반 보강 활성화
}

// MustParseFlags: 명령줄 플래그를 파싱하여 Config 구조체로 변환
// 기본값을 설정하고 잘못된 설정을 검증
func MustParseFlags() Config {
	var cfg Config

	// 1) 먼저 CLI에서 --config 경로를 찾아 파일을 로드하여 초기값을 채운다
	cfg.ConfigFile = scanArgValue("--config")
	if cfg.ConfigFile != "" {
		if err := cfg.LoadFromFile(cfg.ConfigFile); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to parse config file: %v\n", err)
			os.Exit(1)
		}
	}

	// 이제 플래그 등록 (기본값은 앞서 로드된 cfg의 값)
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

	// parse CLI flags (overrides defaults coming from config file)
	flag.Parse()

	// 설정파일 내 nested rules를 CLI 리스트로 병합
	cfg.EnableRules = mergeStringSlices(cfg.EnableRules, cfg.Rules.Enable)
	cfg.DisableRules = mergeStringSlices(cfg.DisableRules, cfg.Rules.Disable)

	// 기본값 검증 및 추가 설정
	if cfg.Workers <= 0 {
		cfg.Workers = 1
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

	// 프리셋 적용: CLI 플래그나 설정파일에서 제공되지 않은 값에만 채움
	if cfg.Preset != "" {
		applyPreset(&cfg)
	}

	// 기본 허용 MIME/확장자 및 콘텐츠 대상 확장자
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

	return cfg
}

// mergeStringSlices: 두 슬라이스를 합치되 중복을 제거
func mergeStringSlices(a, b []string) []string {
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			m[s] = true
			a = append(a, s)
		}
	}
	return a
}

// scanArgValue: os.Args 리스트에서 지정된 플래그에 해당하는 값을 찾아 반환
// --config path 또는 --config=path 등을 지원한다.
func scanArgValue(name string) string {
	for i, arg := range os.Args[1:] {
		if arg == name && i+2 <= len(os.Args[1:]) {
			return os.Args[i+2]
		}
		if strings.HasPrefix(arg, name+"=") {
			return strings.SplitN(arg, "=", 2)[1]
		}
	}
	return ""
}

// LoadFromFile: YAML 또는 JSON 설정파일을 읽어 Config에 반영
// 기존 필드값을 덮어쓰기하지 않고 zero값인 항목만 채운다.
func (cfg *Config) LoadFromFile(path string) error {
	data, err := ioutil.ReadFile(path)
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
	// merge: only set zero-valued fields in cfg
	mergeConfig(cfg, &fileCfg)
	return nil
}

// mergeConfig: fileCfg에서 비어있지 않은 값이 있으면 dst에 채우되, dst의 값이
// 기본(zero)인 경우에만 덮어쓴다. 슬라이스의 경우 dst가 비어있을 때에만 교체.
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
	if dst.Scan == false && src.Scan {
		dst.Scan = src.Scan
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
		dst.Exclude = src.Exclude
	}
	if len(dst.AllowMimePref) == 0 && len(src.AllowMimePref) > 0 {
		dst.AllowMimePref = src.AllowMimePref
	}
	if len(dst.AllowExt) == 0 && len(src.AllowExt) > 0 {
		dst.AllowExt = src.AllowExt
	}
	if len(dst.WatchDirs) == 0 && len(src.WatchDirs) > 0 {
		dst.WatchDirs = src.WatchDirs
	}
	if dst.ComputeHash == false && src.ComputeHash {
		dst.ComputeHash = src.ComputeHash
	}
	if dst.FollowSymlink == false && src.FollowSymlink {
		dst.FollowSymlink = src.FollowSymlink
	}
	// CLI-style enable/disable lists
	if len(dst.EnableRules) == 0 && len(src.EnableRules) > 0 {
		dst.EnableRules = src.EnableRules
	}
	if len(dst.DisableRules) == 0 && len(src.DisableRules) > 0 {
		dst.DisableRules = src.DisableRules
	}
	// config file nested rules block
	if len(dst.EnableRules) == 0 && len(src.Rules.Enable) > 0 {
		dst.EnableRules = src.Rules.Enable
	}
	if len(dst.DisableRules) == 0 && len(src.Rules.Disable) > 0 {
		dst.DisableRules = src.Rules.Disable
	}
	// kafka
	if dst.Kafka.Enabled == false && src.Kafka.Enabled {
		dst.Kafka = src.Kafka
	}
	if dst.Kafka.Brokers == nil && src.Kafka.Brokers != nil {
		dst.Kafka.Brokers = src.Kafka.Brokers
	}
	if dst.Kafka.Topic == "" {
		dst.Kafka.Topic = src.Kafka.Topic
	}
	if dst.Kafka.ClientID == "" {
		dst.Kafka.ClientID = src.Kafka.ClientID
	}
	if dst.Kafka.TLSEnabled == false && src.Kafka.TLSEnabled {
		dst.Kafka.TLSEnabled = src.Kafka.TLSEnabled
	}
	if dst.Kafka.SASLEnabled == false && src.Kafka.SASLEnabled {
		dst.Kafka.SASLEnabled = src.Kafka.SASLEnabled
	}
	if dst.Kafka.Username == "" {
		dst.Kafka.Username = src.Kafka.Username
	}
	if dst.Kafka.PasswordEnv == "" {
		dst.Kafka.PasswordEnv = src.Kafka.PasswordEnv
	}
	if dst.Kafka.MaskSensitive == false && src.Kafka.MaskSensitive {
		dst.Kafka.MaskSensitive = src.Kafka.MaskSensitive
	}
	// その他 필드는 단순 가중 함수로 처리할 수 있음
}

// applyPreset: 선택된 프리셋 값을 cfg에 채운다 (단 CLI에서 이미 설정한 값은 덮어씌우지 않는다)
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
		preset.MaxDepth = 0 // unlimited
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
		// unknown preset ignored
		return
	}
	// merge only zero / unset values
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
