package config

import (
	"flag"
	"os"
	"strings"
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

// Config: 프로그램 실행에 필요한 모든 설정값을 담는 구조체
type Config struct {
	// 입력 소스
	NginxDump  string // Nginx -T 명령 출력 파일 경로 (또는 '-'로 stdin 사용)
	ApacheDump string // apachectl -S 명령 출력 파일 경로

	// 스캔 옵션
	Scan       bool   // 실제 파일 시스템 스캔 실행 여부
	Output     string // 출력 JSON 리포트 파일 경로 (또는 '-'로 stdout 사용)
	MaxDepth   int    // 디렉토리 재귀 최대 깊이
	MaxSizeMB  int64  // MIME 탐지/해시 계산 시 읽을 파일 최대 크기 (MB)
	NewerThanH int    // 마지막 N시간 내 수정된 파일만 플래그 (0=비활성화)

	// 필터 및 화이트리스트
	Exclude       MultiFlag // 제외할 경로 접두사 (반복 가능) 예: -exclude /tmp -exclude /proc
	AllowMimePref MultiFlag // 허용된 MIME 타입 프리픽스 (반복 가능)
	AllowExt      MultiFlag // 허용된 파일 확장자 (반복 가능)
	WatchDirs     MultiFlag // 수동으로 추가할 감시 디렉토리 (반복 가능)

	// 추가 기능
	ComputeHash   bool // 발견된 파일의 SHA256 해시 계산 여부
	FollowSymlink bool // 심볼릭 링크 따라가기 여부 (권장하지 않음)

	// 성능 최적화
	Workers int // 파일 스캔 워커 스레드 수 (기본값 4)

	// 민감정보 콘텐츠 스캔 옵션
	ContentScan      bool      // 파일 본문에서 민감정보 패턴 탐지 활성화
	ContentMaxBytes  int       // 콘텐츠 샘플 최대 읽기 바이트 수
	ContentMaxSizeKB int64     // 콘텐츠 스캔 대상 파일 최대 크기 (KB)
	ContentExts      MultiFlag // 콘텐츠 스캔 대상 확장자 (yaml, json, env, conf 등)
}

// MustParseFlags: 명령줄 플래그를 파싱하여 Config 구조체로 변환
// 기본값을 설정하고 잘못된 설정을 검증
func MustParseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.NginxDump, "nginx-dump", "", "path to nginx -T dump output file, or '-' for stdin")
	flag.StringVar(&cfg.ApacheDump, "apache-dump", "", "path to apachectl -S dump output file, or '-' for stdin")
	flag.BoolVar(&cfg.Scan, "scan", false, "scan discovered roots for suspicious files")
	flag.StringVar(&cfg.Output, "out", "report.json", "output JSON report path ('-' for stdout)")
	flag.IntVar(&cfg.MaxDepth, "max-depth", 12, "max directory recursion depth")
	flag.Int64Var(&cfg.MaxSizeMB, "max-size-mb", 100, "max file size (MB) to read for MIME sniff/hash")
	flag.IntVar(&cfg.NewerThanH, "newer-than-h", 0, "only flag files modified within last N hours (0=disable)")
	flag.Var(&cfg.Exclude, "exclude", "exclude path prefix (repeatable)")
	flag.Var(&cfg.AllowMimePref, "allow-mime-prefix", "allowed MIME prefixes (repeatable)")
	flag.Var(&cfg.AllowExt, "allow-ext", "allowed extensions (repeatable)")
	flag.Var(&cfg.WatchDirs, "watch-dir", "manual watch directory to include (repeatable)")
	flag.BoolVar(&cfg.ComputeHash, "hash", false, "compute SHA256 for findings")
	flag.BoolVar(&cfg.FollowSymlink, "follow-symlink", false, "follow symlinks (not recommended)")
	flag.IntVar(&cfg.Workers, "workers", 4, "number of scan workers (default 4)")
	flag.BoolVar(&cfg.ContentScan, "content-scan", false, "scan file content for sensitive information patterns")
	flag.IntVar(&cfg.ContentMaxBytes, "content-max-bytes", 65536, "max bytes to read per file for content scan (default 65536)")
	flag.Int64Var(&cfg.ContentMaxSizeKB, "content-max-size-kb", 1024, "max file size (KB) to scan for sensitive patterns (default 1024)")
	flag.Var(&cfg.ContentExts, "content-ext", "target extensions for content scan (repeatable, e.g. .yaml .json .env)")
	flag.Parse()

	// Defaults (기존 코드와 동일)
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

	// 콘텐츠 스캔 대상 확장자 기본값
	if len(cfg.ContentExts) == 0 {
		cfg.ContentExts = []string{
			".yaml", ".yml", ".json", ".xml", ".properties", ".conf",
			".env", ".ini", ".txt", ".config", ".cfg", ".toml",
		}
	}

	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}

	// 최소 입력 검증은 main에서 “scan 여부” 고려해 처리해도 됨
	_ = os.Getenv // keep imports sane if needed later
	return cfg
}
