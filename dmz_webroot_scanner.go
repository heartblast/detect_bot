// dmz_webroot_scanner.go
//
// 목적:
//  - Apache(httpd)/Nginx 설정을 "덤프 출력"에서 파싱하여 웹서빙 경로(DocumentRoot/root/alias)를 자동 수집
//  - 수집된 경로(웹루트/alias)를 기준으로 용도 부적합 파일(스테이징 반출 징후)을 탐지
//
// 권장 사용 방식(정확도 우선):
//  - Nginx:  nginx -T 2>&1 | dmz_webroot_scanner --nginx-dump -
//  - Apache: apachectl -S 2>&1 | dmz_webroot_scanner --apache-dump -
// 또는 파일로 저장 후:
//  - dmz_webroot_scanner --nginx-dump /path/nginx_T.txt --apache-dump /path/apache_S.txt --scan
//
// 주의:
//  - 본 코드는 "덤프 출력" 기반 파싱을 우선합니다(Include 확장 누락 감소).
//  - MIME 판별은 net/http.DetectContentType(최대 512B sniff) 기반이라 100% 정확하지 않습니다.
//  - 운영 영향 최소화를 위해 크기 제한, 제외 경로, 샘플링/시간 제한 옵션을 활용하세요.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type RootSource string

const (
	SourceNginxRoot  RootSource = "nginx.root"
	SourceNginxAlias RootSource = "nginx.alias"
	SourceApacheDR   RootSource = "apache.documentroot"
	SourceManual     RootSource = "manual"
)

type RootEntry struct {
	Path        string     `json:"path"`
	RealPath    string     `json:"real_path,omitempty"`
	Source      RootSource `json:"source"`
	ContextHint string     `json:"context_hint,omitempty"` // server_name, vhost, file:line 등 힌트
}

type Finding struct {
	Path                 string   `json:"path"`
	RealPath             string   `json:"real_path,omitempty"`
	Size                 int64    `json:"size_bytes"`
	ModTime              string   `json:"mod_time"`
	OwnerHint            string   `json:"owner_hint,omitempty"` // (옵션) 확장 가능: uid/gid
	Perm                 string   `json:"perm"`
	Ext                  string   `json:"ext"`
	MimeSniff            string   `json:"mime_sniff"`
	Reasons              []string `json:"reasons"`
	SHA256               string   `json:"sha256,omitempty"`
	URLExposureHeuristic string   `json:"url_exposure_heuristic,omitempty"`
	RootMatched          string   `json:"root_matched,omitempty"`
	RootSource           string   `json:"root_source,omitempty"`
}

type Report struct {
	GeneratedAt string      `json:"generated_at"`
	Host        string      `json:"host,omitempty"`
	Inputs      []string    `json:"inputs"`
	Roots       []RootEntry `json:"roots"`
	Findings    []Finding   `json:"findings"`
	Stats       struct {
		RootsCount    int `json:"roots_count"`
		ScannedFiles  int `json:"scanned_files"`
		FindingsCount int `json:"findings_count"`
	} `json:"stats"`
}

type Config struct {
	NginxDump     string
	ApacheDump    string
	Scan          bool
	Output        string
	MaxDepth      int
	MaxSizeMB     int64
	NewerThanH    int
	Exclude       multiFlag
	AllowMimePref multiFlag
	AllowExt      multiFlag
	WatchDirs     multiFlag
	ComputeHash   bool
	FollowSymlink bool
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error {
	if s == "" {
		return nil
	}
	*m = append(*m, s)
	return nil
}

func main() {
	// 스캐너 바이너리의 진입점. 전체 워크플로우는:
	// 1. 커맨드라인 플래그를 구성(Config)으로 파싱
	// 2. 보고서 메타데이터 초기화(타임스탬프, 호스트명, 입력들)
	// 3. nginx/apache 덤프 또는 수동 감시 디렉토리를 읽어
	//    후보 문서 루트 수집
	// 4. 루트들을 정규화하고 중복 제거
	// 5. 선택적으로 각 루트에 대해 파일시스템 스캔 수행
	// 6. 결과 보고서를 JSON으로 직렬화(stdout 또는 파일)
	// 코드 읽기가 쉬워지도록 하이레벨 순서를 여기에 기술함.
	cfg := mustParseFlags()

	rep := Report{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Inputs:      []string{},
	}

	host, _ := os.Hostname()
	rep.Host = host

	roots := make([]RootEntry, 0, 32)

	// 1) Parse nginx dump
	if cfg.NginxDump != "" {
		rep.Inputs = append(rep.Inputs, "nginx-dump:"+cfg.NginxDump)
		b, err := readAllMaybeStdin(cfg.NginxDump)
		if err != nil {
			fatalf("failed to read nginx dump: %v", err)
		}
		roots = append(roots, parseNginxDump(b)...)
	}

	// 2) Parse apache dump
	if cfg.ApacheDump != "" {
		rep.Inputs = append(rep.Inputs, "apache-dump:"+cfg.ApacheDump)
		b, err := readAllMaybeStdin(cfg.ApacheDump)
		if err != nil {
			fatalf("failed to read apache dump: %v", err)
		}
		roots = append(roots, parseApacheDump(b)...)
	}

	// 3) Add manual watch dirs (optional)
	for _, d := range cfg.WatchDirs {
		roots = append(roots, RootEntry{
			Path:   d,
			Source: SourceManual,
		})
	}

	// Normalize roots (dedupe, realpath)
	roots = normalizeRoots(roots)
	rep.Roots = roots
	rep.Stats.RootsCount = len(roots)

	// 4) Scan
	if cfg.Scan {
		findings, scanned := scanRoots(roots, cfg)
		rep.Findings = findings
		rep.Stats.ScannedFiles = scanned
		rep.Stats.FindingsCount = len(findings)
	}

	// 5) Output
	if err := writeReport(rep, cfg.Output); err != nil {
		fatalf("write report: %v", err)
	}
}

func mustParseFlags() Config {
	// 커맨드라인 인자를 Config 구조체로 변환하고
	// 허용 목록에 합리적 기본값을 채우며 기본 유효성 검사를 수행.
	// 잘못된 구성은 여기서 프로그램 종료를 유발.
	var cfg Config
	flag.StringVar(&cfg.NginxDump, "nginx-dump", "", "path to nginx -T dump output file, or '-' for stdin")
	flag.StringVar(&cfg.ApacheDump, "apache-dump", "", "path to apachectl -S dump output file, or '-' for stdin")
	flag.BoolVar(&cfg.Scan, "scan", false, "scan discovered roots for suspicious files")
	flag.StringVar(&cfg.Output, "out", "report.json", "output JSON report path ('-' for stdout)")
	flag.IntVar(&cfg.MaxDepth, "max-depth", 12, "max directory recursion depth")
	flag.Int64Var(&cfg.MaxSizeMB, "max-size-mb", 100, "max file size (MB) to read for MIME sniff/hash")
	flag.IntVar(&cfg.NewerThanH, "newer-than-h", 0, "only flag files modified within last N hours (0=disable)")
	flag.Var(&cfg.Exclude, "exclude", "exclude path prefix (repeatable). Example: --exclude /var/www/html/cache")
	flag.Var(&cfg.AllowMimePref, "allow-mime-prefix", "allowed MIME prefixes (repeatable). Example: --allow-mime-prefix text/html --allow-mime-prefix image/")
	flag.Var(&cfg.AllowExt, "allow-ext", "allowed extensions (repeatable). Example: --allow-ext .html --allow-ext .css")
	flag.Var(&cfg.WatchDirs, "watch-dir", "manual watch directory to include (repeatable)")
	flag.BoolVar(&cfg.ComputeHash, "hash", false, "compute SHA256 for findings (reads file up to max-size-mb)")
	flag.BoolVar(&cfg.FollowSymlink, "follow-symlink", false, "follow symlinks (not recommended in DMZ scans)")
	flag.Parse()

	// Reasonable defaults if user didn't provide allowlist:
	// DMZ 정적 웹 서버를 상정한 최소 allowlist (필요 시 옵션으로 변경)
	if len(cfg.AllowMimePref) == 0 {
		cfg.AllowMimePref = []string{
			"text/html",
			"text/css",
			"application/javascript",
			"text/javascript",
			"application/json",
			"image/",
			"font/",
			"application/font-",
			"application/xml", // sitemap.xml 등 조건부(파일명 제한은 별도 구현 가능)
			"text/plain",      // robots.txt/security.txt 등 조건부(파일명 제한은 별도 구현 가능)
		}
	}
	if len(cfg.AllowExt) == 0 {
		cfg.AllowExt = []string{
			".html", ".htm", ".css", ".js", ".mjs", ".json", ".xml", ".txt",
			".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
			".woff", ".woff2", ".ttf", ".otf", ".eot",
		}
	}

	// Basic validation
	if cfg.NginxDump == "" && cfg.ApacheDump == "" && len(cfg.WatchDirs) == 0 {
		// Still allow scanning if user provided watch-dir only, but if none at all, warn by failing early.
		// However don't require scan; user may only want parse.
		if cfg.Scan {
			fatalf("no input roots: provide --nginx-dump and/or --apache-dump and/or --watch-dir")
		}
	}
	return cfg
}

func readAllMaybeStdin(pathOrDash string) ([]byte, error) {
	// 지정한 파일에서 읽거나, pathOrDash가 "-"이면 stdin에서 읽는 유틸리티.
	// nginx/apache 덤프를 파이프로 전달할 때 편리.
	var r io.Reader
	if pathOrDash == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(pathOrDash)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return io.ReadAll(r)
}

func writeReport(rep Report, out string) error {
	// 보고서 구조를 들여쓰기된 JSON으로 직렬화. 출력이 "-"이면
	// 표준 출력, 그렇지 않으면 지정 파일을 생성/덮어씀.
	var w io.Writer
	if out == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", a...)
	os.Exit(1)
}

func normalizeRoots(in []RootEntry) []RootEntry {
	seen := map[string]RootEntry{}
	for _, r := range in {
		p := strings.TrimSpace(r.Path)
		if p == "" {
			continue
		}
		// remove trailing ; if any artifacts
		p = strings.TrimRight(p, ";")
		p = strings.Trim(p, `"'`)

		// Normalize path separators and clean
		p = filepath.Clean(p)

		real := ""
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			real = rp
		}

		key := p
		if real != "" {
			key = real
		}

		if existing, ok := seen[key]; ok {
			// Prefer more specific source? keep first, but merge hints
			if existing.ContextHint == "" && r.ContextHint != "" {
				existing.ContextHint = r.ContextHint
				seen[key] = existing
			}
			continue
		}

		r.Path = p
		r.RealPath = real
		seen[key] = r
	}

	out := make([]RootEntry, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out
}

// Nginx dump parsing (nginx -T)
//   - root <path>;
//   - alias <path>;
//
// We try to capture context hints like "server_name" lines nearby.
func parseNginxDump(b []byte) []RootEntry {
	sc := bufio.NewScanner(bytes.NewReader(b))
	// Increase scanner buffer for big configs
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 10*1024*1024)

	reRoot := regexp.MustCompile(`(?i)^\s*root\s+([^;#]+);`)
	reAlias := regexp.MustCompile(`(?i)^\s*alias\s+([^;#]+);`)
	reServerName := regexp.MustCompile(`(?i)^\s*server_name\s+([^;#]+);`)
	reConfFileLine := regexp.MustCompile(`(?i)^#\s*configuration\s+file\s+(.+?):(\d+)`)

	var lastServerName string
	var lastFileLine string

	out := []RootEntry{}
	for sc.Scan() {
		line := sc.Text()

		if m := reConfFileLine.FindStringSubmatch(line); len(m) == 3 {
			lastFileLine = fmt.Sprintf("%s:%s", strings.TrimSpace(m[1]), m[2])
		}
		if m := reServerName.FindStringSubmatch(line); len(m) == 2 {
			lastServerName = strings.TrimSpace(m[1])
		}
		if m := reRoot.FindStringSubmatch(line); len(m) == 2 {
			p := strings.TrimSpace(m[1])
			out = append(out, RootEntry{
				Path:        p,
				Source:      SourceNginxRoot,
				ContextHint: joinHint(lastFileLine, "server_name="+lastServerName),
			})
		}
		if m := reAlias.FindStringSubmatch(line); len(m) == 2 {
			p := strings.TrimSpace(m[1])
			out = append(out, RootEntry{
				Path:        p,
				Source:      SourceNginxAlias,
				ContextHint: joinHint(lastFileLine, "server_name="+lastServerName),
			})
		}
	}
	return out
}

// Apache dump parsing (apachectl -S)
// We look for patterns like:
//
//	port 80 namevhost example.com (/etc/httpd/conf.d/site.conf:1)
//	alias example.com
//
// and we then attempt to locate "DocumentRoot" lines if present in dump (it often isn't).
//
// In practice, apachectl -S doesn't print DocumentRoot reliably.
// So we provide two strategies:
//  1. Parse any "DocumentRoot" occurrences if present in the dump text
//  2. Fallback: parse referenced vhost config file paths from -S output; user can feed those files separately
//     (or you can extend this program to read them).
//
// For "this 수준" we include (1) and also capture vhost file paths as hints.
func parseApacheDump(b []byte) []RootEntry {
	s := string(b)

	// If dump includes DocumentRoot lines:
	reDR := regexp.MustCompile(`(?i)\bDocumentRoot\s+"?([^"\r\n]+)"?`)
	// Vhost hints: (.../file.conf:line)
	reVhost := regexp.MustCompile(`\(([^():\r\n]+):(\d+)\)`)

	out := []RootEntry{}

	// Collect DocumentRoot if present
	for _, m := range reDR.FindAllStringSubmatch(s, -1) {
		if len(m) == 2 {
			out = append(out, RootEntry{
				Path:        strings.TrimSpace(m[1]),
				Source:      SourceApacheDR,
				ContextHint: "from apachectl -S dump",
			})
		}
	}

	// Collect vhost config file hints (not roots but useful context)
	// If no DocumentRoot found, we still output nothing as roots here.
	// But we keep file hints as ContextHint if user also passes watch-dir manually.
	_ = reVhost // currently unused in root collection

	return out
}

func joinHint(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " | " + b
}

// Scanning logic
func scanRoots(roots []RootEntry, cfg Config) ([]Finding, int) {
	// 각 후보 웹 루트를 순회하면서 제외 규칙, 깊이 제한, 시간/크기 필터를 적용.
	// 각 파일은 MIME을 sniff하고 허용 목록/휴리스틱과 비교. 정책 위반 파일은
	// Finding으로 기록. 반환값은 Finding 슬라이스와 방문한 파일 수.
	findings := []Finding{}
	scanned := 0

	exclude := normalizePrefixes(cfg.Exclude)

	now := time.Now()
	var newerThan time.Time
	if cfg.NewerThanH > 0 {
		newerThan = now.Add(-time.Duration(cfg.NewerThanH) * time.Hour)
	}

	maxSize := cfg.MaxSizeMB * 1024 * 1024

	allowMimePref := make([]string, 0, len(cfg.AllowMimePref))
	for _, p := range cfg.AllowMimePref {
		allowMimePref = append(allowMimePref, strings.ToLower(strings.TrimSpace(p)))
	}

	allowExt := map[string]bool{}
	for _, e := range cfg.AllowExt {
		allowExt[strings.ToLower(e)] = true
	}

	// High-risk patterns/extensions frequently used for staging or execution
	highRiskExt := map[string]bool{
		".zip": true, ".tar": true, ".tgz": true, ".gz": true, ".7z": true, ".rar": true,
		".sql": true, ".csv": true, ".xlsx": true, ".xls": true, ".jsonl": true,
		".php": true, ".phtml": true, ".phar": true, ".cgi": true, ".pl": true, ".py": true, ".rb": true,
		".jsp": true, ".jspx": true, ".asp": true, ".aspx": true,
		".exe": true, ".dll": true, ".so": true, ".bin": true, ".sh": true,
	}

	for _, r := range roots {
		rootPath := r.Path
		if rootPath == "" {
			continue
		}

		// If root doesn't exist, skip
		if _, err := os.Stat(rootPath); err != nil {
			continue
		}

		// Walk
		filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // ignore unreadable parts
			}

			// Exclude prefixes
			if isExcluded(path, exclude) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}

			// Depth limit
			if cfg.MaxDepth > 0 {
				if depth(rootPath, path) > cfg.MaxDepth {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
			}

			// Symlink policy
			if !cfg.FollowSymlink && d.Type()&os.ModeSymlink != 0 {
				// do not follow
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				return nil
			}

			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}

			scanned++

			// Time filter
			if !newerThan.IsZero() {
				if info.ModTime().Before(newerThan) {
					return nil
				}
			}

			// Size filter for reading/sniffing
			size := info.Size()
			if size < 0 {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			perm := info.Mode().Perm().String()

			// Sniff MIME (read up to 512 bytes)
			mime := "unknown"
			if size == 0 {
				mime = "application/octet-stream"
			} else {
				m, e := sniffMime(path, 512)
				if e == nil && m != "" {
					mime = m
				}
			}

			reasons := []string{}

			// Rule 1: 허용 목록 위반 (MIME) - 감지된 MIME이 허용된 접두어 중
			// 하나로 시작하지 않으면 플래그.
			if !mimeAllowed(mime, allowMimePref) {
				reasons = append(reasons, "mime_not_in_allowlist")
			}

			// Rule 2: 허용 목록 위반 (확장자) - 허용된 정적 파일 접미사 목록에 없음.
			if ext != "" && !allowExt[ext] {
				reasons = append(reasons, "ext_not_in_allowlist")
			}

			// Rule 3: 의심스러운 확장자 - 스테이징이나 코드 실행과 관련된
			// 일반적인 압축/데이터/스크립트 확장자.
			if highRiskExt[ext] {
				reasons = append(reasons, "high_risk_extension")
			}

			// Rule 4: 웹 서비스 경로의 대용량 파일 (스테이징 힌트)
			// 환경에 따라 임계값을 조정할 수 있다.
			if size >= 50*1024*1024 { // 50MB
				reasons = append(reasons, "large_file_in_web_path")
			}

			// Rule 5: 확장자 대 MIME 불일치 휴리스틱. 확장자가 이미지인데
			// MIME이 이미지가 아니거나 그 반대의 경우를 잡아낸다.
			if ext != "" {
				if isImageExt(ext) && !strings.HasPrefix(strings.ToLower(mime), "image/") {
					reasons = append(reasons, "ext_mime_mismatch_image")
				}
				if (ext == ".js" || ext == ".css" || ext == ".html") && strings.HasPrefix(strings.ToLower(mime), "application/zip") {
					reasons = append(reasons, "ext_mime_mismatch_archive")
				}
			}

			// Decide if finding
			if len(reasons) == 0 {
				return nil
			}

			real := ""
			if rp, e := filepath.EvalSymlinks(path); e == nil {
				real = rp
			}

			f := Finding{
				Path:        path,
				RealPath:    real,
				Size:        size,
				ModTime:     info.ModTime().Format(time.RFC3339),
				Perm:        perm,
				Ext:         ext,
				MimeSniff:   mime,
				Reasons:     reasons,
				RootMatched: rootPath,
				RootSource:  string(r.Source),
				// Heuristic: anything under a "root/alias" might be externally reachable
				URLExposureHeuristic: "potentially_web_reachable",
			}

			// Optional: hash (bounded by max-size-mb)
			if cfg.ComputeHash && size <= maxSize {
				if h, he := sha256File(path, maxSize); he == nil {
					f.SHA256 = h
				}
			}

			findings = append(findings, f)
			return nil
		})
	}

	// Sort findings by risk-ish: more reasons first, then size desc
	sort.Slice(findings, func(i, j int) bool {
		if len(findings[i].Reasons) != len(findings[j].Reasons) {
			return len(findings[i].Reasons) > len(findings[j].Reasons)
		}
		if findings[i].Size != findings[j].Size {
			return findings[i].Size > findings[j].Size
		}
		return findings[i].Path < findings[j].Path
	})

	return findings, scanned
}

func normalizePrefixes(in []string) []string {
	// 경로 접두사 목록 정리: 공백 제거, filepath.Clean으로 정규화,
	// 더 나은 매칭을 위해 길이에 따라 정렬. --exclude 경로에 사용.
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		out = append(out, p)
	}
	// sort longer first for slightly better match behavior
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func isExcluded(path string, prefixes []string) bool {
	// 주어진 경로가 제공된 접두사 중 하나와 정확히 일치하거나 그 하위에
	// 있으면 true를 반환. 트리 탐색 중 제외 디렉토리/파일을 건너뛸 때 사용.
	p := filepath.Clean(path)
	for _, pref := range prefixes {
		// exact or prefix match on path boundary
		if p == pref {
			return true
		}
		if strings.HasPrefix(p, pref+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func depth(root, path string) int {
	// 루트 아래의 path 상대 깊이를 경로 구분자로 계산. 루트와 같으면 0.
	// --max-depth 적용을 도와줌.
	r := filepath.Clean(root)
	p := filepath.Clean(path)
	if r == p {
		return 0
	}
	rel, err := filepath.Rel(r, p)
	if err != nil {
		return 0
	}
	if rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(os.PathSeparator)))
}

func sniffMime(path string, max int) (string, error) {
	// 파일의 최대 max 바이트를 읽어 net/http의 DetectContentType을 사용하여
	// MIME 문자열을 반환. max는 일반적으로 512 (stdlib 권장).
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, max)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		if n == 0 {
			return "", err
		}
	}
	return http.DetectContentType(buf[:n]), nil
}

func mimeAllowed(mime string, prefixes []string) bool {
	// 감지된 MIME 타입이 사용자 지정 허용 접두사(예: "image/", "text/html")
	// 중 하나와 일치하는지 확인. 정확한 일치와 단순 접두사 패턴을 지원.
	m := strings.ToLower(strings.TrimSpace(mime))
	for _, p := range prefixes {
		pp := strings.ToLower(strings.TrimSpace(p))
		if pp == "" {
			continue
		}
		// exact match
		if m == pp {
			return true
		}
		// prefix match (e.g. "image/")
		if strings.HasSuffix(pp, "/") && strings.HasPrefix(m, pp) {
			return true
		}
		// common prefix usage: "application/font-" for multiple font mimes
		if strings.HasSuffix(pp, "-") && strings.HasPrefix(m, pp) {
			return true
		}
	}
	return false
}

func isImageExt(ext string) bool {
	// MIME 불일치 휴리스틱에서 사용되는 일반 이미지 파일 접미사를
	// 식별하는 헬퍼.
	switch strings.ToLower(ext) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico":
		return true
	default:
		return false
	}
}

func sha256File(path string, maxBytes int64) (string, error) {
	// 파일의 SHA256 해시를 계산하되 maxBytes(--max-size-mb로 구성)까지만
	// 읽어 큰 객체 해싱을 피함.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	var read int64
	buf := make([]byte, 64*1024)
	for {
		if maxBytes > 0 && read >= maxBytes {
			break
		}
		n, err := f.Read(buf)
		if n > 0 {
			toWrite := n
			if maxBytes > 0 && read+int64(n) > maxBytes {
				toWrite = int(maxBytes - read)
			}
			_, _ = h.Write(buf[:toWrite])
			read += int64(toWrite)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
