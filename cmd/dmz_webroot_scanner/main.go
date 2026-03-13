package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/heartblast/dmz_webroot_scanner/internal/config"
	"github.com/heartblast/dmz_webroot_scanner/internal/input"
	"github.com/heartblast/dmz_webroot_scanner/internal/report"
	"github.com/heartblast/dmz_webroot_scanner/internal/root"
	"github.com/heartblast/dmz_webroot_scanner/internal/rules"
	"github.com/heartblast/dmz_webroot_scanner/internal/scan"
)

// printFlagGroup: 플래그들을 그룹 이름과 함께 출력
func printFlagGroup(title string, names []string) {
	fmt.Fprintf(os.Stderr, "%s:\n", title)
	for _, n := range names {
		if f := flag.Lookup(n); f != nil {
			fmt.Fprintf(os.Stderr, "  --%s\t%s\n", f.Name, f.Usage)
		}
	}
	fmt.Fprintln(os.Stderr)
}

// main: 웹루트 스캔 도구의 메인 진입점
// 1단계: Nginx/Apache 설정 및 수동 디렉토리로부터 웹루트 수집
// 2단계: 설정된 규칙 세트로 웹루트 내 파일 스캔
// 3단계: 발견된 위험한 파일들을 JSON 리포트로 출력
func main() {
	// 커스텀 help 메시지 설정 (옵션을 그룹별로 정리)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "NICE INFORMATION SERVICE\n")
		fmt.Fprintf(os.Stderr, "DMZ Webroot Scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		printFlagGroup("INPUT OPTIONS", []string{"server-type", "nginx-dump", "apache-dump", "watch-dir", "config"})
		printFlagGroup("SCAN/DEPTH OPTIONS", []string{"scan", "exclude", "max-depth", "newer-than-h", "workers", "hash", "max-size-mb", "follow-symlink"})
		printFlagGroup("POLICY/RULE OPTIONS", []string{"allow-mime-prefix", "allow-ext", "enable-rules", "disable-rules", "preset"})
		printFlagGroup("CONTENT SCAN OPTIONS", []string{"content-scan", "content-max-bytes", "content-max-size-kb", "content-ext"})
		printFlagGroup("OUTPUT OPTIONS", []string{"out"})
		printFlagGroup("KAFKA OPTIONS", []string{"kafka-enabled", "kafka-brokers", "kafka-topic", "kafka-client-id", "kafka-tls", "kafka-sasl-enabled", "kafka-username", "kafka-password-env", "kafka-mask-sensitive"})
	}

	// cfg: 커맨드라인 플래그 및 설정파일을 병합한 최종 설정값
	cfg := config.MustParseFlags()

	// 입력/서버 타입 검증
	if err := validateInputCombination(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// final configuration logging for transparency
	fmt.Fprintf(os.Stderr, "Final configuration: %+v\n", cfg)

	// rep: 최종 보고서 구조체. 리포트 메타데이터 초기화
	rep := report.Report{
		ReportVersion: "1.0",                           // 리포트 포맷 버전
		GeneratedAt:   time.Now().Format(time.RFC3339), // 리포트 생성 시각
		Inputs:        []string{},                      // 입력 소스 목록 (nginx/apache 설정파일 경로)
		Config:        cfg,                             // 실행 시 사용된 설정값
	}

	// host: 스캔을 수행하는 호스트명
	host, _ := os.Hostname()
	rep.Host = host

	// [1단계] roots 수집: Nginx/Apache 설정 및 수동 입력으로부터 웹루트 경로 수집
	// roots: 스캔할 웹루트 디렉토리 목록
	roots := make([]root.RootEntry, 0, 32)

	// Nginx 설정 파일 처리: 'nginx -T' 출력으로부터 root/alias 디렉토리 추출
	if cfg.NginxDump != "" {
		if cfg.ServerType == "" {
			cfg.ServerType = "nginx"
		}
		rep.Inputs = append(rep.Inputs, "nginx-dump:"+cfg.NginxDump) // 입력 소스 기록
		b, err := input.ReadAllMaybeStdin(cfg.NginxDump)             // 파일 또는 stdin에서 읽기
		must(err, "read nginx dump")
		roots = append(roots, input.ParseNginxDump(b)...) // 정규식으로 root/alias 디렉토리 파싱
	}

	// Apache 설정 파일 처리: 'apachectl -S' 출력으로부터 DocumentRoot 디렉토리 추출
	if cfg.ApacheDump != "" {
		if cfg.ServerType == "" {
			cfg.ServerType = "apache"
		}
		rep.Inputs = append(rep.Inputs, "apache-dump:"+cfg.ApacheDump) // 입력 소스 기록
		b, err := input.ReadAllMaybeStdin(cfg.ApacheDump)              // 파일 또는 stdin에서 읽기
		must(err, "read apache dump")
		roots = append(roots, input.ParseApacheDump(b)...) // 정규식으로 DocumentRoot 디렉토리 파싱
	}

	// 수동으로 지정된 감시 디렉토리 추가
	for _, d := range cfg.WatchDirs {
		roots = append(roots, root.RootEntry{
			Path:   d,
			Source: root.SourceManual, // 소스 표기: 수동 입력
		})
	}

	// roots 정규화: 중복 제거, symlink 해석, 경로 정리
	roots = root.NormalizeRoots(roots)
	rep.Roots = roots                 // 리포트에 수집된 웹루트 기록
	rep.Stats.RootsCount = len(roots) // 통계: 수집된 루트 개수

	// [2단계] 선택적 스캔 실행 (scan 플래그가 활성화된 경우에만)
	// cfg.Scan이 false면 웹루트 수집만 하고 스캔은 건너뜀
	if cfg.Scan {
		// 활성/비활성 룰 세트 처리: enable/disable lists가 있으면 기본 구성 위에 적용
		ruleSet := makeRuleSet(cfg)
		// 활성 룰 이름 목록을 리포트에 담아둠
		ruleNames := []string{}
		for _, r := range ruleSet {
			ruleNames = append(ruleNames, r.Name())
		}
		rep.ActiveRules = ruleNames

		// sc: 스캐너 인스턴스 생성 및 스캔 실행
		sc := scan.Scanner{
			Cfg:   cfg,     // 스캔 설정 (깊이, 제외 경로, 워커 수 등)
			Rules: ruleSet, // 적용할 규칙 세트
		}

		// findings: 의심 파일 목록, scanned: 검사한 총 파일 수
		findings, scanned := sc.ScanRoots(roots)
		rep.Findings = findings                 // 리포트에 발견 결과 저장
		rep.Stats.ScannedFiles = scanned        // 통계: 검사된 파일 수
		rep.Stats.FindingsCount = len(findings) // 통계: 의심 파일 수
	}

	// [3단계] 리포트 출력 (JSON 파일 또는 stdout)
	must(report.Write(rep, cfg.Output), "write report")

	// Kafka 전송 (옵션 활성화 시)
	if cfg.Kafka.Enabled {
		err := report.SendToKafka(rep, cfg.Kafka)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: kafka send failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "INFO: kafka event sent to %s\n", cfg.Kafka.Topic)
		}
	}
}

// lowerSlice: 문자열 슬라이스의 모든 요소를 소문자로 변환하고 공백 제거
// in: 입력 문자열 배열
// 반환: 정규화된 소문자 문자열 배열
func lowerSlice(in []string) []string {
	out := make([]string, 0, len(in)) // 결과 저장소
	for _, s := range in {
		// 각 문자열의 공백 제거 후 소문자로 변환
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

// validateInputCombination: 서버 타입과 입력 플래그 조합을 검증
func validateInputCombination(cfg config.Config) error {
	// 기존 호환성 유지: 아무 옵션이 없어도 오류 아님
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
		// watch-dir가 없으면 warn but allow
		if len(cfg.WatchDirs) == 0 {
			return fmt.Errorf("server-type manual requires at least one --watch-dir")
		}
	default:
		return fmt.Errorf("unknown server-type '%s'", cfg.ServerType)
	}
	return nil
}

// makeRuleSet: config에서 enable/disable 목록을 읽어 룰 객체 슬라이스 생성
func makeRuleSet(cfg config.Config) []rules.Rule {
	// 기본 룰 목록 (기존과 동일)
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

	// 콘텐츠 스캔 함수
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

	// enable/disable filtering
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

	// report 활성 룰 기록
	// rep는 여기 접근 불가; 대신 메인에서 따로 설정
	return rulesList
}

// must: 에러 처리 헬퍼 함수
// 에러가 발생했을 경우 메시지와 함께 프로그램 종료
// err: 확인할 에러 값
// msg: 에러 메시지 앞에 붙을 설명 문구
func must(err error, msg string) {
	if err == nil {
		return
	}
	// 에러 메시지를 표준 에러 출력으로 저장
	fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", msg, err)
	// 프로그램 비정상 종료 (exit code 1)
	os.Exit(1)
}

// defaultHighRiskExt: 웹루트에서 발견 시 심각한 위협인 파일 확장자 목록
// 반환: 위험한 확장자를 key로 하는 맵 (검색 성능 O(1))
func defaultHighRiskExt() map[string]bool {
	return map[string]bool{
		// 압축 파일 형식
		".zip": true, ".tar": true, ".tgz": true, ".gz": true, ".7z": true, ".rar": true,
		// 데이터베이스/데이터 파일
		".sql": true, ".csv": true, ".xlsx": true, ".xls": true, ".jsonl": true,
		// 서버 측 스크립트 언어
		".php": true, ".phtml": true, ".phar": true, ".cgi": true, ".pl": true, ".py": true, ".rb": true,
		// Java/ASP 웹 스크립트
		".jsp": true, ".jspx": true, ".asp": true, ".aspx": true,
		// 바이너리 실행 파일
		".exe": true, ".dll": true, ".so": true, ".bin": true, ".sh": true,
	}
}
