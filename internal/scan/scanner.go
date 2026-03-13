package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/heartblast/dmz_webroot_scanner/internal/config"
	"github.com/heartblast/dmz_webroot_scanner/internal/model"
	"github.com/heartblast/dmz_webroot_scanner/internal/report"
	"github.com/heartblast/dmz_webroot_scanner/internal/root"
	"github.com/heartblast/dmz_webroot_scanner/internal/rules"
)

type Scanner struct {
	Cfg   config.Config
	Rules []rules.Rule
}

// ScanRoots: 웹루트 목록을 스캔하여 의심 파일 검사
// roots: 검사할 웹루트 디렉토리 목록
// 반환: 발견된 의심 파일(Finding) 목록, 검사한 총 파일 수
func (s *Scanner) ScanRoots(roots []root.RootEntry) ([]report.Finding, int) {
	var scanned int64

	findCh := make(chan report.Finding, 256)
	pathCh := make(chan walkItem, 1024)

	workers := s.Cfg.Workers
	if workers <= 0 {
		workers = 1
	}

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for it := range pathCh {
				atomic.AddInt64(&scanned, 1)

				ctx, ok := s.buildFileCtx(it)
				if !ok {
					continue
				}

				reasons := s.evalRules(ctx)
				if len(reasons) == 0 {
					continue
				}

				f := report.Finding{
					Path:                 ctx.Path,
					RealPath:             ctx.RealPath,
					Size:                 ctx.Size,
					ModTime:              ctx.ModTime.Format(time.RFC3339),
					Perm:                 ctx.Perm,
					Ext:                  ctx.Ext,
					MimeSniff:            ctx.Mime,
					Reasons:              toCodes(reasons),
					Severity:             maxSeverity(reasons).String(),
					URLExposureHeuristic: "potentially_web_reachable",
					RootMatched:          ctx.RootPath,
					RootSource:           string(ctx.RootSource),
					MatchedPatterns:      []string{},
					EvidenceMasked:       []string{},
					ContentFlags:         "",
				}

				if ctx.ContentSample != "" && ctx.ContentTruncated {
					f.ContentFlags = "truncated"
				}

				for _, r := range reasons {
					if strings.HasPrefix(r.Code, "connection_") ||
						strings.HasPrefix(r.Code, "credential_") ||
						strings.HasPrefix(r.Code, "private_key_") ||
						strings.HasPrefix(r.Code, "combo_") ||
						strings.HasPrefix(r.Code, "internal_") {
						f.MatchedPatterns = append(f.MatchedPatterns, r.Code)
						if r.Message != "" {
							f.EvidenceMasked = append(f.EvidenceMasked, r.Message)
						}
					}
				}

				findCh <- f
			}
		}()
	}

	go func() {
		defer close(pathCh)
		for _, r := range roots {
			walkRoot(r, s.Cfg, pathCh)
		}
	}()

	go func() {
		wg.Wait()
		close(findCh)
	}()

	findings := make([]report.Finding, 0, 128)
	for f := range findCh {
		findings = append(findings, f)
	}

	sort.Slice(findings, func(i, j int) bool {
		if len(findings[i].Reasons) != len(findings[j].Reasons) {
			return len(findings[i].Reasons) > len(findings[j].Reasons)
		}
		if findings[i].Size != findings[j].Size {
			return findings[i].Size > findings[j].Size
		}
		return findings[i].Path < findings[j].Path
	})

	return findings, int(scanned)
}

// evalRules: 파일에 대해 모든 검사 규칙을 평가
// ctx: 평가할 파일 정보
// 반환: 모든 규칙에서 반환한 Reason 목록 (없으면 빈 슬라이스)
func (s *Scanner) evalRules(ctx model.FileCtx) []rules.Reason {
	out := make([]rules.Reason, 0, 4)
	for _, r := range s.Rules {
		out = append(out, r.Evaluate(ctx)...)
	}
	return out
}

// toCodes: Reason 배열의 코드만 추출하여 문자열 배열로 변환
// rs: Reason 배열
// 반환: 코드 문자열 배열 (예: [\"mime_not_in_allowlist\", \"ext_not_in_allowlist\"])
func toCodes(rs []rules.Reason) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Code)
	}
	return out
}

// maxSeverity: Reason 배열에서 가장 높은 심각도를 찾음
// rs: Reason 배열
// 반환: 가장 높은 Severity 값 (없으면 SevLow)
func maxSeverity(rs []rules.Reason) rules.Severity {
	max := rules.SevLow
	for _, r := range rs {
		if r.Severity > max {
			max = r.Severity
		}
	}
	return max
}

// buildFileCtx: 파일 정보로부터 검사에 필요한 컨텍스트 정보 구성
// 수행 작업: 수정 시간 필터링, 파일 권한 추출, MIME 스니프, symlink 해석
func (s *Scanner) buildFileCtx(it walkItem) (model.FileCtx, bool) {
	info := it.Info
	path := it.Path

	// newer-than 필터: 최근 N시간 내 수정된 파일만 검사
	if s.Cfg.NewerThanH > 0 {
		cut := time.Now().Add(-time.Duration(s.Cfg.NewerThanH) * time.Hour)
		if info.ModTime().Before(cut) {
			return model.FileCtx{}, false // 오래된 파일이므로 스킵
		}
	}

	// 파일 확장자 추출 (소문자로 정규화)
	ext := strings.ToLower(filepath.Ext(path))
	// 파일 권한을 문자열로 변환 (예: -rw-r--r--)
	perm := info.Mode().Perm().String()

	// symlink 해석하여 실제 경로 찾기
	real := ""
	if rp, err := filepath.EvalSymlinks(path); err == nil {
		real = rp
	}

	// MIME 타입 스니프: 파일의 처음 512바이트로 MIME 타입 감지
	mime := "unknown"
	if info.Size() == 0 {
		mime = "application/octet-stream" // 빈 파일
	} else {
		if m, err := sniffMime(path, 512); err == nil && m != "" {
			mime = m
		}
	}

	// 콘텐츠 샘플 읽기 (선택적): 텍스트성 파일에서 민감정보 패턴 탐지용
	contentSample := ""
	contentSampleBytes := 0
	contentTruncated := false
	if s.Cfg.ContentScan {
		extMap := make(map[string]bool)
		for _, e := range s.Cfg.ContentExts {
			extMap[strings.ToLower(strings.TrimSpace(e))] = true
		}
		if isTextLikeExt(ext, extMap) && info.Size() > 0 && info.Size() <= s.Cfg.ContentMaxSizeKB*1024 {
			sample, readBytes, truncated, err := readContentSample(path, s.Cfg.ContentMaxBytes)
			if err == nil {
				contentSample = sample
				contentSampleBytes = readBytes
				contentTruncated = truncated
			}
		}
	}

	return model.FileCtx{
		Path:               path,
		RealPath:           real,
		RootPath:           it.Root.Path,
		RootSource:         it.Root.Source,
		Size:               info.Size(),
		ModTime:            info.ModTime(),
		Perm:               perm,
		Ext:                ext,
		Mime:               mime,
		ContentSample:      contentSample,
		ContentSampleBytes: contentSampleBytes,
		ContentTruncated:   contentTruncated,
	}, true
}

// sha256FileBounded: 파일의 SHA256 해시를 계산 (최대 바이트 제한 포함)
// path: 해시를 계산할 파일 경로
// maxBytes: 읽을 최대 바이트 수 (0이면 제한 없음)
// 반환: 16진법 SHA256 해시 문자열, 오류
func sha256FileBounded(path string, maxBytes int64) (string, error) {
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
			if err == io.EOF {
				break
			}
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isTextLikeExt: 파일 확장자가 텍스트성(텍스트 기반 설정 파일 등)인지 판단
// ext: 소문자 확장자 (예: ".yaml", ".json")
// contentExts: 콘텐츠 스캔 대상 확장자 맵
// 반환: 텍스트성 파일이면 true
func isTextLikeExt(ext string, contentExts map[string]bool) bool {
	if len(contentExts) == 0 {
		// 기본값이 있으면 여기서도 기본값 사용
		defaults := map[string]bool{
			".yaml": true, ".yml": true, ".json": true, ".xml": true,
			".properties": true, ".conf": true, ".env": true, ".ini": true,
			".txt": true, ".config": true, ".cfg": true, ".toml": true,
		}
		return defaults[ext]
	}
	return contentExts[ext]
}

// readContentSample: 파일에서 텍스트 샘플을 읽음 (최대 바이트 제한)
// path: 파일 경로
// maxBytes: 읽을 최대 바이트 수
// 반환: 샘플 문자열, 실제 읽은 바이트 수, 파일이 잘렸는지 여부, 에러
func readContentSample(path string, maxBytes int) (string, int, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false, err
	}
	defer f.Close()

	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return "", n, false, err
	}

	// 파일이 maxBytes보다 큰지 확인
	truncated := false
	var fileSize int64
	if fi, err := f.Stat(); err == nil {
		fileSize = fi.Size()
		truncated = fileSize > int64(maxBytes)
	}

	// 바이트 배열을 문자열로 변환 (유효한 UTF-8만 포함)
	// 바이너리 데이터는 제외하기 위해 간단한 검증
	sample := string(buf[:n])

	// 제어 문자나 널 바이트가 많으면 바이너리로 간주 (스킵)
	if isBinaryContent(buf[:n]) {
		return "", n, truncated, nil
	}

	return sample, n, truncated, nil
}

// isBinaryContent: 바이트 배열이 바이너리(텍스트가 아닌) 데이터로 보이는지 판단
func isBinaryContent(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}

	// 처음 512 바이트 중 널 바이트가 1개 이상이면 바이너리로 간주
	nullCount := 0
	for _, b := range buf {
		if b == 0 {
			nullCount++
		}
	}

	// 널 바이트가 1% 이상이면 바이너리
	if nullCount > len(buf)/100 {
		return true
	}

	// 제어 문자 비율 확인
	controlCount := 0
	for _, b := range buf {
		if b < 32 && b != '\t' && b != '\n' && b != '\r' {
			controlCount++
		}
	}

	// 제어 문자가 5% 이상이면 바이너리
	if controlCount > len(buf)/20 {
		return true
	}

	return false
}
