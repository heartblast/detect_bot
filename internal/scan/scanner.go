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

	"dmz_webroot_scanner/internal/config"
	"dmz_webroot_scanner/internal/model"
	"dmz_webroot_scanner/internal/report"
	"dmz_webroot_scanner/internal/root"
	"dmz_webroot_scanner/internal/rules"
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

	findCh := make(chan report.Finding, 256)     // 발견된 의심 파일들을 전달하는 채널
	pathCh := make(chan walkItem, 1024)          // 탐색된 파일들을 전달하는 채널

	workers := s.Cfg.Workers  // 동시 처리 워커 스레드 수
	if workers <= 0 {
		workers = 1  // 최소 1개
	}

	var wg sync.WaitGroup
	wg.Add(workers)

	// 병렬 처리 워커: 각 워커는 pathCh에서 파일을 받아 검사
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for it := range pathCh {
				atomic.AddInt64(&scanned, 1) // 검사한 파일 수 증가 (동시성 안전)

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
				}

			// 선택 사항: SHA256 해시 계산 (max-size-mb 옵션으로 제한)
				if s.Cfg.ComputeHash && ctx.Size <= s.Cfg.MaxSizeMB*1024*1024 {
					if h, err := sha256FileBounded(ctx.Path, s.Cfg.MaxSizeMB*1024*1024); err == nil {
						f.SHA256 = h
					}
				}

				findCh <- f
			}
		}()
	}

	// Producer: 루트 디렉토리들을 순회하며 파일을 채널로 전송
	go func() {
		defer close(pathCh)
		for _, r := range roots {
			walkRoot(r, s.Cfg, pathCh)
		}
	}()

	// Closer: 모든 워커가 완료될 때까지 대기 후 결과 채널 종료
	go func() {
		wg.Wait()
		close(findCh)
	}()

	// 결과 수집: 모든 의심 파일들을 배열에 모음
	findings := make([]report.Finding, 0, 128)
	for f := range findCh {
		findings = append(findings, f)
	}

	// 정렬: 이유 많은 항목 먼저, 같으면 크기 큰 순, 마지막으로 경로명 알파벳순
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

	return model.FileCtx{
		Path:       path,
		RealPath:   real,
		RootPath:   it.Root.Path,
		RootSource: it.Root.Source,
		Size:       info.Size(),
		ModTime:    info.ModTime(),
		Perm:       perm,
		Ext:        ext,
		Mime:       mime,
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
