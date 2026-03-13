//go:build windows

package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/heartblast/dmz_webroot_scanner/internal/config"
	"github.com/heartblast/dmz_webroot_scanner/internal/root"
)

func walkRoot(r root.RootEntry, cfg config.Config, out chan<- walkItem) {
	rootPath := r.Path
	if rootPath == "" {
		return
	}
	if _, err := os.Stat(rootPath); err != nil {
		return
	}

	exclude := normalizePrefixesCI(cfg.Exclude)

	_ = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 읽을 수 없는 부분은 무시
		}

		// 제외 (Windows에서 대소문자 구분 안 함)
		if isExcludedCI(path, exclude) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// 깊이 제한
		if cfg.MaxDepth > 0 && depth(rootPath, path) > cfg.MaxDepth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// 심볼링크/접합점/재분석 포인트 정책 (안전한 기본값)
		// - follow-symlink이 false면 재분석 포인트 디렉토리에 진입하지 않음
		if !cfg.FollowSymlink {
			// 빠른 경로: 명확한 심볼링크
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			// 보수적: 모든 재분석 포인트(접합점/마운트 포인트 등) 건너뛰기
			if isReparsePoint(path) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}

		if d.IsDir() {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}

		out <- walkItem{Path: path, Info: info, Root: r}
		return nil
	})
}

// isReparsePoint: FILE_ATTRIBUTE_REPARSE_POINT가 설정되면 true를 반환합니다.
// 접합점/마운트 포인트 및 심볼링크를 감지합니다.
// DMZ/IR 스캔 안전을 위해 보수적인 정책을 사용합니다.
func isReparsePoint(path string) bool {
	p := filepath.Clean(path)
	attrs, err := syscall.GetFileAttributes(syscall.StringToUTF16Ptr(p))
	if err != nil {
		return false
	}
	// 파일 속성 재분석 포인트 = 0x400
	return attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func normalizePrefixesCI(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Windows 일치를 위해 정리 및 대소문자 정규화
		cp := filepath.Clean(p)
		out = append(out, strings.ToLower(cp))
	}
	// 더 나은 일치 동작을 위해 더 긴 경로를 먼저
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func isExcludedCI(path string, prefixes []string) bool {
	p := strings.ToLower(filepath.Clean(path))
	sep := string(os.PathSeparator)

	for _, pref := range prefixes {
		// 정확한 일치
		if p == pref {
			return true
		}
		// 경계 접두사
		if strings.HasPrefix(p, pref+sep) {
			return true
		}
	}
	return false
}
