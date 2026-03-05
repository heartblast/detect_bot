package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"dmz_webroot_scanner/internal/config"
	"dmz_webroot_scanner/internal/root"
)

type walkItem struct {
	Path string        // 파일의 절대경로
	Info fs.FileInfo   // 파일의 메타정보 (크기, 권한, 수정시간 등)
	Root root.RootEntry // 어느 웹루트에서 발견된 파일인지
}

// walkRoot: 한 웹루트 디렉토리 아래의 모든 파일을 재귀적으로 탐색
// r: 탐색할 웹루트 정보
// cfg: 스캔 설정 (깊이 제한, 제외 경로 등)
// out: 발견된 파일을 전달할 채널
func walkRoot(r root.RootEntry, cfg config.Config, out chan<- walkItem) {
	rootPath := r.Path
	if rootPath == "" {
		return
	}
	// 루트 디렉토리 존재 여부 확인
	if _, err := os.Stat(rootPath); err != nil {
		return
	}

	// 제외할 경로 프리픁스 정규화
	exclude := normalizePrefixes(cfg.Exclude)

	_ = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// exclude
		if isExcluded(path, exclude) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// depth
		if cfg.MaxDepth > 0 && depth(rootPath, path) > cfg.MaxDepth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// symlink policy
		if !cfg.FollowSymlink && d.Type()&os.ModeSymlink != 0 {
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

		out <- walkItem{Path: path, Info: info, Root: r}
		return nil
	})
}

// normalizePrefixes: 제외 경로 프리픁스를 정규화
// 경로를 정소화하고 길이 내림차순으로 정렬 (긴 경로부터 매칭)
// in: 입력 경로 문자열 배열
// 반환: 정규화되고 정렬된 경로 배열
func normalizePrefixes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// isExcluded: 주어진 경로가 제외 목록에 포함되는지 확인
// path: 확인할 경로
// prefixes: 제외할 경로 프리픁스 배열
// 반환: 제외하면 true, 포함하면 false
func isExcluded(path string, prefixes []string) bool {
	p := filepath.Clean(path)
	for _, pref := range prefixes {
		if p == pref {
			return true
		}
		if strings.HasPrefix(p, pref+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// depth: 루트 디렉토리에서 주어진 경로까지의 깊이 계산
// root: 루트 디렉토리 경로
// path: 깊이를 계산할 경로
// 반환: 깊이 정수 값 (루트와 동일하면 0)
func depth(root, path string) int {
	r := filepath.Clean(root)
	p := filepath.Clean(path)
	if r == p {
		return 0
	}
	rel, err := filepath.Rel(r, p)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(os.PathSeparator)))
}
