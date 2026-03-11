package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"dmz_webroot_scanner/internal/root"
)

type walkItem struct {
	Path string         // 파일의 절대경로
	Info fs.FileInfo    // 파일의 메타정보 (크기, 권한, 수정시간 등)
	Root root.RootEntry // 어느 웹루트에서 발견된 파일인지
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
