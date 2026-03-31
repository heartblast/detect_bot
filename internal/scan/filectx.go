package scan

import (
	"time"

	"github.com/heartblast/detect_bot/internal/root"
)

// FileCtx: 파일 스캐닝 동안 수집된 파일 메타데이터를 저장하는 구조체
// 각 검사 규칙을 적용할 때 사용되는 데이터 단위
type FileCtx struct {
	Path       string          // 파일의 절대경로
	RealPath   string          // 심볼릭 링크 해석 후 실제 경로 (비어있을 수 있음)
	RootPath   string          // 스캔되는 단원의 웹루트 경로
	RootSource root.RootSource // 웹루트 소스 (예: nginx.root, apache.documentroot)

	Size    int64     // 파일 크기 (바이트)
	ModTime time.Time // 파일 마지막 수정 시간
	Perm    string    // 파일 권한 (예: -rw-r--r--)
	Ext     string    // 파일 확장자 (를: .html, .php)
	Mime    string    // MIME 타입 (스니프된값, 예: text/html)
}
