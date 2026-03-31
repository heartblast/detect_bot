package input

import (
	"regexp"
	"strings"

	"github.com/heartblast/detect_bot/internal/root"
)

// ParseApacheDump: 'apachectl -S' 명령 출력에서 DocumentRoot 디렉토리를 파싱
// b: Apache 설정 덤프 바이트 배열
// 반환: 추출된 RootEntry 배열 (각각 DocumentRoot 경로 포함)
func ParseApacheDump(b []byte) []root.RootEntry {
	s := string(b)
	// 정규식: DocumentRoot "경로" 또는 DocumentRoot 경로 형식 매칭
	// 예: DocumentRoot "/var/www" 또는 DocumentRoot /home/user/html
	reDR := regexp.MustCompile(`(?i)\bDocumentRoot\s+"?([^"\r\n]+)"?`)

	out := []root.RootEntry{}
	// 모든 매칭되는 DocumentRoot 라인 찾기
	for _, m := range reDR.FindAllStringSubmatch(s, -1) {
		if len(m) == 2 {
			out = append(out, root.RootEntry{
				Path:        strings.TrimSpace(m[1]),  // 추출된 경로를 정소정소
				Source:      root.SourceApacheDR,      // 소스: Apache DocumentRoot
				ContextHint: "from apachectl -S dump", // 참고 정보
			})
		}
	}
	return out
}
