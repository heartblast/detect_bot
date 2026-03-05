package input

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"dmz_webroot_scanner/internal/root"
)

// ParseNginxDump: 'nginx -T' 명령 출력에서 root/alias 디렉토리를 파싱
// b: Nginx 설정 덤프 바이트 배열
// 반환: 추출된 RootEntry 배열 (root 및 alias 디렉토리 포함)
func ParseNginxDump(b []byte) []root.RootEntry {
	// sc: 대용량 파일 처리를 위한 스캐너
	sc := bufio.NewScanner(bytes.NewReader(b))
	buf := make([]byte, 0, 64*1024)
	// 버퍼 크기를 10MB까지 허용하여 대용량 설정 파일 처리 가능
	sc.Buffer(buf, 10*1024*1024)

	// 정규식 패턴들
	reRoot := regexp.MustCompile(`(?i)^\s*root\s+([^;#]+);`)                            // root /path/to/root;
	reAlias := regexp.MustCompile(`(?i)^\s*alias\s+([^;#]+);`)                          // alias /path/to/alias;
	reServerName := regexp.MustCompile(`(?i)^\s*server_name\s+([^;#]+);`)               // server_name example.com;
	reConfFileLine := regexp.MustCompile(`(?i)^#\s*configuration\s+file\s+(.+?):(\d+)`) // # configuration file /etc/nginx/nginx.conf:12

	var lastServerName, lastFileLine string // 문맥 정보 저장
	out := []root.RootEntry{}

	// 라인 단위로 파일 읽기 및 파싱
	for sc.Scan() {
		line := sc.Text()

		// 현재 설정 파일과 라인 번호 추출
		if m := reConfFileLine.FindStringSubmatch(line); len(m) == 3 {
			lastFileLine = fmt.Sprintf("%s:%s", strings.TrimSpace(m[1]), m[2])
		}
		// 현재 server_name 추출 (이후 root/alias의 문맥 정보로 사용)
		if m := reServerName.FindStringSubmatch(line); len(m) == 2 {
			lastServerName = strings.TrimSpace(m[1])
		}
		// root 디렉토리 추출
		if m := reRoot.FindStringSubmatch(line); len(m) == 2 {
			out = append(out, root.RootEntry{
				Path:        strings.TrimSpace(m[1]),                               // root 경로
				Source:      root.SourceNginxRoot,                                  // 소스: Nginx root
				ContextHint: joinHint(lastFileLine, "server_name="+lastServerName), // 문맥 정보
			})
		}
		// alias 디렉토리 추출
		if m := reAlias.FindStringSubmatch(line); len(m) == 2 {
			out = append(out, root.RootEntry{
				Path:        strings.TrimSpace(m[1]),                               // alias 경로
				Source:      root.SourceNginxAlias,                                 // 소스: Nginx alias
				ContextHint: joinHint(lastFileLine, "server_name="+lastServerName), // 문맥 정보
			})
		}
	}
	return out
}

// joinHint: 두 개의 문맥 정보 문자열을 합침 (둘 다 비어있지 않으면 " | "로 구분)
// a, b: 합칠 문자열
// 반환: 합쳐진 문자열
func joinHint(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b) // 공백 제거
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	// 둘 다 있으면 구분자로 연결
	return a + " | " + b
}
