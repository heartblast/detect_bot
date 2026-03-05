package scan

import (
	"errors"
	"io"
	"net/http"
	"os"
)

// sniffMime: 파일의 처음 몇 바이트를 읽어 MIME 타입을 웹 표준 방식으로 탐지
// path: 파일 경로
// max: 읽을 최대 바이트 수 (일반적으로 512)
// 반환: 탐지된 MIME 타입 문자열, 오류 (읽기 실패 등)
func sniffMime(path string, max int) (string, error) {
	// 파일 열기 시도
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// 파일의 처음 max 바이트 읽기
	buf := make([]byte, max)
	n, err := f.Read(buf)
	// 읽기 오류 처리: 부분 읽음는 OK, 완전 실패는 에러
	if err != nil && !errors.Is(err, io.EOF) {
		if n == 0 {
			return "", err // 한 바이트도 못 읽었으면 에러
		}
		// 부분 읽음은 진행
	}
	// Go 표준 라이브러리의 HTTP MIME 탐지 함수 사용
	return http.DetectContentType(buf[:n]), nil
}
