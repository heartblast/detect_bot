package input

import (
	"io"
	"os"
)

// ReadAllMaybeStdin: 파일 또는 stdin으로부터 모든 내용을 읽음
// pathOrDash: 파일 경로 또는 "-" (stdin을 의미)
// 반환: 읽은 바이트 배열, 오류
func ReadAllMaybeStdin(pathOrDash string) ([]byte, error) {
	// r: 읽을 입력 스트림 (파일 또는 stdin)
	var r io.Reader
	if pathOrDash == "-" {
		// "-"면 표준 입력 사용
		r = os.Stdin
	} else {
		// 일반 파일 열기
		f, err := os.Open(pathOrDash)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	// 스트림의 모든 내용을 읽음
	return io.ReadAll(r)
}
