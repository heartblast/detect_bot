package report

import (
	"encoding/json"
	"io"
	"os"
)

// Write: Report 구조체를 JSON 포맷으로 파일 또는 stdout으로 출력
// rep: 출력할 Report 구조체
// out: 출력 대상 (경로 또는 '-'로 stdout 사용)
// 반환: 파일 기록/JSON 인코드 중 발생한 오류
func Write(rep Report, out string) error {
	// w: 출력 대상 (파일 또는 stdout)
	var w io.Writer
	if out == "-" {
		// "-"면 표준 출력 사용
		w = os.Stdout
	} else {
		// 경로로 파일 생성
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	// JSON 인코더 생성
	enc := json.NewEncoder(w)
	// 읽기 쉬운 보기 모양으로 출력
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
