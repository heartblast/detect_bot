package rules

import "github.com/heartblast/dmz_webroot_scanner/internal/model"

// LargeFileRule: 대용량 파일을 검사
// 차단, 큰 파일은 임시 스테이징 또는 백업 누수 가능성을 나타냄(Heuristic)
type LargeFileRule struct {
	ThresholdBytes int64 // 대용량 판단 기준 (Byte 단위)
}

// Name: 규칙 이름 반환
func (r *LargeFileRule) Name() string { return "large_file" }

// Evaluate: 파일 크기가 대용량 기준을 초과하는지 검사
func (r *LargeFileRule) Evaluate(ctx model.FileCtx) []Reason {
	if r.ThresholdBytes > 0 && ctx.Size >= r.ThresholdBytes {
		return []Reason{{
			Code:     "large_file_in_web_path",                                      // 대용량 파일 검출
			Severity: SevHigh,                                                       // 높은 중요도
			Message:  "Large file found under web-serving path (staging heuristic)", // 단어
		}}
	}
	return nil // 일반 반환
}
