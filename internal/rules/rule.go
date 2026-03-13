package rules

import "github.com/heartblast/dmz_webroot_scanner/internal/model"

// Severity: 검출된 의심 파일의 오류 중요도 레벨
type Severity int

const (
	SevLow      Severity = iota // 0: 낮음
	SevMedium                   // 1: 중간
	SevHigh                     // 2: 높음
	SevCritical                 // 3: 매우 높음
)

// String: Severity 값을 문자열로 변환
func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "critical"
	case SevHigh:
		return "high"
	case SevMedium:
		return "medium"
	default:
		return "low"
	}
}

// Reason: 규칙이 판단한 오류의 종류와 값을 나타내는 구조체
type Reason struct {
	Code     string   // 오류 코드 (예: mime_not_in_allowlist)
	Severity Severity // 중요도 레벨
	Message  string   // 의심 메시지
}

// Rule: 파일 메타데이터를 검사하는 인터페이스
// 모든 규칙은 이 인터페이스를 기반으로 작성됨
type Rule interface {
	Name() string                        // 규칙 이름 반환
	Evaluate(ctx model.FileCtx) []Reason // 파일 정보를 나눈 결과 목록 (비어있을 수 있음)
}
