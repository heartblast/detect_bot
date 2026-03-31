package rules

import (
	"strings"

	"github.com/heartblast/detect_bot/internal/model"
)

// AllowlistRule: 파일의 MIME 타입과 확장자가 허용 목록에 있는지 검사
type AllowlistRule struct {
	AllowMimePrefixes []string        // 허용된 MIME 타입 프리픽스 목록 (예: text/, image/)
	AllowExt          map[string]bool // 허용된 파일 확장자 맵 (검색 성능 O(1))
}

// Name: 규칙 이름 반환
func (r *AllowlistRule) Name() string { return "allowlist" }

// Evaluate: MIME 타입과 확장자가 허용 목록에 있는지 검사
// ctx: 검사할 파일 정보
// 반환: 위반 사항이 있으면 Reason 배열, 없으면 빈 배열
func (r *AllowlistRule) Evaluate(ctx model.FileCtx) []Reason {
	out := make([]Reason, 0, 2) // 최대 2개의 위반 가능성

	// MIME 타입이 허용 목록에 있는지 검사
	if !mimeAllowed(ctx.Mime, r.AllowMimePrefixes) {
		out = append(out, Reason{
			Code:     "mime_not_in_allowlist",                   // 오류 코드
			Severity: SevHigh,                                   // 높은 중요도
			Message:  "MIME is not allowed by prefix allowlist", // 오류 설명
		})
	}

	// 파일 확장자가 허용 목록에 있는지 검사
	if ctx.Ext != "" && !r.AllowExt[ctx.Ext] {
		out = append(out, Reason{
			Code:     "ext_not_in_allowlist",                  // 오류 코드
			Severity: SevHigh,                                 // 높은 중요도
			Message:  "Extension is not allowed by allowlist", // 오류 설명
		})
	}

	return out // 검사 결과 반환
}

// mimeAllowed: 주어진 MIME 타입이 허용된 프리픽스 목록에 있는지 확인
// mime: 확인할 MIME 타입 (예: application/octet-stream)
// prefixes: 허용된 MIME 프리픽스 목록 (예: ["image/", "text/plain"])
// 반환: 허용되면 true, 아니면 false
func mimeAllowed(mime string, prefixes []string) bool {
	m := strings.ToLower(strings.TrimSpace(mime))
	for _, p := range prefixes {
		pp := strings.ToLower(strings.TrimSpace(p))
		if pp == "" {
			continue // 빈 프리픽스는 무시
		}
		if m == pp {
			return true // 정확한 매칭
		}
		// 프리픽스 매칭 (예: "image/"는 "image/png" 포함)
		if strings.HasSuffix(pp, "/") && strings.HasPrefix(m, pp) {
			return true
		}
		// 접미사 매칭 (예: "application/font-"는 "application/font-woff" 포함)
		if strings.HasSuffix(pp, "-") && strings.HasPrefix(m, pp) {
			return true
		}
	}
	return false // 허용된 MIME이 아님
}
