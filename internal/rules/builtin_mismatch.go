package rules

import (
	"strings"

	"github.com/heartblast/detect_bot/internal/model"
)

// ExtMimeMismatchRule: 파일 확장자와 스니프된 MIME 타입이 일치하지 않는 경우 확인
// 예: .png 파일에 스니프되는 MIME이 application/zip이면 위장 가능성
type ExtMimeMismatchRule struct{}

// Name: 규칙 이름 반환
func (r *ExtMimeMismatchRule) Name() string { return "ext_mime_mismatch" }

// Evaluate: 파일 확장자와 MIME 타입의 불일치 검사
func (r *ExtMimeMismatchRule) Evaluate(ctx model.FileCtx) []Reason {
	var out []Reason
	m := strings.ToLower(ctx.Mime) // MIME 타입을 소문자로 변환

	// 이미지 확장자인데 MIME에 image/*가 아니면 위장 가능성
	if isImageExt(ctx.Ext) && !strings.HasPrefix(m, "image/") {
		out = append(out, Reason{
			Code:     "ext_mime_mismatch_image",
			Severity: SevHigh,
			Message:  "Image extension but MIME is not image/*",
		})
	}

	// 텍스트파일(js/css/html)일 때 zip으로 탐지되면
	if (ctx.Ext == ".js" || ctx.Ext == ".css" || ctx.Ext == ".html") && strings.HasPrefix(m, "application/zip") {
		out = append(out, Reason{
			Code:     "ext_mime_mismatch_archive",
			Severity: SevHigh,
			Message:  "Text/asset extension but MIME detected as archive",
		})
	}

	return out // 검사 결과 반환
}

func isImageExt(ext string) bool {
	// isImageExt: 주어진 파일 확장자가 이미지 파일인지 여부 판단
	// ext: 파일 확장자 (예: ".png")
	// 반환: 이미지 확장자면 true, 아니면 false
	switch strings.ToLower(ext) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico":
		return true // 이미지 확장자
	default:
		return false // 다른 파일 형태
	}
}
