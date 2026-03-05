package rules

import "dmz_webroot_scanner/internal/model"

// HighRiskExtRule: 실행 가능한 또는 압축 파일 확장자를 검사
// 예: .zip, .exe, .php, .jsp 등
// 매우 높은 중요도로 표시
type HighRiskExtRule struct {
	HighRisk map[string]bool // 위험을 나타내는 파일 확장자 맵
}

// Name: 규칙 이름 반환
func (r *HighRiskExtRule) Name() string { return "high_risk_ext" }

// Evaluate: 파일 확장자가 위험 목록에 있는지 검사
func (r *HighRiskExtRule) Evaluate(ctx model.FileCtx) []Reason {
	if ctx.Ext != "" && r.HighRisk[ctx.Ext] {
		return []Reason{{ // 위험 확장자 검출되면 웹루트에서 노출되면 위협
			Code:     "high_risk_extension",
			Severity: SevCritical, // 가장 높은 중요도
			Message:  "High-risk extension detected in web-serving path",
		}}
	}
	return nil // 없음 반환
}
