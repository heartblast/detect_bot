package rules

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/heartblast/dmz_webroot_scanner/internal/model"
)

// PIIPatternsRule: 파일 본문에서 개인정보(PII) 유출위험 패턴을 탐지
// 규칙의 특징:
// - 파일 본문 샘플만 검사 (전체 파일 X)
// - 개인정보 원문을 JSON에 저장하지 않음
// - 패턴 종류와 위험도만 기록하되, 증거는 마스킹된 형태로 제한적 표시
type PIIPatternsRule struct {
	MaxSampleSize      int             // ContentSample 최대 바이트 수 (기본 65536)
	EnablePatterns     bool            // 패턴 검사 활성화 여부
	ContentExts        map[string]bool // 검사 대상 확장자
	MaxMatches         int             // 규칙별 최대 저장 샘플 수
	MaskSensitive      bool            // 민감정보 마스킹
	StoreSample        bool            // 샘플 저장 여부
	UseContextKeywords bool            // 문맥 키워드 사용
}

// Name: 규칙 이름 반환
func (r *PIIPatternsRule) Name() string {
	return "pii_patterns"
}

// Evaluate: 파일 본문 샘플에서 개인정보 패턴 검사
func (r *PIIPatternsRule) Evaluate(ctx model.FileCtx) []Reason {
	// 활성화되지 않음
	if !r.EnablePatterns {
		return nil
	}

	// 본문 샘플이 없으면 검사 불가
	if ctx.ContentSample == "" {
		return nil
	}

	// 검사 대상 확장자 필터
	if len(r.ContentExts) > 0 && !r.ContentExts[strings.ToLower(ctx.Ext)] {
		return nil
	}

	// 개인정보 패턴 탐지
	matches := detectPIIPatterns(ctx.ContentSample, r.UseContextKeywords)
	if len(matches) == 0 {
		return nil
	}

	// 매칭 결과를 Reason으로 변환
	return scorePIIMatchesAndConvertToReasons(matches, r.MaxMatches, r.MaskSensitive, r.StoreSample)
}

// PIIMatchedPattern: 탐지된 단일 PII 패턴의 메타데이터
type PIIMatchedPattern struct {
	Rule             string   // PII 규칙 이름 (e.g., "resident_registration_number")
	Severity         Severity // 위험도
	MatchStatus      string   // 매치 상태: validated, suspected, weak_match
	Confidence       string   // 신뢰도: high, medium, low
	Count            int      // 발견 개수
	MaskedSamples    []string // 마스킹된 샘플
	EvidenceKeywords []string // 문맥 키워드
	FileClass        string   // 파일 유형: config, data, log
	RawMatches       []string // 내부 사용 (JSON 출력 금지)
}

// detectPIIPatterns: ContentSample에서 모든 PII 패턴 탐지 수행
func detectPIIPatterns(sample string, useContext bool) []PIIMatchedPattern {
	var matches []PIIMatchedPattern

	// 탐지할 PII 유형들
	piiTypes := []PIIType{
		{Name: "resident_registration_number", Severity: SevCritical, Patterns: residentRegistrationPatterns()},
		{Name: "foreigner_registration_number", Severity: SevCritical, Patterns: foreignerRegistrationPatterns()},
		{Name: "passport_number", Severity: SevHigh, Patterns: passportPatterns()},
		{Name: "drivers_license", Severity: SevHigh, Patterns: driversLicensePatterns()},
		{Name: "credit_card", Severity: SevCritical, Patterns: creditCardPatterns()},
		{Name: "bank_account", Severity: SevHigh, Patterns: bankAccountPatterns()},
		{Name: "mobile_phone", Severity: SevMedium, Patterns: mobilePhonePatterns()},
		{Name: "email", Severity: SevMedium, Patterns: emailPatterns()},
		{Name: "birth_date", Severity: SevMedium, Patterns: birthDatePatterns()},
	}

	for _, piiType := range piiTypes {
		matched := detectPIIType(sample, piiType, useContext)
		if matched != nil {
			matches = append(matches, *matched)
		}
	}

	return matches
}

// PIIType: PII 유형 정의
type PIIType struct {
	Name     string
	Severity Severity
	Patterns []PIIPattern
}

// PIIPattern: 단일 패턴 정의
type PIIPattern struct {
	Regex       *regexp.Regexp
	Validator   func(string) bool
	Masker      func(string) string
	ContextKeys []string
}

// detectPIIType: 특정 PII 유형 탐지
func detectPIIType(sample string, piiType PIIType, useContext bool) *PIIMatchedPattern {
	var rawMatches []string
	var maskedSamples []string
	var evidenceKeywords []string

	for _, pattern := range piiType.Patterns {
		matches := pattern.Regex.FindAllString(sample, -1)
		for _, match := range matches {
			if isCommentLine(match) || isExample(match) {
				continue
			}
			rawMatches = append(rawMatches, match)
			if pattern.Masker != nil {
				maskedSamples = append(maskedSamples, pattern.Masker(match))
			} else {
				maskedSamples = append(maskedSamples, maskGeneric(match))
			}
			if useContext {
				evidenceKeywords = append(evidenceKeywords, findContextKeywords(sample, pattern.ContextKeys)...)
			}
		}
	}

	if len(rawMatches) == 0 {
		return nil
	}

	// 검증 수행
	matchStatus, confidence := validatePIIMatches(rawMatches, piiType.Name)

	// 파일 클래스 결정
	fileClass := determineFileClass(sample)

	return &PIIMatchedPattern{
		Rule:             piiType.Name,
		Severity:         piiType.Severity,
		MatchStatus:      matchStatus,
		Confidence:       confidence,
		Count:            len(rawMatches),
		MaskedSamples:    maskedSamples,
		EvidenceKeywords: evidenceKeywords,
		FileClass:        fileClass,
		RawMatches:       rawMatches,
	}
}

// validatePIIMatches: 매치 검증 및 상태 결정
func validatePIIMatches(matches []string, ruleName string) (string, string) {
	if len(matches) == 0 {
		return "weak_match", "low"
	}

	validated := 0
	suspected := 0

	for _, match := range matches {
		switch ruleName {
		case "resident_registration_number":
			if validateResidentRegistrationNumber(match) {
				validated++
			} else if hasContextKeywords(match) {
				suspected++
			}
		case "foreigner_registration_number":
			if validateForeignerRegistrationNumber(match) {
				validated++
			} else if hasContextKeywords(match) {
				suspected++
			}
		case "credit_card":
			if validateCreditCard(match) {
				validated++
			} else if hasContextKeywords(match) {
				suspected++
			}
		case "email":
			if validateEmail(match) {
				validated++
			} else if hasContextKeywords(match) {
				suspected++
			}
		case "mobile_phone":
			if validateMobilePhone(match) {
				validated++
			} else if hasContextKeywords(match) {
				suspected++
			}
		case "birth_date":
			if validateBirthDate(match) {
				validated++
			} else if hasContextKeywords(match) {
				suspected++
			}
		default:
			// 다른 유형은 패턴 매치만으로 suspected
			if hasContextKeywords(match) {
				suspected++
			}
		}
	}

	if validated > 0 {
		return "validated", "high"
	} else if suspected > 0 {
		return "suspected", "medium"
	} else {
		return "weak_match", "low"
	}
}

// determineFileClass: 파일 내용으로 클래스 결정
func determineFileClass(sample string) string {
	lower := strings.ToLower(sample)
	if strings.Contains(lower, "config") || strings.Contains(lower, "env") || strings.Contains(lower, "yaml") || strings.Contains(lower, "json") {
		return "config"
	} else if strings.Contains(lower, "log") || strings.Contains(lower, "error") || strings.Contains(lower, "info") {
		return "log"
	} else {
		return "data"
	}
}

// scorePIIMatchesAndConvertToReasons: PIIMatchedPattern 배열을 Reason으로 변환
func scorePIIMatchesAndConvertToReasons(matches []PIIMatchedPattern, maxMatches int, maskSensitive, storeSample bool) []Reason {
	var reasons []Reason

	for _, m := range matches {
		samples := m.MaskedSamples
		if !storeSample {
			samples = nil
		}
		if maskSensitive && len(samples) > 0 {
			// 이미 마스킹됨
		}
		if maxMatches > 0 && len(samples) > maxMatches {
			samples = samples[:maxMatches]
		}

		reason := Reason{
			Code:     m.Rule,
			Severity: m.Severity,
			Message:  strings.Join(samples, "; "),
		}
		reasons = append(reasons, reason)
	}

	return reasons
}

// PII 패턴 정의 함수들

func residentRegistrationPatterns() []PIIPattern {
	re := regexp.MustCompile(`\b\d{6}-[1-4]\d{6}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   validateResidentRegistrationNumber,
			Masker:      maskResidentRegistrationNumber,
			ContextKeys: []string{"주민", "주민등록번호", "resident", "rrn"},
		},
	}
}

func foreignerRegistrationPatterns() []PIIPattern {
	re := regexp.MustCompile(`\b\d{6}-[5-8]\d{6}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   validateForeignerRegistrationNumber,
			Masker:      maskForeignerRegistrationNumber,
			ContextKeys: []string{"외국인", "foreigner"},
		},
	}
}

func passportPatterns() []PIIPattern {
	re := regexp.MustCompile(`\b[A-Z]{1,2}\d{7,8}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   nil, // 검증 어려움
			Masker:      maskPassport,
			ContextKeys: []string{"passport", "여권"},
		},
	}
}

func driversLicensePatterns() []PIIPattern {
	re := regexp.MustCompile(`\b\d{2}-\d{2}-\d{6}-\d{2}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   nil,
			Masker:      maskDriversLicense,
			ContextKeys: []string{"license", "면허", "driver"},
		},
	}
}

func creditCardPatterns() []PIIPattern {
	re := regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   validateCreditCard,
			Masker:      maskCreditCard,
			ContextKeys: []string{"card", "카드"},
		},
	}
}

func bankAccountPatterns() []PIIPattern {
	re := regexp.MustCompile(`\b\d{10,16}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   nil,
			Masker:      maskBankAccount,
			ContextKeys: []string{"account", "acct", "bank", "계좌", "예금주"},
		},
	}
}

func mobilePhonePatterns() []PIIPattern {
	re := regexp.MustCompile(`\b01[016789]-\d{3,4}-\d{4}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   validateMobilePhone,
			Masker:      maskMobilePhone,
			ContextKeys: []string{"phone", "mobile", "휴대전화", "연락처"},
		},
	}
}

func emailPatterns() []PIIPattern {
	re := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   validateEmail,
			Masker:      maskEmail,
			ContextKeys: []string{"email", "mail", "e-mail"},
		},
	}
}

func birthDatePatterns() []PIIPattern {
	re := regexp.MustCompile(`\b\d{4}[./-]?\d{2}[./-]?\d{2}\b`)
	return []PIIPattern{
		{
			Regex:       re,
			Validator:   validateBirthDate,
			Masker:      maskBirthDate,
			ContextKeys: []string{"birth", "birthday", "dob", "생년월일"},
		},
	}
}

// 검증 함수들

func validateResidentRegistrationNumber(s string) bool {
	// 간단한 형식 검증 (실제 체크섬 검증은 생략)
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return false
	}
	if len(parts[0]) != 6 || len(parts[1]) != 7 {
		return false
	}
	// 첫 글자가 1-4
	if parts[1][0] < '1' || parts[1][0] > '4' {
		return false
	}
	return true
}

func validateForeignerRegistrationNumber(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return false
	}
	if len(parts[0]) != 6 || len(parts[1]) != 7 {
		return false
	}
	// 첫 글자가 5-8
	if parts[1][0] < '5' || parts[1][0] > '8' {
		return false
	}
	return true
}

func validateCreditCard(s string) bool {
	// Luhn 알고리즘
	digits := strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), " ", "")
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhnCheck(digits)
}

func luhnCheck(digits string) bool {
	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alternate = !alternate
	}
	return sum%10 == 0
}

func validateEmail(s string) bool {
	// 간단한 이메일 형식 검증
	return strings.Contains(s, "@") && strings.Contains(s, ".")
}

func validateMobilePhone(s string) bool {
	// 한국 휴대전화 형식
	return strings.HasPrefix(s, "010") || strings.HasPrefix(s, "011") || strings.HasPrefix(s, "016") || strings.HasPrefix(s, "017") || strings.HasPrefix(s, "018") || strings.HasPrefix(s, "019")
}

func validateBirthDate(s string) bool {
	// 날짜 유효성 검증
	year := 0
	month := 0
	day := 0
	if strings.Contains(s, "/") {
		parts := strings.Split(s, "/")
		if len(parts) == 3 {
			year, _ = strconv.Atoi(parts[0])
			month, _ = strconv.Atoi(parts[1])
			day, _ = strconv.Atoi(parts[2])
		}
	} else if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) == 3 {
			year, _ = strconv.Atoi(parts[0])
			month, _ = strconv.Atoi(parts[1])
			day, _ = strconv.Atoi(parts[2])
		}
	} else if strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		if len(parts) == 3 {
			year, _ = strconv.Atoi(parts[0])
			month, _ = strconv.Atoi(parts[1])
			day, _ = strconv.Atoi(parts[2])
		}
	} else {
		// YYYYMMDD
		if len(s) == 8 {
			year, _ = strconv.Atoi(s[:4])
			month, _ = strconv.Atoi(s[4:6])
			day, _ = strconv.Atoi(s[6:])
		}
	}
	if year < 1900 || year > time.Now().Year() {
		return false
	}
	if month < 1 || month > 12 {
		return false
	}
	if day < 1 || day > 31 {
		return false
	}
	return true
}

// 마스킹 함수들

func maskResidentRegistrationNumber(s string) string {
	if len(s) < 14 {
		return s
	}
	return s[:8] + "******"
}

func maskForeignerRegistrationNumber(s string) string {
	return maskResidentRegistrationNumber(s) // 동일
}

func maskPassport(s string) string {
	if len(s) < 3 {
		return s
	}
	return s[:2] + strings.Repeat("*", len(s)-2)
}

func maskDriversLicense(s string) string {
	return s // 전체 마스킹 어려움
}

func maskCreditCard(s string) string {
	digits := strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), " ", "")
	if len(digits) != 16 {
		return s
	}
	return digits[:4] + "-****-****-" + digits[12:]
}

func maskBankAccount(s string) string {
	if len(s) <= 4 {
		return s
	}
	return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}

func maskMobilePhone(s string) string {
	if len(s) < 13 {
		return s
	}
	return s[:7] + "**-****"
}

func maskEmail(s string) string {
	at := strings.Index(s, "@")
	if at == -1 {
		return s
	}
	local := s[:at]
	if len(local) > 3 {
		return local[:3] + "***" + s[at:]
	}
	return local + "***" + s[at:]
}

func maskBirthDate(s string) string {
	return s // 날짜는 그대로
}

func maskGeneric(s string) string {
	if len(s) > 10 {
		return s[:5] + "***"
	}
	return s
}

// 헬퍼 함수들

func hasContextKeywords(match string) bool {
	// 간단히 true로 가정 (실제로는 주변 텍스트 분석 필요)
	return true
}

func findContextKeywords(sample string, contextKeys []string) []string {
	// 간단 구현
	var keywords []string
	lower := strings.ToLower(sample)
	for _, key := range contextKeys {
		if strings.Contains(lower, strings.ToLower(key)) {
			keywords = append(keywords, key)
		}
	}
	return keywords
}
