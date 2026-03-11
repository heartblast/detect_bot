package rules

import (
	"regexp"
	"strings"

	"dmz_webroot_scanner/internal/model"
)

// SecretPatternsRule: 파일 본문에서 민감정보 패턴(연결정보, 자격증명, 비공개 키 등)을 탐지
// 규칙의 특징:
// - 파일 본문 샘플만 검사 (전체 파일 X)
// - 민감정보 원문을 JSON에 저장하지 않음
// - 패턴 종류와 위험도만 기록하되, 증거는 마스킹된 형태로 제한적 표시
type SecretPatternsRule struct {
	MaxSampleSize  int             // ContentSample 최대 바이트 수 (기본 65536)
	EnablePatterns bool            // 패턴 검사 활성화 여부
	ContentExts    map[string]bool // 검사 대상 확장자 (yaml, json, env, conf 등)
}

// Name: 규칙 이름 반환
func (r *SecretPatternsRule) Name() string {
	return "secret_patterns"
}

// Evaluate: 파일 본문 샘플에서 민감정보 패턴 검사
func (r *SecretPatternsRule) Evaluate(ctx model.FileCtx) []Reason {
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

	// 민감정보 패턴 탐지
	matches := detectPatterns(ctx.ContentSample)
	if len(matches) == 0 {
		return nil
	}

	// 매칭 결과를 Reason으로 변환
	return scorePatternsAndConvertToReasons(matches)
}

// MatchedPattern: 탐지된 단일 패턴의 메타데이터
type MatchedPattern struct {
	Kind         string   // 패턴 종류 (e.g., "jdbc_url", "password_key", "api_key")
	Severity     Severity // 위험도
	Evidence     string   // 마스킹된 증거 일부
	RawMatch     string   // 원본 매칭 문자열 (내부 사용 전용, JSON 출력 금지)
	IsCombo      bool     // 조합 탐지 여부
	ComboMatches []string // 이 탐지에 포함된 다른 패턴들
}

// detectPatterns: ContentSample에서 모든 패턴 탐지 수행
func detectPatterns(sample string) []MatchedPattern {
	var matches []MatchedPattern

	// 1. Connection String 패턴
	matches = append(matches, detectConnectionStrings(sample)...)

	// 2. Credential/Key 패턴
	matches = append(matches, detectCredentials(sample)...)

	// 3. Private Key Material 패턴
	matches = append(matches, detectPrivateKeys(sample)...)

	// 4. Internal Endpoint 패턴
	matches = append(matches, detectInternalEndpoints(sample)...)

	// 5. Suspicious Combo 패턴 (조합 탐지는 최상위에서만)
	comboMatches := detectSuspiciousCombos(sample, matches)
	matches = append(matches, comboMatches...)

	return matches
}

// detectConnectionStrings: JDBC, Redis, MongoDB, PostgreSQL, MySQL, Oracle, LDAP, S3, SMTP 등 연결문자열 탐지
func detectConnectionStrings(sample string) []MatchedPattern {
	var matches []MatchedPattern

	// JDBC 연결문자열 (jdbc:mysql, jdbc:postgresql, jdbc:oracle, jdbc:mssql, jdbc:mariadb 등)
	if re := regexp.MustCompile(`(?i)jdbc:[a-z0-9]+://[^\s\n\";,]+`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_jdbc_url",
				Severity: SevCritical,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	// Redis URI (redis://, rediss://)
	if re := regexp.MustCompile(`(?i)redis(?:s)?://` + `[^\s\n\";,]*`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_redis_uri",
				Severity: SevHigh,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	// MongoDB URI (mongodb://, mongodb+srv://)
	if re := regexp.MustCompile(`(?i)mongodb\+?(?:srv)?://[^\s\n\";,]+`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_mongodb_uri",
				Severity: SevCritical,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	// PostgreSQL 연결문자열 (user=, password=, host=)
	if re := regexp.MustCompile(`(?i)postgresql://[^\s\n\";]*`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_postgresql_uri",
				Severity: SevCritical,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	// MySQL/MariaDB 연결문자열
	if re := regexp.MustCompile(`(?i)mysql://[^\s\n\";]+`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_mysql_uri",
				Severity: SevCritical,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	// LDAP/LDAPS URI
	if re := regexp.MustCompile(`(?i)ldaps?://[^\s\n\";,]+`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_ldap_uri",
				Severity: SevHigh,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	// SMTP 설정 (host, port, user, password)
	if re := regexp.MustCompile(`(?i)smtp(?:s)?://[^\s\n\";,]+`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_smtp_uri",
				Severity: SevHigh,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	// S3/MinIO endpoint URL (s3://, minio://)
	if re := regexp.MustCompile(`(?i)(?:s3|minio)://[^\s\n\";,]+`); re.MatchString(sample) {
		m := re.FindString(sample)
		if !isCommentLine(m) && !isExample(m) {
			matches = append(matches, MatchedPattern{
				Kind:     "connection_s3_endpoint",
				Severity: SevHigh,
				Evidence: maskConnectionString(m),
				RawMatch: m,
			})
		}
	}

	return matches
}

// detectCredentials: 자격증명 키 탐지 (password, username, api_key, token 등)
func detectCredentials(sample string) []MatchedPattern {
	var matches []MatchedPattern

	// 패턴 정의: 키 = 값 형태
	patterns := []struct {
		keyPattern   string
		kind         string
		baseSeverity Severity
	}{
		{`(?i)(?:password|passwd|pwd)\s*[:=]`, "credential_password", SevCritical},
		{`(?i)username\s*[:=]`, "credential_username", SevMedium},
		{`(?i)db_user(?:name)?\s*[:=]`, "credential_db_user", SevMedium},
		{`(?i)db_password\s*[:=]`, "credential_db_password", SevCritical},
		{`(?i)bind_dn\s*[:=]`, "credential_bind_dn", SevHigh},
		{`(?i)bind_password\s*[:=]`, "credential_bind_password", SevCritical},
		{`(?i)(?:access_key|accessKey)\s*[:=]`, "credential_access_key", SevCritical},
		{`(?i)(?:secret_key|secretKey|secret)\s*[:=]`, "credential_secret_key", SevCritical},
		{`(?i)(?:api_key|apiKey)\s*[:=]`, "credential_api_key", SevCritical},
		{`(?i)(?:client_secret|clientSecret)\s*[:=]`, "credential_client_secret", SevCritical},
		{`(?i)(?:bearer\s+)?token\s*[:=]`, "credential_token", SevHigh},
		{`(?i)(?:access_token|accessToken)\s*[:=]`, "credential_access_token", SevCritical},
		{`(?i)(?:refresh_token|refreshToken)\s*[:=]`, "credential_refresh_token", SevHigh},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p.keyPattern + `\s*['\"]?([^\'\"\s\n;,]+)['\"]?`)
		matches_list := re.FindAllStringSubmatch(sample, -1)

		for _, m := range matches_list {
			if len(m) > 0 {
				fullMatch := m[0]
				if isCommentLine(fullMatch) || isExample(fullMatch) || isEmptyValue(fullMatch) {
					// 낮은 severity로 조정
					adjustedSev := p.baseSeverity
					if isEmptyValue(fullMatch) {
						adjustedSev = SevLow
					}
					matches = append(matches, MatchedPattern{
						Kind:     p.kind,
						Severity: adjustedSev,
						Evidence: maskCredential(fullMatch),
						RawMatch: fullMatch,
					})
				} else {
					matches = append(matches, MatchedPattern{
						Kind:     p.kind,
						Severity: p.baseSeverity,
						Evidence: maskCredential(fullMatch),
						RawMatch: fullMatch,
					})
				}
			}
		}
	}

	return matches
}

// detectPrivateKeys: 비공개 키 블록 탐지 (BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY 등)
func detectPrivateKeys(sample string) []MatchedPattern {
	var matches []MatchedPattern

	keyPatterns := []struct {
		pattern string
		kind    string
	}{
		{`BEGIN RSA PRIVATE KEY`, "private_key_rsa"},
		{`BEGIN OPENSSH PRIVATE KEY`, "private_key_openssh"},
		{`BEGIN PRIVATE KEY`, "private_key_generic"},
		{`BEGIN EC PRIVATE KEY`, "private_key_ec"},
		{`BEGIN DSA PRIVATE KEY`, "private_key_dsa"},
		{`BEGIN PGP PRIVATE KEY BLOCK`, "private_key_pgp"},
	}

	for _, kp := range keyPatterns {
		re := regexp.MustCompile(`(?i)-----` + kp.pattern + `-----`)
		if re.MatchString(sample) {
			matches = append(matches, MatchedPattern{
				Kind:     kp.kind,
				Severity: SevCritical,
				Evidence: "[Private key material detected - content redacted]",
				RawMatch: kp.pattern,
			})
		}
	}

	return matches
}

// detectInternalEndpoints: 사설 IP 또는 내부 호스트 기반 endpoint 탐지
func detectInternalEndpoints(sample string) []MatchedPattern {
	var matches []MatchedPattern

	// 사설 IP 대역 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
	privIPRe := regexp.MustCompile(`(?:\b10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b`)
	privIPs := privIPRe.FindAllString(sample, -1)
	for _, ip := range privIPs {
		if !isExample(ip) && !isCommentLine(ip) {
			matches = append(matches, MatchedPattern{
				Kind:     "internal_endpoint_private_ip",
				Severity: SevMedium,
				Evidence: ip,
				RawMatch: ip,
			})
		}
	}

	// .internal, .local 도메인
	internalDomainRe := regexp.MustCompile(`(?:\w+\.)+(?:internal|local|lan|corp|intra)\b`)
	internalDomains := internalDomainRe.FindAllString(sample, -1)
	for _, dom := range internalDomains {
		if !isExample(dom) && !isCommentLine(dom) {
			matches = append(matches, MatchedPattern{
				Kind:     "internal_endpoint_domain",
				Severity: SevMedium,
				Evidence: dom,
				RawMatch: dom,
			})
		}
	}

	return matches
}

// detectSuspiciousCombos: 조합 탐지 (connection string + credentials)
func detectSuspiciousCombos(sample string, allMatches []MatchedPattern) []MatchedPattern {
	var comboMatches []MatchedPattern

	// jdbc + password 조합
	if hasPatternKind(allMatches, "connection_jdbc_url") && hasCredentialPattern(allMatches) {
		comboMatches = append(comboMatches, MatchedPattern{
			Kind:     "combo_jdbc_with_credentials",
			Severity: SevCritical,
			Evidence: "[JDBC connection with embedded credentials detected]",
			IsCombo:  true,
		})
	}

	// datasource + username + password 조합
	if containsPattern(sample, "datasource") && hasPatternKind(allMatches, "credential_username") && hasPatternKind(allMatches, "credential_password") {
		comboMatches = append(comboMatches, MatchedPattern{
			Kind:     "combo_datasource_with_credentials",
			Severity: SevCritical,
			Evidence: "[Datasource config with embedded username and password]",
			IsCombo:  true,
		})
	}

	// redis + password 조합
	if hasPatternKind(allMatches, "connection_redis_uri") && hasPatternKind(allMatches, "credential_password") {
		comboMatches = append(comboMatches, MatchedPattern{
			Kind:     "combo_redis_with_password",
			Severity: SevCritical,
			Evidence: "[Redis connection with password detected]",
			IsCombo:  true,
		})
	}

	// s3/minio + access_key + secret_key 조합
	if hasS3Pattern(allMatches) && hasPatternKind(allMatches, "credential_access_key") && hasPatternKind(allMatches, "credential_secret_key") {
		comboMatches = append(comboMatches, MatchedPattern{
			Kind:     "combo_s3_with_keys",
			Severity: SevCritical,
			Evidence: "[S3/MinIO config with access and secret keys]",
			IsCombo:  true,
		})
	}

	// ldap + bind_dn + bind_password 조합
	if hasPatternKind(allMatches, "connection_ldap_uri") && hasPatternKind(allMatches, "credential_bind_dn") && hasPatternKind(allMatches, "credential_bind_password") {
		comboMatches = append(comboMatches, MatchedPattern{
			Kind:     "combo_ldap_with_credentials",
			Severity: SevCritical,
			Evidence: "[LDAP config with bind DN and password]",
			IsCombo:  true,
		})
	}

	return comboMatches
}

// Helper functions for combo detection

func hasPatternKind(matches []MatchedPattern, kind string) bool {
	for _, m := range matches {
		if strings.Contains(m.Kind, kind) {
			return true
		}
	}
	return false
}

func hasCredentialPattern(matches []MatchedPattern) bool {
	for _, m := range matches {
		if strings.HasPrefix(m.Kind, "credential_") {
			return true
		}
	}
	return false
}

func hasS3Pattern(matches []MatchedPattern) bool {
	for _, m := range matches {
		if strings.Contains(m.Kind, "s3") || strings.Contains(m.Kind, "minio") {
			return true
		}
	}
	return false
}

func containsPattern(sample string, pattern string) bool {
	return regexp.MustCompile(`(?i)\b` + pattern + `\b`).MatchString(sample)
}

// Masking functions

// maskConnectionString: 연결 문자열 마스킹 (호스트/포트/DB명 일부만 노출)
func maskConnectionString(connStr string) string {
	if len(connStr) > 80 {
		return connStr[:40] + "...>" // 앞부분만 노출, 말미 마스킹
	}
	return connStr
}

// maskCredential: 자격증명값 마스킹 (=값 부분을 ***로 표시)
func maskCredential(credLine string) string {
	// password=admin1234 → password=***
	re := regexp.MustCompile(`(?i)((?:password|passwd|pwd|username|user|token|api_key|access_key|secret_key|key|secret)\s*[:=]\s*)(['\"]?)([^'\"\s\n]+)`)
	return re.ReplaceAllString(credLine, `$1$2***`)
}

// Filter functions

// isCommentLine: 라인이 주석처럼 보이는지 판단
func isCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "<!--")
}

// isExample: 라인이 예제/샘플/템플릿 표시가 있는지 판단
func isExample(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "example") ||
		strings.Contains(lower, "template") ||
		strings.Contains(lower, "sample") ||
		strings.Contains(lower, "demo")
}

// isEmptyValue: 키만 있고 값이 비어있는지 판단
func isEmptyValue(line string) bool {
	// password= 또는 password: 형태 (값 없음)
	re := regexp.MustCompile(`(?i)((?:password|username|token|api_key|secret_key|access_key)\s*[:=]\s*)(?:$|['\"]['\"]|$)`)
	return re.MatchString(line)
}

// scorePatternsAndConvertToReasons: MatchedPattern 배열을 Reason으로 변환
func scorePatternsAndConvertToReasons(matches []MatchedPattern) []Reason {
	var reasons []Reason
	seenCombos := make(map[string]bool)

	// 조합 탐지 우선 (높은 우선순위)
	for _, m := range matches {
		if m.IsCombo {
			if !seenCombos[m.Kind] {
				seenCombos[m.Kind] = true
				reasons = append(reasons, Reason{
					Code:     m.Kind,
					Severity: m.Severity,
					Message:  m.Evidence,
				})
			}
		}
	}

	// 단일 패턴 탐지
	for _, m := range matches {
		if !m.IsCombo {
			reasons = append(reasons, Reason{
				Code:     m.Kind,
				Severity: m.Severity,
				Message:  m.Evidence,
			})
		}
	}

	return reasons
}
