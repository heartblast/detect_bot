"""
Constants for DMZ Webroot Scanner Streamlit UI
"""

# Default allow lists
DEFAULT_ALLOW_MIME_PREFIXES = [
    "text/",
    "image/",
    "application/javascript",
    "application/json",
    "application/xml",
]

DEFAULT_ALLOW_EXTS = [
    ".html", ".htm", ".css", ".js", ".mjs",
    ".json", ".xml", ".txt",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".map",
]

DEFAULT_CONTENT_EXTS = [
    ".yaml", ".yml", ".json", ".xml", ".properties",
    ".conf", ".env", ".ini", ".txt", ".config", ".cfg", ".toml",
]

DEFAULT_PII_EXTS = [
    ".yaml", ".yml", ".json", ".xml", ".properties",
    ".conf", ".env", ".ini", ".txt", ".log", ".csv", ".tsv",
]

# Rule options
RULE_OPTIONS = [
    "mime_not_in_allowlist",
    "ext_not_in_allowlist",
    "high_risk_extension",
    "large_file_in_web_path",
    "ext_mime_mismatch_image",
    "ext_mime_mismatch_archive",
    "secret_patterns",
    "pii_patterns",
]

# Severity settings
SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_EMOJI = {
    "critical": "🟥",
    "high": "🟧",
    "medium": "🟨",
    "low": "🟩",
    "unknown": "⬜",
}

# Reason labels for Korean translation
REASON_LABELS = {
    "mime_not_in_allowlist": "허용 MIME 위반",
    "ext_not_in_allowlist": "허용 확장자 위반",
    "high_risk_extension": "고위험 확장자",
    "large_file_in_web_path": "웹경로 대용량 파일",
    "ext_mime_mismatch_image": "이미지 확장자-MIME 불일치",
    "ext_mime_mismatch_archive": "아카이브 위장 의심",
    "resident_registration_number": "주민등록번호 패턴",
    "foreigner_registration_number": "외국인등록번호 패턴",
    "passport_number": "여권번호 패턴",
    "drivers_license": "운전면허번호 패턴",
    "credit_card": "신용카드번호 패턴",
    "bank_account": "계좌번호 패턴",
    "mobile_phone": "휴대전화번호 패턴",
    "email_address": "이메일 패턴",
    "birth_date": "생년월일 패턴",
    "secret_patterns": "비밀정보 패턴",
    "jdbc_connection_string": "JDBC 연결문자열",
    "private_key_material": "비공개 키 패턴",
}