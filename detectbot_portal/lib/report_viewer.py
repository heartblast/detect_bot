"""
Report viewer helpers for DetectBot Portal.
"""

from collections import Counter

import pandas as pd

from lib.time_utils import format_display_datetime


def normalize_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def fmt_dt(value):
    if not value:
        return "-"
    formatted = format_display_datetime(value)
    return str(value) if formatted == "-" else formatted


def fmt_bytes(num):
    if num is None:
        return "-"
    try:
        num = float(num)
    except Exception:
        return str(num)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if num < 1024 or unit == units[-1]:
            return f"{num:,.1f} {unit}"
        num /= 1024
    return f"{num} B"


SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


def severity_rank(sev):
    sev = (sev or "unknown").lower()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def normalize_host_info(report):
    raw_host = report.get("host")
    host = {
        "hostname": "",
        "ip_addresses": [],
        "primary_ip": "",
        "os_type": "알 수 없음",
        "os_name": "",
        "os_version": "",
        "platform": "",
        "collected_at": "",
    }

    if isinstance(raw_host, dict):
        host["hostname"] = str(raw_host.get("hostname") or "").strip()
        host["ip_addresses"] = [
            str(value).strip()
            for value in normalize_list(raw_host.get("ip_addresses"))
            if str(value).strip()
        ]
        host["primary_ip"] = str(raw_host.get("primary_ip") or "").strip()
        host["os_type"] = str(raw_host.get("os_type") or "알 수 없음").strip() or "알 수 없음"
        host["os_name"] = str(raw_host.get("os_name") or "").strip()
        host["os_version"] = str(raw_host.get("os_version") or "").strip()
        host["platform"] = str(raw_host.get("platform") or "").strip()
        host["collected_at"] = str(raw_host.get("collected_at") or "").strip()
    elif isinstance(raw_host, str):
        host["hostname"] = raw_host.strip()

    if not host["primary_ip"] and host["ip_addresses"]:
        host["primary_ip"] = host["ip_addresses"][0]

    return host


def normalize_roots(report):
    return normalize_list(report.get("roots") or report.get("scan_roots"))


def host_summary_text(host):
    parts = [
        part
        for part in [host.get("hostname"), host.get("primary_ip"), host.get("os_type")]
        if part
    ]
    return " / ".join(parts) if parts else "알 수 없음"


def build_findings_df(findings):
    rows = []
    for idx, finding in enumerate(findings):
        reasons = normalize_list(finding.get("reasons"))
        matched_patterns = normalize_list(finding.get("matched_patterns"))
        evidence_masked = normalize_list(finding.get("evidence_masked"))
        content_flags = normalize_list(finding.get("content_flags"))

        rows.append(
            {
                "idx": idx,
                "severity": (finding.get("severity") or "unknown").lower(),
                "path": finding.get("path", ""),
                "real_path": finding.get("real_path", ""),
                "ext": finding.get("ext", ""),
                "mime_sniff": finding.get("mime_sniff", ""),
                "size_bytes": finding.get("size_bytes"),
                "size_human": fmt_bytes(finding.get("size_bytes")),
                "mod_time": finding.get("mod_time", ""),
                "mod_time_fmt": fmt_dt(finding.get("mod_time")),
                "perm": finding.get("perm", ""),
                "reasons": reasons,
                "reasons_text": ", ".join(reasons),
                "matched_patterns": matched_patterns,
                "matched_patterns_text": ", ".join(matched_patterns),
                "evidence_masked": evidence_masked,
                "evidence_masked_text": " | ".join(evidence_masked),
                "content_flags": content_flags,
                "content_flags_text": ", ".join(content_flags),
                "url_exposure_heuristic": finding.get("url_exposure_heuristic", ""),
                "root_matched": finding.get("root_matched", ""),
                "root_source": finding.get("root_source", ""),
                "sha256": finding.get("sha256", ""),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    df["severity_rank"] = df["severity"].apply(severity_rank)
    df = df.sort_values(
        by=["severity_rank", "size_bytes", "mod_time_fmt"],
        ascending=[True, False, False],
        na_position="last",
    ).reset_index(drop=True)
    return df


def summarize_findings(findings_df):
    severity_counter = Counter()
    reason_counter = Counter()
    pattern_counter = Counter()

    if findings_df is None or findings_df.empty:
        return severity_counter, reason_counter, pattern_counter

    for _, row in findings_df.iterrows():
        severity_counter[row["severity"]] += 1
        for reason in row["reasons"]:
            reason_counter[reason] += 1
        for pattern in row["matched_patterns"]:
            pattern_counter[pattern] += 1

    return severity_counter, reason_counter, pattern_counter


def filter_findings_df(
    findings_df,
    severities=None,
    reasons=None,
    patterns=None,
    keyword="",
    min_size_mb=0.0,
):
    if findings_df is None or findings_df.empty:
        return findings_df

    filtered = findings_df.copy()
    severities = severities or []
    reasons = reasons or []
    patterns = patterns or []
    keyword = (keyword or "").strip().lower()

    if severities:
        filtered = filtered[filtered["severity"].isin(severities)]

    if reasons:
        filtered = filtered[
            filtered["reasons"].apply(lambda values: any(value in values for value in reasons))
        ]

    if patterns:
        filtered = filtered[
            filtered["matched_patterns"].apply(
                lambda values: any(value in values for value in patterns)
            )
        ]

    if keyword:
        filtered = filtered[
            filtered.apply(
                lambda row: keyword in str(row["path"]).lower()
                or keyword in str(row["real_path"]).lower()
                or keyword in str(row["root_matched"]).lower(),
                axis=1,
            )
        ]

    if min_size_mb > 0:
        filtered = filtered[
            filtered["size_bytes"].fillna(0) >= int(float(min_size_mb) * 1024 * 1024)
        ]

    return filtered.reset_index(drop=True)


def build_roots_df(roots):
    rows = [
        {
            "path": root.get("path", ""),
            "real_path": root.get("real_path", ""),
            "source": root.get("source", ""),
        }
        for root in roots
    ]
    return pd.DataFrame(rows)


def interpret_finding(row):
    reasons = row["reasons"]
    severity = row["severity"]

    lines = [f"위험도는 **{severity}** 입니다."]

    if "high_risk_extension" in reasons:
        lines.append("- 웹 경로에 실행형 또는 압축형 계열의 고위험 확장자 파일이 존재할 수 있습니다.")
    if "mime_not_in_allowlist" in reasons:
        lines.append("- 파일 MIME이 허용 정책과 맞지 않아 노출 대상이 아닌 파일일 가능성이 있습니다.")
    if "ext_not_in_allowlist" in reasons:
        lines.append("- 파일 확장자가 허용 정책 밖에 있어 업무 목적과 무관한 파일일 가능성이 있습니다.")
    if "large_file_in_web_path" in reasons or "large_file" in reasons:
        lines.append("- 웹 경로에 대용량 파일이 있어 스테이징 또는 비정상 반출 준비 흔적일 수 있습니다.")
    if "ext_mime_mismatch_image" in reasons or "ext_mime_mismatch_archive" in reasons:
        lines.append("- 확장자와 실제 MIME이 일치하지 않아 위장 파일 가능성을 확인할 필요가 있습니다.")

    pii_related = {
        "resident_registration_number",
        "foreigner_registration_number",
        "passport_number",
        "drivers_license",
        "credit_card",
        "bank_account",
        "mobile_phone",
        "email_address",
        "birth_date",
    }
    if any(code in pii_related for code in reasons):
        lines.append("- 개인정보 패턴이 탐지되었습니다. 마스킹된 증거를 우선 확인해 주세요.")

    if (
        "secret_patterns" in reasons
        or "private_key_material" in reasons
        or "jdbc_connection_string" in reasons
    ):
        lines.append("- 설정정보, 자격증명, 연결문자열 등 민감정보 노출 위험이 있습니다.")

    if row["url_exposure_heuristic"]:
        lines.append(f"- 노출 추정: **{row['url_exposure_heuristic']}**")

    return "\n".join(lines)
