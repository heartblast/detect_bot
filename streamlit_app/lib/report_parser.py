"""
Report parsing and analysis functions for DMZ Webroot Scanner
"""

import pandas as pd
from collections import Counter
from lib.utils import normalize_list, fmt_dt, fmt_bytes, severity_rank
from lib.constants import SEVERITY_ORDER, SEVERITY_EMOJI, REASON_LABELS


def build_findings_df(findings):
    """Build pandas DataFrame from findings"""
    rows = []
    for idx, f in enumerate(findings):
        reasons = normalize_list(f.get("reasons"))
        matched_patterns = normalize_list(f.get("matched_patterns"))
        evidence_masked = normalize_list(f.get("evidence_masked"))
        content_flags = normalize_list(f.get("content_flags"))

        rows.append(
            {
                "idx": idx,
                "severity": (f.get("severity") or "unknown").lower(),
                "path": f.get("path", ""),
                "real_path": f.get("real_path", ""),
                "ext": f.get("ext", ""),
                "mime_sniff": f.get("mime_sniff", ""),
                "size_bytes": f.get("size_bytes"),
                "size_human": fmt_bytes(f.get("size_bytes")),
                "mod_time": f.get("mod_time", ""),
                "mod_time_fmt": fmt_dt(f.get("mod_time")),
                "perm": f.get("perm", ""),
                "reasons": reasons,
                "reasons_text": ", ".join(reasons),
                "matched_patterns": matched_patterns,
                "matched_patterns_text": ", ".join(matched_patterns),
                "evidence_masked": evidence_masked,
                "evidence_masked_text": " | ".join(evidence_masked),
                "content_flags": content_flags,
                "content_flags_text": ", ".join(content_flags),
                "url_exposure_heuristic": f.get("url_exposure_heuristic", ""),
                "root_matched": f.get("root_matched", ""),
                "root_source": f.get("root_source", ""),
                "sha256": f.get("sha256", ""),
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


def render_summary(report):
    """Render summary metrics"""
    import streamlit as st

    stats = report.get("stats", {}) or {}
    roots = normalize_list(report.get("roots"))
    findings = normalize_list(report.get("findings"))

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Host", report.get("host", "-"))
    col2.metric("Roots", stats.get("roots_count", len(roots)))
    col3.metric("Scanned Files", stats.get("scanned_files", "-"))
    col4.metric("Findings", stats.get("findings_count", len(findings)))
    col5.metric("Generated At", fmt_dt(report.get("generated_at")))


def render_root_table(roots):
    """Render roots table"""
    import streamlit as st

    if not roots:
        st.info("roots 정보가 없습니다.")
        return

    root_rows = []
    for r in roots:
        root_rows.append(
            {
                "path": r.get("path", ""),
                "real_path": r.get("real_path", ""),
                "source": r.get("source", ""),
            }
        )
    st.dataframe(pd.DataFrame(root_rows), use_container_width=True, hide_index=True)


def render_counters(findings_df):
    """Render severity and reason counters"""
    import streamlit as st

    sev_counter = Counter(findings_df["severity"].tolist())
    sev_rows = []
    for sev in SEVERITY_ORDER:
        count = sev_counter.get(sev, 0)
        if count > 0:
            sev_rows.append(
                {
                    "severity": f"{SEVERITY_EMOJI.get(sev, '⬜')} {sev}",
                    "count": count,
                }
            )
    if sev_rows:
        st.dataframe(pd.DataFrame(sev_rows), use_container_width=True, hide_index=True)

    reason_counter = Counter()
    pattern_counter = Counter()

    for _, row in findings_df.iterrows():
        for reason in row["reasons"]:
            reason_counter[reason] += 1
        for pattern in row["matched_patterns"]:
            pattern_counter[pattern] += 1

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 탐지 사유 상위")
        if reason_counter:
            reason_df = pd.DataFrame(
                [
                    {
                        "reason_code": code,
                        "의미": REASON_LABELS.get(code, code),
                        "count": count,
                    }
                    for code, count in reason_counter.most_common(20)
                ]
            )
            st.dataframe(reason_df, use_container_width=True, hide_index=True)
        else:
            st.info("탐지 사유가 없습니다.")

    with col2:
        st.markdown("#### 패턴 탐지 상위")
        if pattern_counter:
            pattern_df = pd.DataFrame(
                [
                    {
                        "pattern": code,
                        "의미": REASON_LABELS.get(code, code),
                        "count": count,
                    }
                    for code, count in pattern_counter.most_common(20)
                ]
            )
            st.dataframe(pattern_df, use_container_width=True, hide_index=True)
        else:
            st.info("matched_patterns 정보가 없습니다.")


def render_filters(df):
    """Render filtering controls and return filtered DataFrame"""
    import streamlit as st

    st.markdown("### 필터")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        selected_severity = st.multiselect(
            "위험도",
            options=SEVERITY_ORDER,
            default=[sev for sev in SEVERITY_ORDER if sev in df["severity"].unique()],
        )

    all_reasons = sorted({r for reasons in df["reasons"] for r in reasons})
    with col2:
        selected_reasons = st.multiselect(
            "탐지 사유",
            options=all_reasons,
            default=[],
            format_func=lambda x: REASON_LABELS.get(x, x),
        )

    all_patterns = sorted({p for patterns in df["matched_patterns"] for p in patterns})
    with col3:
        selected_patterns = st.multiselect(
            "탐지 패턴",
            options=all_patterns,
            default=[],
            format_func=lambda x: REASON_LABELS.get(x, x),
        )

    with col4:
        keyword = st.text_input("경로/실경로/루트 검색", value="").strip()

    min_size_mb = st.number_input("최소 크기(MB)", min_value=0.0, value=0.0, step=1.0)

    filtered = df.copy()

    if selected_severity:
        filtered = filtered[filtered["severity"].isin(selected_severity)]

    if selected_reasons:
        filtered = filtered[
            filtered["reasons"].apply(lambda xs: any(x in xs for x in selected_reasons))
        ]

    if selected_patterns:
        filtered = filtered[
            filtered["matched_patterns"].apply(
                lambda xs: any(x in xs for x in selected_patterns)
            )
        ]

    if keyword:
        keyword_lower = keyword.lower()
        filtered = filtered[
            filtered.apply(
                lambda r: keyword_lower in str(r["path"]).lower()
                or keyword_lower in str(r["real_path"]).lower()
                or keyword_lower in str(r["root_matched"]).lower(),
                axis=1,
            )
        ]

    if min_size_mb > 0:
        filtered = filtered[
            filtered["size_bytes"].fillna(0) >= int(min_size_mb * 1024 * 1024)
        ]

    return filtered.reset_index(drop=True)


def interpret_finding(row):
    """Interpret a single finding and return explanation text"""
    reasons = row["reasons"]
    severity = row["severity"]

    lines = []
    lines.append(f"위험도는 **{severity}** 입니다.")

    if "high_risk_extension" in reasons:
        lines.append("- 웹 경로에 스크립트/실행/압축 등 고위험 확장자 계열 파일이 존재할 가능성이 있습니다.")
    if "mime_not_in_allowlist" in reasons:
        lines.append("- 파일 MIME이 허용 정책과 맞지 않아 웹루트 내 비정상 파일일 수 있습니다.")
    if "ext_not_in_allowlist" in reasons:
        lines.append("- 파일 확장자가 허용 정책 밖에 있어 업무 목적과 무관한 적재 파일일 수 있습니다.")
    if "large_file_in_web_path" in reasons:
        lines.append("- 웹 경로 내 대용량 파일은 스테이징 또는 반출 준비 흔적일 수 있습니다.")
    if "ext_mime_mismatch_image" in reasons or "ext_mime_mismatch_archive" in reasons:
        lines.append("- 확장자와 실제 MIME이 맞지 않아 위장 파일 가능성을 의심할 수 있습니다.")

    pii_related = [
        "resident_registration_number",
        "foreigner_registration_number",
        "passport_number",
        "drivers_license",
        "credit_card",
        "bank_account",
        "mobile_phone",
        "email_address",
        "birth_date",
    ]
    if any(x in reasons for x in pii_related):
        lines.append("- 개인정보 패턴이 파일 본문에서 탐지되었습니다. 원문 대신 마스킹 증거를 우선 검토해야 합니다.")

    if "secret_patterns" in reasons or "private_key_material" in reasons or "jdbc_connection_string" in reasons:
        lines.append("- 설정정보·자격증명·연결문자열 등 민감정보 유출 위험을 의심할 수 있습니다.")

    if row["url_exposure_heuristic"]:
        lines.append(f"- 노출 추정: **{row['url_exposure_heuristic']}**")

    return "\n".join(lines)