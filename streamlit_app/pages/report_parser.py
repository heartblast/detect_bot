import json
from collections import Counter
from datetime import datetime

import pandas as pd
import streamlit as st

from lib.constants import SEVERITY_ORDER, SEVERITY_EMOJI, REASON_LABELS
from lib.utils import safe_json_load, normalize_list, fmt_dt, fmt_bytes, severity_rank
from lib.report_parser import (
    build_findings_df,
    render_summary,
    render_root_table,
    render_counters,
    render_filters,
    interpret_finding,
)


st.title("🛡️ DMZ 웹루트 스캔 결과 해석기")
st.caption("dmz_webroot_scanner JSON 결과를 업로드하면 위험도, 탐지사유, 루트경로, 세부 증거를 해석해줍니다.")

uploaded = st.file_uploader("JSON 결과 파일 업로드", type=["json"])

if not uploaded:
    st.info("dmz_webroot_scanner의 결과 JSON 파일을 업로드하세요.")
    st.stop()

report = safe_json_load(uploaded)
findings = normalize_list(report.get("findings"))
roots = normalize_list(report.get("roots"))
config = report.get("config", {}) or {}
active_rules = normalize_list(report.get("active_rules"))

render_summary(report)

with st.expander("리포트 기본 정보", expanded=True):
    left, right = st.columns(2)

    with left:
        st.write(f"**report_version**: {report.get('report_version', '-')}")
        st.write(f"**host**: {report.get('host', '-')}")
        st.write(f"**generated_at**: {fmt_dt(report.get('generated_at'))}")
        st.write(f"**scan_started_at**: {fmt_dt(report.get('scan_started_at'))}")
        st.write(f"**active_rules**: {', '.join(active_rules) if active_rules else '-'}")

    with right:
        stats = report.get("stats", {}) or {}
        st.write(f"**roots_count**: {stats.get('roots_count', len(roots))}")
        st.write(f"**scanned_files**: {stats.get('scanned_files', '-')}")
        st.write(f"**findings_count**: {stats.get('findings_count', len(findings))}")

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["요약", "Roots", "Findings", "Config", "원본 JSON"]
)

with tab1:
    if findings:
        findings_df = build_findings_df(findings)
        render_counters(findings_df)
    else:
        st.success("findings 가 없습니다. 탐지된 항목이 없는 리포트입니다.")

with tab2:
    st.markdown("### 추출된 웹서빙 경로")
    render_root_table(roots)

with tab3:
    st.markdown("### 탐지 결과")
    if not findings:
        st.success("탐지 결과가 없습니다.")
    else:
        findings_df = build_findings_df(findings)
        filtered_df = render_filters(findings_df)

        st.write(f"조회 결과: **{len(filtered_df)}건**")

        display_cols = [
            "severity",
            "path",
            "size_human",
            "mod_time_fmt",
            "ext",
            "mime_sniff",
            "root_source",
            "reasons_text",
            "matched_patterns_text",
        ]
        st.dataframe(
            filtered_df[display_cols],
            use_container_width=True,
            hide_index=True,
        )

        if len(filtered_df) > 0:
            selected_idx = st.selectbox(
                "상세 해석할 항목 선택",
                options=filtered_df.index.tolist(),
                format_func=lambda i: f"[{filtered_df.loc[i, 'severity']}] {filtered_df.loc[i, 'path']}",
            )
            row = filtered_df.loc[selected_idx]

            st.markdown("#### 상세 해석")
            st.markdown(interpret_finding(row))

            c1, c2 = st.columns(2)
            with c1:
                st.markdown("#### 메타정보")
                st.write(f"**path**: {row['path']}")
                st.write(f"**real_path**: {row['real_path'] or '-'}")
                st.write(f"**root_matched**: {row['root_matched'] or '-'}")
                st.write(f"**root_source**: {row['root_source'] or '-'}")
                st.write(f"**size**: {row['size_human']}")
                st.write(f"**mod_time**: {row['mod_time_fmt']}")
                st.write(f"**perm**: {row['perm'] or '-'}")
                st.write(f"**ext**: {row['ext'] or '-'}")
                st.write(f"**mime_sniff**: {row['mime_sniff'] or '-'}")
                st.write(f"**sha256**: {row['sha256'] or '-'}")

            with c2:
                st.markdown("#### 탐지 정보")
                st.write(f"**severity**: {row['severity']}")
                st.write(f"**reasons**: {', '.join(row['reasons']) if row['reasons'] else '-'}")
                st.write(
                    f"**matched_patterns**: {', '.join(row['matched_patterns']) if row['matched_patterns'] else '-'}"
                )
                st.write(
                    f"**content_flags**: {', '.join(row['content_flags']) if row['content_flags'] else '-'}"
                )
                st.write(
                    f"**url_exposure_heuristic**: {row['url_exposure_heuristic'] or '-'}"
                )

            st.markdown("#### 마스킹 증거")
            if row["evidence_masked"]:
                for ev in row["evidence_masked"]:
                    st.code(ev)
            else:
                st.info("evidence_masked 값이 없습니다.")

with tab4:
    st.markdown("### 실행 설정")
    if config:
        st.json(config, expanded=False)
    else:
        st.info("config 정보가 없습니다.")

with tab5:
    st.markdown("### 원본 JSON")
    st.json(report, expanded=False)