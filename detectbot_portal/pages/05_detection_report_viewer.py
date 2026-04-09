import json

import pandas as pd
import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.codebook import get_pattern_meaning, get_reason_meaning
from lib.navigation import render_portal_sidebar
from lib.report_viewer import (
    SEVERITY_ORDER,
    build_findings_df,
    filter_findings_df,
    fmt_dt,
    host_summary_text,
    interpret_finding,
    summarize_findings,
)
from lib.ui import (
    dataframe_or_info,
    format_timestamp_columns,
    inject_portal_css,
    render_metric_summary,
    render_portal_header,
)
from services.scan_service import ScanService
from services.server_service import ServerService


st.set_page_config(
    page_title="DetectBot 포털 - 탐지 리포트 뷰어",
    page_icon="RV",
    layout="wide",
)

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
inject_portal_css()
render_portal_sidebar(settings)

server_service = ServerService()
scan_service = ScanService()


def _server_label(servers_df, server_id):
    if not server_id:
        return "전체 서버"
    matched = servers_df.loc[servers_df["id"] == server_id, "server_name"]
    return matched.iloc[0] if not matched.empty else server_id


def _safe_json_loads(text, default):
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _apply_focus_from_other_pages():
    focus_server_id = st.session_state.pop("report_viewer_focus_server_id", "")
    focus_run_id = st.session_state.pop("report_viewer_focus_run_id", "")
    if focus_server_id:
        st.session_state["report_viewer_server_id"] = focus_server_id
    if focus_run_id:
        st.session_state["report_viewer_run_id"] = focus_run_id
    return bool(focus_server_id or focus_run_id)


def _choose_default_run_id(runs_df):
    current_run_id = st.session_state.get("report_viewer_run_id", "")
    if runs_df is None or runs_df.empty:
        st.session_state["report_viewer_run_id"] = ""
        return ""

    run_ids = runs_df["id"].tolist()
    if current_run_id in run_ids:
        return current_run_id

    latest_candidates = runs_df.loc[runs_df["latest_for_server"] == True, "id"].tolist()
    default_run_id = latest_candidates[0] if latest_candidates else run_ids[0]
    st.session_state["report_viewer_run_id"] = default_run_id
    return default_run_id


def _build_host_info(run_meta, raw_report):
    host = {
        "hostname": run_meta.get("host_hostname") or run_meta.get("hostname") or "",
        "primary_ip": run_meta.get("host_primary_ip") or run_meta.get("ip_address") or "",
        "os_type": run_meta.get("host_os_type") or run_meta.get("os_type") or "",
        "os_name": run_meta.get("host_os_name") or run_meta.get("os_name") or "",
        "os_version": "",
        "platform": run_meta.get("host_platform") or run_meta.get("platform") or "",
    }
    if raw_report and isinstance(raw_report.get("host"), dict):
        report_host = raw_report["host"]
        host["hostname"] = report_host.get("hostname") or host["hostname"]
        host["primary_ip"] = report_host.get("primary_ip") or host["primary_ip"]
        host["os_type"] = report_host.get("os_type") or host["os_type"]
        host["os_name"] = report_host.get("os_name") or host["os_name"]
        host["os_version"] = report_host.get("os_version") or host["os_version"]
        host["platform"] = report_host.get("platform") or host["platform"]
    return host


def _build_roots_df(detail, raw_report):
    if raw_report:
        roots = raw_report.get("roots") or raw_report.get("scan_roots") or []
        rows = [
            {
                "path": root.get("path", ""),
                "real_path": root.get("real_path", ""),
                "source": root.get("source", ""),
            }
            for root in roots
        ]
        return pd.DataFrame(rows)
    return detail.get("roots")


def _build_report_payload(detail):
    run_meta = detail.get("run") or {}
    raw_report = detail.get("raw_report")
    findings_records = detail["findings"].to_dict("records") if detail.get("findings") is not None else []
    if raw_report:
        return raw_report, findings_records

    payload = {
        "report_version": run_meta.get("scanner_version") or "",
        "generated_at": run_meta.get("generated_at"),
        "scan_started_at": run_meta.get("scan_started_at"),
        "host": {
            "hostname": run_meta.get("host_hostname") or run_meta.get("hostname") or "",
            "primary_ip": run_meta.get("host_primary_ip") or run_meta.get("ip_address") or "",
            "os_type": run_meta.get("host_os_type") or run_meta.get("os_type") or "",
            "os_name": run_meta.get("host_os_name") or run_meta.get("os_name") or "",
            "platform": run_meta.get("host_platform") or run_meta.get("platform") or "",
        },
        "config": _safe_json_loads(run_meta.get("config_json"), {}),
        "active_rules": _safe_json_loads(run_meta.get("active_rules_json"), []),
        "stats": {
            "findings_count": run_meta.get("findings_count", 0),
            "roots_count": run_meta.get("roots_count", 0),
            "scanned_files": run_meta.get("scanned_files", 0),
        },
        "findings": findings_records,
    }
    return payload, findings_records


render_portal_header(
    "탐지 리포트 뷰어",
    "서버와 스캔 실행 이력을 선택한 뒤, 저장된 리포트의 요약과 상세 Findings를 운영자 화면에서 확인합니다.",
)

st.caption("All displayed timestamps use KST (Asia/Seoul).")

focus_applied = _apply_focus_from_other_pages()

servers_df = server_service.list_servers_df(active_only=False)
server_options = [""]
if servers_df is not None and not servers_df.empty:
    server_options.extend(servers_df["id"].tolist())

selected_server_id = st.selectbox(
    "서버 선택",
    options=server_options,
    index=server_options.index(st.session_state.get("report_viewer_server_id", ""))
    if st.session_state.get("report_viewer_server_id", "") in server_options
    else 0,
    format_func=lambda value: _server_label(servers_df, value),
    key="report_viewer_server_id",
)

server_runs_df = format_timestamp_columns(
    scan_service.list_scan_runs_df(server_id=selected_server_id, limit=100) if selected_server_id else None,
    ["scan_started_at", "generated_at", "uploaded_at", "created_at"],
)

if focus_applied:
    st.info("다른 페이지에서 선택한 서버 또는 실행 이력을 기준으로 리포트 뷰어를 열었습니다. 필요하면 여기에서 다시 변경할 수 있습니다.")

if not selected_server_id:
    st.info("탐지 리포트를 보려면 먼저 서버를 선택해 주세요.")
    st.stop()

if server_runs_df is None or server_runs_df.empty:
    st.info("선택한 서버에 연결된 스캔 실행 이력이 없습니다.")
    st.stop()

selected_run_id = _choose_default_run_id(server_runs_df)
selected_run_id = st.selectbox(
    "스캔 실행 선택",
    options=server_runs_df["id"].tolist(),
    index=server_runs_df["id"].tolist().index(selected_run_id),
    format_func=lambda value: (
        f"{server_runs_df.loc[server_runs_df['id'] == value, 'generated_at'].iloc[0] or server_runs_df.loc[server_runs_df['id'] == value, 'scan_started_at'].iloc[0]} / "
        f"탐지 {int(server_runs_df.loc[server_runs_df['id'] == value, 'findings_count'].iloc[0] or 0)}건 / "
        f"{server_runs_df.loc[server_runs_df['id'] == value, 'input_type'].iloc[0] or '-'}"
    ),
    key="report_viewer_run_id",
)

detail = scan_service.get_scan_run_detail(selected_run_id)
if not detail:
    st.error("선택한 실행 이력의 상세 정보를 불러오지 못했습니다.")
    st.stop()

run_meta = detail.get("run") or {}
raw_report, raw_findings = _build_report_payload(detail)
report_error = detail.get("report_error")
host = _build_host_info(run_meta, raw_report)
config = raw_report.get("config", {}) if raw_report else _safe_json_loads(run_meta.get("config_json"), {})
active_rules = raw_report.get("active_rules", []) if raw_report else _safe_json_loads(run_meta.get("active_rules_json"), [])
stats = raw_report.get("stats", {}) if raw_report else {}
findings = raw_findings
findings_df = build_findings_df(findings)
roots_df = _build_roots_df(detail, raw_report)
severity_counter, reason_counter, pattern_counter = summarize_findings(findings_df)

if report_error and not raw_report:
    st.warning(f"원본 리포트 파일을 직접 읽지는 못했습니다. 저장된 실행 정보 기준으로 화면을 구성합니다. 사유: {report_error}")

render_metric_summary(
    [
        {"label": "선택 서버", "value": _server_label(servers_df, selected_server_id)},
        {"label": "실행 시각", "value": fmt_dt(run_meta.get("scan_started_at") or run_meta.get("generated_at"))},
        {"label": "Findings", "value": stats.get("findings_count", run_meta.get("findings_count", len(findings)))},
        {"label": "Roots", "value": stats.get("roots_count", run_meta.get("roots_count", 0))},
        {"label": "Host", "value": host_summary_text(host)},
    ]
)

with st.expander("리포트 기본 정보", expanded=True):
    left, right = st.columns(2)
    with left:
        os_detail = " ".join([part for part in [host.get("os_name"), host.get("os_version")] if part])
        st.write(f"**report_version**: {raw_report.get('report_version', run_meta.get('scanner_version') or '-')}")
        st.write(f"**hostname**: {host.get('hostname') or '-'}")
        st.write(f"**primary_ip**: {host.get('primary_ip') or '-'}")
        st.write(f"**os_type**: {host.get('os_type') or '-'}")
        st.write(f"**os_detail**: {os_detail or '-'}")
        st.write(f"**platform**: {host.get('platform') or '-'}")
        st.write(f"**generated_at**: {fmt_dt(raw_report.get('generated_at') if raw_report else run_meta.get('generated_at'))}")
        st.write(f"**scan_started_at**: {fmt_dt(raw_report.get('scan_started_at') if raw_report else run_meta.get('scan_started_at'))}")
        st.write(f"**active_rules**: {', '.join(active_rules) if active_rules else '-'}")
    with right:
        st.write(f"**server_name**: {run_meta.get('server_name') or '-'}")
        st.write(f"**file_name**: {run_meta.get('file_name') or '-'}")
        st.write(f"**stored_path**: {run_meta.get('stored_path') or '-'}")
        st.write(f"**uploaded_at**: {fmt_dt(run_meta.get('uploaded_at'))}")
        st.write(f"**created_at**: {fmt_dt(run_meta.get('created_at'))}")
        st.write(f"**roots_count**: {stats.get('roots_count', run_meta.get('roots_count', 0))}")
        st.write(f"**scanned_files**: {stats.get('scanned_files', run_meta.get('scanned_files', '-'))}")
        st.write(f"**findings_count**: {stats.get('findings_count', run_meta.get('findings_count', len(findings)))}")

tab_summary, tab_roots, tab_findings, tab_config, tab_raw = st.tabs(
    ["요약", "Roots", "Findings", "Config", "원본 JSON"]
)

with tab_summary:
    if findings_df is None or findings_df.empty:
        st.success("탐지 결과가 없습니다. 선택한 실행은 탐지 없는 정상 리포트입니다.")
    else:
        sev_rows = [
            {"severity": severity, "count": severity_counter.get(severity, 0)}
            for severity in SEVERITY_ORDER
            if severity_counter.get(severity, 0) > 0
        ]
        reason_rows = [
            {"reason_code": code, "meaning": get_reason_meaning(code), "count": count}
            for code, count in reason_counter.most_common(20)
        ]
        pattern_rows = [
            {"pattern": code, "meaning": get_pattern_meaning(code), "count": count}
            for code, count in pattern_counter.most_common(20)
        ]
        col1, col2 = st.columns(2)
        with col1:
            dataframe_or_info(pd.DataFrame(sev_rows), "위험도 집계가 없습니다.")
            if sev_rows:
                st.bar_chart(pd.DataFrame(sev_rows).set_index("severity")["count"])
        with col2:
            dataframe_or_info(pd.DataFrame(reason_rows), "탐지 사유 집계가 없습니다.")
        st.markdown("#### 패턴 Top")
        dataframe_or_info(pd.DataFrame(pattern_rows), "탐지 패턴 집계가 없습니다.")

with tab_roots:
    st.markdown("### 추출된 스캔 루트")
    dataframe_or_info(roots_df, "루트 정보가 없습니다.")

with tab_findings:
    st.markdown("### 탐지 결과")
    if findings_df is None or findings_df.empty:
        st.success("탐지 결과가 없습니다.")
    else:
        filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
        with filter_col1:
            selected_severity = st.multiselect(
                "위험도",
                options=SEVERITY_ORDER,
                default=[sev for sev in SEVERITY_ORDER if sev in findings_df["severity"].unique()],
            )
        all_reasons = sorted({reason for reasons in findings_df["reasons"] for reason in reasons})
        with filter_col2:
            selected_reasons = st.multiselect("탐지 사유", options=all_reasons, default=[])
        all_patterns = sorted({pattern for patterns in findings_df["matched_patterns"] for pattern in patterns})
        with filter_col3:
            selected_patterns = st.multiselect("탐지 패턴", options=all_patterns, default=[])
        with filter_col4:
            keyword = st.text_input("경로/루트 검색", value="").strip()

        min_size_mb = st.number_input("최소 크기(MB)", min_value=0.0, value=0.0, step=1.0)
        filtered_df = filter_findings_df(
            findings_df,
            severities=selected_severity,
            reasons=selected_reasons,
            patterns=selected_patterns,
            keyword=keyword,
            min_size_mb=min_size_mb,
        )

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
        st.write(f"조회 결과: **{len(filtered_df)}건**")
        st.dataframe(filtered_df[display_cols], width="stretch", hide_index=True)

        if len(filtered_df) > 0:
            selected_idx = st.selectbox(
                "상세 해석 대상 선택",
                options=filtered_df.index.tolist(),
                format_func=lambda index: f"[{filtered_df.loc[index, 'severity']}] {filtered_df.loc[index, 'path']}",
                key="report_viewer_selected_finding_idx",
            )
            row = filtered_df.loc[selected_idx]

            st.markdown("#### 상세 해석")
            st.markdown(interpret_finding(row))

            c1, c2 = st.columns(2)
            with c1:
                st.markdown("#### 메타 정보")
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
                st.write(f"**matched_patterns**: {', '.join(row['matched_patterns']) if row['matched_patterns'] else '-'}")
                st.write(f"**content_flags**: {', '.join(row['content_flags']) if row['content_flags'] else '-'}")
                st.write(f"**url_exposure_heuristic**: {row['url_exposure_heuristic'] or '-'}")

            st.markdown("#### 마스킹된 증거")
            if row["evidence_masked"]:
                for evidence in row["evidence_masked"]:
                    st.code(evidence)
            else:
                st.info("evidence_masked 값이 없습니다.")

with tab_config:
    st.markdown("### 실행 설정")
    if config:
        st.json(config, expanded=False)
    else:
        st.info("저장된 설정 정보가 없습니다.")

    st.markdown("### 활성 규칙")
    if active_rules:
        st.write(", ".join(str(rule) for rule in active_rules))
    else:
        st.info("활성 규칙 정보가 없습니다.")

with tab_raw:
    st.markdown("### 원본 리포트 JSON")
    if raw_report:
        st.json(raw_report, expanded=False)
    else:
        st.info("원본 리포트 파일을 직접 불러오지 못해 실행 메타데이터만 확인할 수 있습니다.")
        st.json(run_meta, expanded=False)
