from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.models import INPUT_TYPES
from lib.navigation import render_portal_sidebar
from lib.time_utils import format_display_datetime
from lib.ui import dataframe_or_info, format_timestamp_columns, inject_portal_css, render_portal_header
from services.policy_service import PolicyService
from services.scan_service import ScanService
from services.server_service import ServerService


st.set_page_config(page_title="DetectBot 포털 - 리포트 업로드 및 저장 이력", page_icon="SC", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
inject_portal_css()
render_portal_sidebar(settings)

scan_service = ScanService()
server_service = ServerService()
policy_service = PolicyService()


def server_label(servers_df, server_id):
    if not server_id:
        return "전체 서버"
    matched = servers_df.loc[servers_df["id"] == server_id, "server_name"]
    return matched.iloc[0] if not matched.empty else server_id


def policy_label(policies_df, policy_id):
    if not policy_id:
        return "전체 정책"
    matched = policies_df.loc[policies_df["id"] == policy_id, "policy_name"]
    return matched.iloc[0] if not matched.empty else policy_id


def input_type_label(value):
    labels = {
        "manual_json": "수동 JSON",
        "nginx_dump": "Nginx 덤프",
        "apache_dump": "Apache 덤프",
        "watch_dir": "감시 디렉터리",
        "kafka_event": "Kafka 이벤트",
        "unknown": "미분류",
        "": "자동 판별",
    }
    return labels.get(value or "", value or "자동 판별")


def build_run_history_display_df(df: pd.DataFrame | None):
    if df is None or df.empty:
        return df

    display = df.copy()
    display["서버명"] = display["server_name"].fillna("미연결 서버")
    display["정책명"] = display["policy_name"].fillna("정책 미지정")
    display["입력 유형"] = display["input_type"].apply(input_type_label)
    display["탐지 건수"] = display["findings_count"].fillna(0).astype(int)
    display["스캔 시각"] = display["generated_at"].fillna(display["scan_started_at"]).fillna("")
    display["업로드 시각"] = display["uploaded_at"].fillna("")
    display["리포트 파일"] = display["file_name"].fillna("")
    display["최신"] = display["latest_for_server"].apply(lambda value: "최신" if value else "")
    return display[
        ["최신", "서버명", "정책명", "입력 유형", "탐지 건수", "스캔 시각", "업로드 시각", "리포트 파일"]
    ]


def build_findings_display_df(df: pd.DataFrame | None):
    if df is None or df.empty:
        return df

    display = df.copy()
    severity_map = {
        "critical": "심각",
        "high": "높음",
        "medium": "보통",
        "low": "낮음",
        "unknown": "미분류",
    }
    display["경로"] = display["path"].fillna("")
    display["위험도"] = display["severity"].fillna("").map(severity_map).fillna("미분류")
    display["사유"] = display["reason_meanings"].where(display["reason_meanings"] != "", display["reason_codes"])
    display["패턴"] = display["pattern_meanings"].where(display["pattern_meanings"] != "", display["pattern_codes"])
    display["탐지 시각"] = display["generated_at"].fillna("")
    return display[["경로", "위험도", "사유", "패턴", "탐지 시각"]]


def render_run_summary(run: dict):
    st.markdown("### 선택한 이력 요약")
    cols = st.columns(4)
    cols[0].metric("서버", run.get("server_name") or "미연결 서버")
    cols[1].metric("탐지 건수", int(run.get("findings_count") or 0))
    cols[2].metric("입력 유형", input_type_label(run.get("input_type") or ""))
    cols[3].metric("정책", run.get("policy_name") or "정책 미지정")
    st.write(f"**스캔 시각**: {format_display_datetime(run.get('generated_at') or run.get('scan_started_at'))}")
    st.write(f"**업로드 사용자**: {run.get('uploaded_by') or '-'}")
    st.write(f"**리포트 파일**: {run.get('file_name') or '-'}")


def render_run_overview_json(run: dict):
    overview = {
        "server_name": run.get("server_name") or "",
        "hostname": run.get("hostname") or "",
        "ip_address": run.get("ip_address") or "",
        "policy_name": run.get("policy_name") or "",
        "input_type": input_type_label(run.get("input_type") or ""),
        "generated_at": run.get("generated_at"),
        "scan_started_at": run.get("scan_started_at"),
        "uploaded_at": run.get("uploaded_at"),
        "findings_count": run.get("findings_count", 0),
        "roots_count": run.get("roots_count", 0),
        "scanned_files": run.get("scanned_files", 0),
        "file_name": run.get("file_name") or "",
        "original_path": run.get("original_path") or "",
    }
    st.json(overview, expanded=False)


def sanitize_finding_detail(detail: dict | None):
    if not detail:
        return detail
    sanitized = dict(detail)
    sanitized.pop("id", None)
    sanitized.pop("scan_run_id", None)
    sanitized.pop("server_id", None)
    return sanitized


def render_selected_run_banner(run: dict, highlight_recent: bool = False):
    accent = "#0f766e" if highlight_recent else "#2563eb"
    title = "방금 등록한 실행 이력" if highlight_recent else "현재 선택한 실행 이력"
    hint = (
        "업로드 직후 선택된 이력입니다. 아래에서 통계와 Findings를 바로 확인할 수 있습니다."
        if highlight_recent
        else "현재 이력을 기준으로 아래 상세 정보와 Findings가 표시됩니다."
    )
    generated_at = format_display_datetime(run.get("generated_at") or run.get("scan_started_at"))
    server_name = run.get("server_name") or "미연결 서버"
    findings_count = int(run.get("findings_count") or 0)
    file_name = run.get("file_name") or "-"
    input_type = input_type_label(run.get("input_type") or "")
    st.markdown(
        f"""
        <div style="border:1px solid {accent}33; border-left:6px solid {accent};
                    border-radius:18px; padding:1rem 1.1rem; background:linear-gradient(180deg, #eff6ff 0%, #ffffff 100%);
                    box-shadow:0 2px 8px rgba(37, 99, 235, 0.08); margin:0.75rem 0 1rem 0;">
          <div style="font-size:0.9rem; font-weight:700; color:{accent}; margin-bottom:0.25rem;">{title}</div>
          <div style="font-size:1.15rem; font-weight:700; color:#0f172a; margin-bottom:0.35rem;">{server_name}</div>
          <div style="color:#475569; font-size:0.92rem; margin-bottom:0.45rem;">
            스캔 시각: {generated_at} · 입력 유형: {input_type} · 탐지 건수: {findings_count}건
          </div>
          <div style="color:#475569; font-size:0.88rem; margin-bottom:0.35rem;">리포트 파일: {file_name}</div>
          <div style="color:{accent}; font-size:0.84rem; font-weight:600;">{hint}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


render_portal_header(
    "리포트 업로드 및 저장 이력",
    "스캔 리포트를 업로드하고, 저장된 실행 이력을 필터링한 뒤, 선택한 이력의 통계와 Findings를 확인합니다.",
)

for key, value in {
    "report_history_server_filter": "",
    "report_history_policy_filter": "",
    "report_history_input_type_filter": "",
    "report_history_latest_only": False,
    "report_history_findings_only": False,
    "report_history_recent_days": 30,
    "report_history_selected_run_id": "",
    "report_history_recent_upload_run_id": "",
}.items():
    st.session_state.setdefault(key, value)

servers_df = server_service.list_servers_df(active_only=False)
policies_df = policy_service.list_policies_df(active_only=False)
all_runs_source_df = scan_service.list_scan_runs_df(limit=500)
all_runs_df = format_timestamp_columns(
    all_runs_source_df,
    ["scan_started_at", "generated_at", "uploaded_at", "created_at"],
)

st.caption("좌측 메뉴에서 다른 화면으로 이동할 수 있으며, 이 화면에서는 리포트 업로드와 저장된 실행 이력 확인을 함께 진행할 수 있습니다.")

tab_upload, tab_history = st.tabs(["리포트 업로드", "저장 이력"])

with tab_upload:
    st.info("JSON 리포트를 업로드하면 포털에 저장되고, 업로드 직후 저장 이력 탭에서 해당 실행 이력을 바로 확인할 수 있습니다.")
    with st.form("scan_upload_form"):
        uploaded_file = st.file_uploader("리포트 파일", type=["json"], help="DetectBot JSON 리포트를 업로드합니다.")
        original_path = st.text_input("원본 리포트 경로", placeholder="예: /var/reports/report.json")
        uploaded_by = st.text_input("업로드 사용자", value="portal-admin")
        selected_server_id = st.selectbox(
            "대상 서버",
            options=["AUTO"] + (servers_df["id"].tolist() if not servers_df.empty else []),
            format_func=lambda value: "자동 식별" if value == "AUTO" else server_label(servers_df, value),
        )
        selected_policy_id = st.selectbox(
            "적용 정책",
            options=[""] + (policies_df["id"].tolist() if not policies_df.empty else []),
            format_func=lambda value: policy_label(policies_df, value),
        )
        input_type = st.selectbox(
            "입력 유형",
            options=[""] + INPUT_TYPES,
            format_func=input_type_label,
        )
        auto_create_server = st.checkbox("일치하는 서버가 없으면 자동으로 등록", value=True)
        submitted = st.form_submit_button("리포트 업로드", width="stretch")
        if submitted:
            if uploaded_file is None:
                st.error("먼저 업로드할 JSON 리포트 파일을 선택해 주세요.")
            else:
                result = scan_service.ingest_report(
                    uploaded_file.getvalue(),
                    uploaded_file.name,
                    server_id=None if selected_server_id == "AUTO" else selected_server_id,
                    policy_id=selected_policy_id or None,
                    input_type=input_type or None,
                    uploaded_by=uploaded_by,
                    original_path=original_path,
                    auto_create_server=auto_create_server,
                )
                st.session_state["report_history_selected_run_id"] = result["scan_run_id"]
                st.session_state["report_history_recent_upload_run_id"] = result["scan_run_id"]
                st.success("리포트 업로드가 완료되었습니다. 저장 이력 탭에서 방금 등록된 실행 이력을 바로 확인할 수 있습니다.")
                st.rerun()

with tab_history:
    st.info("필터로 원하는 실행 이력을 좁힌 뒤, 아래 목록에서 이력을 선택하면 상세 정보와 Findings를 확인할 수 있습니다.")
    filter_cols = st.columns(5)
    with filter_cols[0]:
        st.selectbox(
            "서버",
            options=[""] + (servers_df["id"].tolist() if not servers_df.empty else []),
            format_func=lambda value: server_label(servers_df, value),
            key="report_history_server_filter",
        )
    with filter_cols[1]:
        st.selectbox(
            "정책",
            options=[""] + (policies_df["id"].tolist() if not policies_df.empty else []),
            format_func=lambda value: policy_label(policies_df, value),
            key="report_history_policy_filter",
        )
    with filter_cols[2]:
        st.selectbox(
            "입력 유형",
            options=[""] + INPUT_TYPES,
            key="report_history_input_type_filter",
            format_func=input_type_label,
        )
    with filter_cols[3]:
        st.selectbox(
            "조회 기간",
            options=[7, 30, 90, 180, 0],
            key="report_history_recent_days",
            format_func=lambda value: "전체 기간" if value == 0 else f"최근 {value}일",
        )
    with filter_cols[4]:
        st.checkbox("최신 이력만 보기", key="report_history_latest_only")
    st.checkbox("Findings가 있는 이력만 보기", key="report_history_findings_only")

    filtered_source = all_runs_source_df.copy() if all_runs_source_df is not None else pd.DataFrame()
    if st.session_state["report_history_server_filter"] and not filtered_source.empty:
        filtered_source = filtered_source[filtered_source["server_id"] == st.session_state["report_history_server_filter"]]
    if st.session_state["report_history_policy_filter"] and not filtered_source.empty:
        filtered_source = filtered_source[filtered_source["policy_id"] == st.session_state["report_history_policy_filter"]]
    if st.session_state["report_history_input_type_filter"] and not filtered_source.empty:
        filtered_source = filtered_source[filtered_source["input_type"] == st.session_state["report_history_input_type_filter"]]
    if st.session_state["report_history_latest_only"] and not filtered_source.empty:
        filtered_source = filtered_source[filtered_source["latest_for_server"] == True]
    if st.session_state["report_history_findings_only"] and not filtered_source.empty:
        filtered_source = filtered_source[filtered_source["findings_count"].fillna(0).astype(int) > 0]
    if st.session_state["report_history_recent_days"] != 0 and not filtered_source.empty:
        cutoff = pd.Timestamp(datetime.now() - timedelta(days=int(st.session_state["report_history_recent_days"])))
        generated_series = pd.to_datetime(filtered_source["generated_at"], errors="coerce", utc=True)
        filtered_source = filtered_source[generated_series >= cutoff.tz_localize("UTC")]

    filtered = format_timestamp_columns(
        filtered_source,
        ["scan_started_at", "generated_at", "uploaded_at", "created_at"],
    )

    st.caption(f"현재 조건에 맞는 실행 이력: {0 if filtered is None else len(filtered)}건")
    st.markdown("### 저장 이력 목록")
    dataframe_or_info(build_run_history_display_df(filtered), "현재 필터 조건에 맞는 저장 이력이 없습니다.")

    if filtered is not None and not filtered.empty:
        run_ids = filtered["id"].tolist()
        if st.session_state["report_history_selected_run_id"] not in run_ids:
            st.session_state["report_history_selected_run_id"] = run_ids[0]
        selected_run_id = st.selectbox(
            "선택한 이력",
            options=run_ids,
            index=run_ids.index(st.session_state["report_history_selected_run_id"]),
            format_func=lambda value: (
                f"{filtered.loc[filtered['id'] == value, 'server_name'].iloc[0]} / "
                f"{filtered.loc[filtered['id'] == value, 'generated_at'].fillna(filtered.loc[filtered['id'] == value, 'scan_started_at']).iloc[0]}"
            ),
        )
        st.session_state["report_history_selected_run_id"] = selected_run_id
        detail = scan_service.get_scan_run_detail(selected_run_id)
        if detail:
            highlight_recent = selected_run_id == st.session_state.get("report_history_recent_upload_run_id", "")
            render_selected_run_banner(detail["run"], highlight_recent=highlight_recent)
            if highlight_recent:
                st.info("방금 업로드한 리포트의 실행 이력이 선택되어 있습니다.")
            render_run_summary(detail["run"])

            metric_cols = st.columns(3)
            metric_cols[0].metric("탐지 건수", int(detail["run"].get("findings_count") or 0))
            metric_cols[1].metric("루트 수", int(detail["run"].get("roots_count") or 0))
            metric_cols[2].metric("스캔 파일 수", int(detail["run"].get("scanned_files") or 0))

            st.markdown("### 실행 상세")
            render_run_overview_json(detail["run"])

            summary_col1, summary_col2 = st.columns(2)
            with summary_col1:
                st.markdown("#### 위험도 통계")
                dataframe_or_info(detail["severity_counts"], "위험도 통계가 없습니다.")
                if detail["severity_counts"] is not None and not detail["severity_counts"].empty:
                    st.bar_chart(detail["severity_counts"].set_index("severity")["count"])
            with summary_col2:
                st.markdown("#### 사유 코드 통계")
                dataframe_or_info(detail["reason_counts"], "사유 코드 통계가 없습니다.")

            st.markdown("### Findings 목록")
            findings_df = format_timestamp_columns(detail["findings"], ["generated_at", "mod_time", "created_at"])
            dataframe_or_info(build_findings_display_df(findings_df), "선택한 실행 이력에 Findings가 없습니다.")
            if findings_df is not None and not findings_df.empty:
                finding_id = st.selectbox(
                    "상세 확인할 Findings",
                    options=findings_df["id"].tolist(),
                    format_func=lambda value: findings_df.loc[findings_df["id"] == value, "path"].iloc[0],
                )
                st.markdown("#### 선택한 Findings 상세")
                st.json(sanitize_finding_detail(scan_service.get_finding_detail(finding_id)), expanded=False)
