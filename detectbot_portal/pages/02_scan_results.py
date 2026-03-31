from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from lib.db import init_db
from lib.ingest import ingest_report
from lib.repository import get_scan_run_detail, list_policies, list_scan_runs, list_servers
from lib.seed import bootstrap_demo_data
from lib.ui import (
    build_scan_run_display_df,
    dataframe_or_info,
    format_timestamp_columns,
    inject_portal_css,
    input_type_badge_text,
    json_text_to_lines,
    render_info_panel,
    render_metric_summary,
    render_portal_header,
    render_run_selection_cards,
    render_scan_run_overview,
    style_scan_run_table,
)


st.set_page_config(
    page_title="DetectBot Portal - 점검 결과 관리",
    page_icon="📋",
    layout="wide",
)

init_db()
bootstrap_demo_data()
inject_portal_css()


def _safe_to_datetime(series):
    return pd.to_datetime(series, errors="coerce")


def _format_dt(value):
    if not value:
        return "-"
    try:
        return str(value).replace("T", " ")
    except Exception:
        return str(value)


def _server_label(servers_df, server_id):
    if not server_id:
        return "전체 서버"
    matched = servers_df.loc[servers_df["id"] == server_id, "server_name"]
    return matched.iloc[0] if not matched.empty else server_id


def _policy_label(policies_df, policy_id):
    if not policy_id:
        return "전체 정책"
    matched = policies_df.loc[policies_df["id"] == policy_id, "policy_name"]
    return matched.iloc[0] if not matched.empty else policy_id


def _reset_history_filters():
    defaults = {
        "scan_results_server_filter": "",
        "scan_results_policy_filter": "",
        "scan_results_input_type_filter": "",
        "scan_results_host_keyword": "",
        "scan_results_latest_only": False,
        "scan_results_findings_only": False,
        "scan_results_recent_days": 30,
    }
    for key, value in defaults.items():
        st.session_state[key] = value


def _apply_inventory_focus_filter():
    focus_server_id = st.session_state.pop("scan_results_focus_server_id", "")
    focus_origin = st.session_state.pop("scan_results_focus_origin", "")
    if not focus_server_id:
        return None

    st.session_state["scan_results_server_filter"] = focus_server_id
    st.session_state["scan_results_latest_only"] = False
    st.session_state["scan_results_findings_only"] = False
    st.session_state["scan_results_host_keyword"] = ""
    return {
        "server_id": focus_server_id,
        "origin": focus_origin or "server_inventory",
    }


def _open_detection_report_viewer(server_id="", scan_run_id=""):
    if server_id:
        st.session_state["report_viewer_focus_server_id"] = server_id
    if scan_run_id:
        st.session_state["report_viewer_focus_run_id"] = scan_run_id
    st.switch_page("pages/05_detection_report_viewer.py")


def _filter_runs(runs_df):
    if runs_df is None or runs_df.empty:
        return runs_df

    filtered = runs_df.copy()

    server_filter = st.session_state.get("scan_results_server_filter", "")
    policy_filter = st.session_state.get("scan_results_policy_filter", "")
    input_type_filter = st.session_state.get("scan_results_input_type_filter", "")
    host_keyword = st.session_state.get("scan_results_host_keyword", "").strip().lower()
    latest_only = st.session_state.get("scan_results_latest_only", False)
    findings_only = st.session_state.get("scan_results_findings_only", False)
    recent_days = int(st.session_state.get("scan_results_recent_days", 30) or 0)

    if server_filter:
        filtered = filtered[filtered["server_id"] == server_filter]
    if policy_filter:
        filtered = filtered[filtered["policy_id"].fillna("") == policy_filter]
    if input_type_filter:
        filtered = filtered[filtered["input_type"].fillna("") == input_type_filter]
    if host_keyword:
        filtered = filtered[
            filtered.apply(
                lambda row: host_keyword in str(row.get("server_name", "")).lower()
                or host_keyword in str(row.get("host_hostname", "") or row.get("hostname", "")).lower()
                or host_keyword in str(row.get("host_primary_ip", "") or row.get("ip_address", "")).lower()
                or host_keyword in str(row.get("host_os_type", "") or row.get("os_type", "")).lower(),
                axis=1,
            )
        ]
    if latest_only:
        filtered = filtered[filtered["latest_for_server"] == True]
    if findings_only:
        filtered = filtered[filtered["findings_count"].fillna(0).astype(int) > 0]
    if recent_days > 0:
        cutoff = pd.Timestamp(datetime.now() - timedelta(days=recent_days))
        filtered = filtered[filtered["sort_time"] >= cutoff]

    filtered = filtered.sort_values(
        by=["latest_rank", "findings_count_num", "sort_time", "server_name"],
        ascending=[False, False, False, True],
        na_position="last",
    )
    return filtered.reset_index(drop=True)


def _prepare_runs(runs_df):
    if runs_df is None or runs_df.empty:
        return runs_df

    prepared = format_timestamp_columns(
        runs_df,
        ["scan_started_at", "generated_at"],
    ).copy()
    prepared["sort_time"] = _safe_to_datetime(
        prepared["generated_at"].where(prepared["generated_at"] != "", prepared["scan_started_at"])
    )
    prepared["findings_count_num"] = prepared["findings_count"].fillna(0).astype(int)
    prepared["latest_rank"] = prepared["latest_for_server"].fillna(False).astype(int)
    return prepared


def _summary_metrics(runs_df):
    if runs_df is None or runs_df.empty:
        return [
            {"label": "조회 실행", "value": 0},
            {"label": "최신 실행", "value": 0},
            {"label": "탐지 포함 실행", "value": 0},
            {"label": "탐지 건수 합계", "value": 0},
        ]

    findings = runs_df["findings_count_num"].sum()
    return [
        {"label": "조회 실행", "value": int(len(runs_df))},
        {"label": "최신 실행", "value": int(runs_df["latest_rank"].sum())},
        {"label": "탐지 포함 실행", "value": int((runs_df["findings_count_num"] > 0).sum())},
        {"label": "탐지 건수 합계", "value": int(findings)},
    ]


def _format_count_table(df, code_column):
    if df is None or df.empty:
        return df
    renamed = df.copy()
    renamed = renamed.rename(
        columns={
            code_column: "코드",
            "meaning": "의미",
            "count": "건수",
        }
    )
    return renamed[["코드", "의미", "건수"]]


def _format_roots_table(df):
    if df is None or df.empty:
        return df
    renamed = df.rename(
        columns={
            "root_path": "점검 루트",
            "real_path": "실제 경로",
            "source_type": "입력 소스",
        }
    )
    return renamed[["점검 루트", "실제 경로", "입력 소스"]]


render_portal_header(
    "점검 결과 관리",
    "JSON 리포트 적재, 점검 실행 이력 조회, 실행별 상세 분석을 한 화면에서 관리합니다.",
)

focus_context = _apply_inventory_focus_filter()

servers_df = list_servers(active_only=False)
policies_df = list_policies(active_only=False)
all_runs_df = list_scan_runs(limit=400)

if all_runs_df is None:
    all_runs_df = pd.DataFrame()
if "server_id" not in all_runs_df.columns:
    all_runs_df["server_id"] = ""
if "policy_id" not in all_runs_df.columns:
    all_runs_df["policy_id"] = ""

prepared_runs_df = _prepare_runs(all_runs_df)

page_metrics = _summary_metrics(prepared_runs_df)
render_metric_summary(page_metrics)

render_info_panel(
    "점검 결과 관리 허브",
    "리포트를 업로드하면 실행 이력에 누적 저장되고, 아래 실행 이력 탭에서 최신 실행과 탐지 건수가 많은 실행을 바로 확인할 수 있습니다.",
)

if focus_context:
    st.info("서버 인벤토리에서 선택한 서버 기준으로 스캔 결과 필터가 적용되었습니다. 필요하면 여기서 다른 서버로 바꾸거나 필터를 해제할 수 있습니다.")

flash_result = st.session_state.pop("scan_results_last_ingest", None)
if flash_result:
    st.success(
        f"리포트 적재가 완료되었습니다. 탐지 {flash_result['findings_count']}건, scan_run_id={flash_result['scan_run_id']}"
    )
    flash_col1, flash_col2, flash_col3 = st.columns(3)
    flash_col1.metric("적재된 탐지 건수", int(flash_result["findings_count"]))
    flash_col2.metric("생성된 실행 ID", flash_result["scan_run_id"][:8])
    flash_col3.metric("연결 서버", flash_result.get("server_name") or flash_result["server_id"][:8])
    st.caption(f"저장 위치: {flash_result['stored_path']}")
    st.info("이제 아래 '실행 이력' 탭에서 방금 적재한 실행을 바로 확인할 수 있습니다.")

tab_upload, tab_history = st.tabs(["리포트 등록", "실행 이력"])

with tab_upload:
    intro_left, intro_right = st.columns((1.25, 1))
    with intro_left:
        render_info_panel(
            "등록 흐름",
            "1. JSON 리포트를 선택합니다. 2. 대상 서버와 정책을 확인합니다. 3. 적재 후 실행 이력에서 최신 실행을 확인합니다.",
        )
    with intro_right:
        st.markdown("#### 등록 시 확인할 항목")
        st.write("- 대상 서버: 특정 서버에 연결하거나, 리포트 host 기준으로 자동 연결합니다.")
        st.write("- 정책: 실제 스캔에 사용한 정책을 알고 있다면 함께 남겨 이력 해석성을 높입니다.")
        st.write("- 입력 유형: 리포트가 어떤 방식으로 수집되었는지 구분합니다.")
        st.write("- 서버 자동 등록 허용: 미등록 host를 새 서버 자산으로 등록할지 결정합니다.")

    with st.form("report_upload_form", clear_on_submit=False):
        form_left, form_right = st.columns((1.2, 1))
        with form_left:
            uploaded_file = st.file_uploader(
                "JSON 리포트 업로드",
                type=["json"],
                help="Detect Bot 결과 JSON 파일을 업로드합니다.",
            )
            original_path = st.text_input(
                "원본 JSON 리포트 경로",
                placeholder="/var/reports/report.json",
                help="수집 서버나 배치 경로를 남겨두면 나중에 원본 추적이 쉬워집니다.",
            )
            uploaded_by = st.text_input(
                "등록자",
                value="portal-admin",
                help="누가 이 리포트를 포털에 등록했는지 남깁니다.",
            )

        with form_right:
            server_options = ["AUTO"]
            if servers_df is not None and not servers_df.empty:
                server_options.extend(servers_df["id"].tolist())
            selected_server_id = st.selectbox(
                "대상 서버",
                options=server_options,
                format_func=lambda value: (
                    "AUTO - 리포트 host 기준 자동 연결/등록"
                    if value == "AUTO"
                    else _server_label(servers_df, value)
                ),
                help="AUTO를 선택하면 리포트의 host 값을 기준으로 기존 서버를 찾고, 없으면 자동 등록할 수 있습니다.",
            )

            policy_options = [""]
            if policies_df is not None and not policies_df.empty:
                policy_options.extend(policies_df["id"].tolist())
            selected_policy_id = st.selectbox(
                "정책",
                options=policy_options,
                format_func=lambda value: _policy_label(policies_df, value),
                help="리포트 생성에 사용한 정책을 알고 있다면 함께 연결해 두는 것을 권장합니다.",
            )

            input_type_options = [
                "",
                "manual_json",
                "nginx_dump",
                "apache_dump",
                "watch_dir",
                "kafka_event",
                "unknown",
            ]
            input_type = st.selectbox(
                "입력 유형",
                options=input_type_options,
                format_func=lambda value: "리포트에서 자동 추론" if not value else input_type_badge_text(value),
                help="리포트 수집 경로를 명시하면 실행 이력 필터링과 운영 분석이 쉬워집니다.",
            )
            auto_create_server = st.checkbox(
                "미등록 서버 자동 등록 허용",
                value=True,
                help="리포트 host가 포털 서버 자산에 없을 때 새 자산으로 자동 생성합니다.",
            )

        submitted = st.form_submit_button("리포트 적재", width="stretch")
        if submitted:
            if uploaded_file is None:
                st.error("업로드할 JSON 파일을 먼저 선택해 주세요.")
            else:
                result = ingest_report(
                    uploaded_file.getvalue(),
                    uploaded_file.name,
                    server_id=None if selected_server_id == "AUTO" else selected_server_id,
                    policy_id=selected_policy_id or None,
                    input_type=input_type or None,
                    uploaded_by=uploaded_by,
                    original_path=original_path,
                    auto_create_server=auto_create_server,
                )
                server_name = _server_label(servers_df, result["server_id"])
                st.session_state["scan_results_last_ingest"] = {
                    **result,
                    "server_name": server_name,
                }
                st.session_state["scan_results_selected_run_id"] = result["scan_run_id"]
                st.rerun()

with tab_history:
    st.markdown("### 실행 이력 조회")
    st.caption("최근 실행, 탐지 건수가 많은 실행, 특정 서버나 정책 기준의 실행을 빠르게 좁혀서 확인할 수 있습니다.")

    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    with filter_col1:
        st.selectbox(
            "서버",
            options=[""] + (servers_df["id"].tolist() if servers_df is not None and not servers_df.empty else []),
            format_func=lambda value: _server_label(servers_df, value),
            key="scan_results_server_filter",
        )
    with filter_col2:
        st.selectbox(
            "정책",
            options=[""] + (policies_df["id"].tolist() if policies_df is not None and not policies_df.empty else []),
            format_func=lambda value: _policy_label(policies_df, value),
            key="scan_results_policy_filter",
        )
    with filter_col3:
        st.selectbox(
            "입력 유형",
            options=["", "manual_json", "nginx_dump", "apache_dump", "watch_dir", "kafka_event", "unknown"],
            format_func=lambda value: "전체 입력 유형" if not value else input_type_badge_text(value),
            key="scan_results_input_type_filter",
        )
    with filter_col4:
        st.selectbox(
            "최근 기간",
            options=[7, 30, 90, 180, 0],
            format_func=lambda value: "전체 기간" if value == 0 else f"최근 {value}일",
            key="scan_results_recent_days",
        )

    st.text_input(
        "호스트 검색",
        key="scan_results_host_keyword",
        placeholder="hostname, primary IP, os_type, 서버명",
    )

    toggle_col1, toggle_col2, toggle_col3 = st.columns((1, 1, 1.2))
    with toggle_col1:
        st.checkbox("최신 실행만 보기", key="scan_results_latest_only")
    with toggle_col2:
        st.checkbox("탐지 0건 제외", key="scan_results_findings_only")
    with toggle_col3:
        if st.button("필터 초기화", width="stretch"):
            _reset_history_filters()
            st.rerun()

    filtered_runs_df = _filter_runs(prepared_runs_df)
    render_metric_summary(_summary_metrics(filtered_runs_df))

    if filtered_runs_df is None or filtered_runs_df.empty:
        st.info("조건에 맞는 실행 이력이 없습니다. 필터를 완화하거나 새 리포트를 적재해 주세요.")
    else:
        selected_run_id = st.session_state.get("scan_results_selected_run_id")
        if selected_run_id not in filtered_runs_df["id"].tolist():
            selected_run_id = filtered_runs_df.iloc[0]["id"]
            st.session_state["scan_results_selected_run_id"] = selected_run_id

        new_selected_run_id = render_run_selection_cards(
            filtered_runs_df,
            selected_run_id,
            key_prefix="scan-results-run",
        )
        if new_selected_run_id != selected_run_id:
            st.session_state["scan_results_selected_run_id"] = new_selected_run_id
            st.rerun()

        with st.expander("다른 실행 선택", expanded=False):
            chosen_run_id = st.selectbox(
                "실행 선택",
                options=filtered_runs_df["id"].tolist(),
                index=filtered_runs_df["id"].tolist().index(st.session_state["scan_results_selected_run_id"]),
                format_func=lambda value: (
                    f"{filtered_runs_df.loc[filtered_runs_df['id'] == value, 'server_name'].iloc[0]} / "
                    f"{filtered_runs_df.loc[filtered_runs_df['id'] == value, 'host_hostname'].iloc[0] or filtered_runs_df.loc[filtered_runs_df['id'] == value, 'hostname'].iloc[0] or '-'} / "
                    f"{filtered_runs_df.loc[filtered_runs_df['id'] == value, 'host_primary_ip'].iloc[0] or filtered_runs_df.loc[filtered_runs_df['id'] == value, 'ip_address'].iloc[0] or '-'} / "
                    f"{filtered_runs_df.loc[filtered_runs_df['id'] == value, 'generated_at'].iloc[0] or filtered_runs_df.loc[filtered_runs_df['id'] == value, 'scan_started_at'].iloc[0]}"
                ),
                key="scan_results_run_picker",
            )
            if chosen_run_id != st.session_state["scan_results_selected_run_id"]:
                st.session_state["scan_results_selected_run_id"] = chosen_run_id
                st.rerun()

        st.markdown("### 실행 이력 목록")
        display_runs_df = build_scan_run_display_df(filtered_runs_df.head(100))
        dataframe_or_info(
            style_scan_run_table(display_runs_df),
            "표시할 실행 이력이 없습니다.",
        )

        detail = get_scan_run_detail(st.session_state["scan_results_selected_run_id"])
        if not detail:
            st.warning("선택한 실행의 상세 정보를 찾지 못했습니다.")
        else:
            run = detail["run"]
            run["scan_started_at"] = _format_dt(run.get("scan_started_at"))
            run["generated_at"] = _format_dt(run.get("generated_at"))

            st.markdown("### 실행 상세")
            render_scan_run_overview(run)
            if st.button("상세 리포트 해석 보기", key="open_detection_report_viewer_from_scan_results", width="stretch"):
                _open_detection_report_viewer(run.get("server_id") or "", run.get("id") or "")

            severity_df = detail["severity_counts"]
            if severity_df is not None and not severity_df.empty:
                severity_df = severity_df.rename(columns={"severity": "위험도", "count": "건수"})

            reasons_df = _format_count_table(detail["reason_counts"], "reason_code")
            patterns_df = _format_count_table(detail["pattern_counts"], "pattern_code")
            roots_df = _format_roots_table(detail["roots"])

            top_left, top_right = st.columns((1, 1))
            with top_left:
                st.markdown("#### 위험도 분포")
                dataframe_or_info(severity_df, "이 실행에는 위험도 집계가 없습니다.")
                if severity_df is not None and not severity_df.empty:
                    st.bar_chart(severity_df.set_index("위험도")["건수"])
            with top_right:
                st.markdown("#### 점검 루트")
                dataframe_or_info(roots_df, "등록된 점검 루트가 없습니다.")

            lower_left, lower_right = st.columns((1, 1))
            with lower_left:
                st.markdown("#### 탐지사유 Top")
                dataframe_or_info(reasons_df, "탐지사유 집계가 없습니다.")
            with lower_right:
                st.markdown("#### 패턴 Top")
                dataframe_or_info(patterns_df, "패턴 집계가 없습니다.")

            with st.expander("저장된 옵션 설정", expanded=False):
                if run.get("config_json"):
                    st.code(json_text_to_lines(run["config_json"]), language="json")
                else:
                    st.info("저장된 옵션 설정이 없습니다.")

            with st.expander("원본 실행 메타데이터", expanded=False):
                st.json(run, expanded=False)
