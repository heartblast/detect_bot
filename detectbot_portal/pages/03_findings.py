from collections import Counter

import pandas as pd
import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.time_utils import format_display_datetime
from lib.ui import dataframe_or_info, format_timestamp_columns, render_portal_header
from services.scan_service import ScanService
from services.server_service import ServerService


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
    "": 5,
}

SEVERITY_LABELS = {
    "critical": "심각",
    "high": "높음",
    "medium": "보통",
    "low": "낮음",
    "unknown": "미분류",
    "": "-",
}


st.set_page_config(page_title="DetectBot 포털 - Findings", page_icon="FD", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
render_portal_sidebar(settings)

server_service = ServerService()
scan_service = ScanService()


def normalize_server_options(servers_df: pd.DataFrame):
    if servers_df is None or servers_df.empty:
        return [""], {}

    options = [""]
    server_map = {}
    for _, row in servers_df.iterrows():
        server_id = str(row.get("id") or "").strip()
        if not server_id:
            continue
        options.append(server_id)
        server_map[server_id] = {
            "server_name": row.get("server_name") or server_id,
            "hostname": row.get("hostname") or "",
            "ip_address": row.get("ip_address") or "",
        }
    return options, server_map


def server_label(server_map: dict, server_id: str) -> str:
    if not server_id:
        return "전체 서버"
    server = server_map.get(str(server_id).strip())
    return server["server_name"] if server else str(server_id)


def normalize_scan_runs_df(df: pd.DataFrame | None) -> pd.DataFrame | None:
    if df is None or df.empty:
        return df

    normalized = df.copy()
    normalized["id"] = normalized["id"].astype(str)
    normalized["server_id"] = normalized["server_id"].fillna("").astype(str)
    normalized["server_name"] = normalized["server_name"].fillna("미연결 서버")
    normalized["input_type"] = normalized["input_type"].fillna("")
    normalized["file_name"] = normalized["file_name"].fillna("")
    normalized["findings_count"] = normalized["findings_count"].fillna(0).astype(int)
    normalized["generated_at"] = normalized["generated_at"].fillna("")
    normalized["scan_started_at"] = normalized["scan_started_at"].fillna("")
    return normalized.sort_values(
        by=["generated_at", "scan_started_at"],
        ascending=[False, False],
        na_position="last",
    ).reset_index(drop=True)


def build_scan_run_options(df: pd.DataFrame | None):
    if df is None or df.empty:
        return [""], {}

    options = [""]
    run_map = {}
    for _, row in df.iterrows():
        run_id = str(row["id"]).strip()
        if not run_id:
            continue
        options.append(run_id)
        run_map[run_id] = {
            "generated_at": row.get("generated_at") or row.get("scan_started_at") or "-",
            "server_name": row.get("server_name") or "미연결 서버",
            "findings_count": int(row.get("findings_count") or 0),
            "input_type": row.get("input_type") or "-",
        }
    return options, run_map


def run_label(run_map: dict, run_id: str) -> str:
    if not run_id:
        return "탐지이력을 선택해 주세요"
    run_info = run_map.get(str(run_id).strip())
    if not run_info:
        return str(run_id)
    return (
        f"{run_info['generated_at']} / "
        f"탐지 {run_info['findings_count']}건 / "
        f"{run_info['input_type']}"
    )


def normalize_findings_df(df: pd.DataFrame | None) -> pd.DataFrame | None:
    if df is None or df.empty:
        return df

    normalized = df.copy()
    defaults = {
        "id": "",
        "scan_run_id": "",
        "server_name": "",
        "hostname": "",
        "severity": "",
        "path": "",
        "real_path": "",
        "ext": "",
        "mime_sniff": "",
        "reason_codes": "",
        "reason_meanings": "",
        "pattern_codes": "",
        "pattern_meanings": "",
        "generated_at": "",
        "mod_time": "",
    }
    for column, default_value in defaults.items():
        if column not in normalized.columns:
            normalized[column] = default_value

    normalized["id"] = normalized["id"].astype(str)
    normalized["scan_run_id"] = normalized["scan_run_id"].astype(str)
    normalized["severity"] = normalized["severity"].fillna("").astype(str).str.lower()
    normalized["severity_label"] = normalized["severity"].map(SEVERITY_LABELS).fillna("미분류")
    normalized["server_name"] = normalized["server_name"].fillna("").replace("", "미연결 서버")
    normalized["hostname"] = normalized["hostname"].fillna("")
    normalized["path"] = normalized["path"].fillna("")
    normalized["real_path"] = normalized["real_path"].fillna("")
    normalized["ext"] = normalized["ext"].fillna("")
    normalized["mime_sniff"] = normalized["mime_sniff"].fillna("")
    normalized["reason_codes"] = normalized["reason_codes"].fillna("")
    normalized["reason_meanings"] = normalized["reason_meanings"].fillna("")
    normalized["pattern_codes"] = normalized["pattern_codes"].fillna("")
    normalized["pattern_meanings"] = normalized["pattern_meanings"].fillna("")
    normalized["generated_at"] = normalized["generated_at"].fillna("")
    normalized["mod_time"] = normalized["mod_time"].fillna("")
    normalized["severity_sort"] = normalized["severity"].map(SEVERITY_ORDER).fillna(9)
    return normalized.sort_values(
        by=["severity_sort", "generated_at", "path"],
        ascending=[True, False, True],
        na_position="last",
    ).reset_index(drop=True)


def option_values_from_csv(series: pd.Series) -> list[str]:
    values = set()
    for value in series.fillna(""):
        for item in str(value).split(","):
            cleaned = item.strip()
            if cleaned:
                values.add(cleaned)
    return sorted(values)


def apply_secondary_filters(
    df: pd.DataFrame | None,
    path_keyword: str,
    severity: str,
    reason_code: str,
    pattern_code: str,
) -> pd.DataFrame | None:
    if df is None or df.empty:
        return df

    filtered = df.copy()
    if path_keyword.strip():
        keyword = path_keyword.strip().lower()
        filtered = filtered[
            filtered["path"].str.lower().str.contains(keyword, na=False)
            | filtered["real_path"].str.lower().str.contains(keyword, na=False)
        ]
    if severity:
        filtered = filtered[filtered["severity"] == severity]
    if reason_code:
        filtered = filtered[
            filtered["reason_codes"].str.contains(reason_code, case=False, na=False)
            | filtered["reason_meanings"].str.contains(reason_code, case=False, na=False)
        ]
    if pattern_code:
        filtered = filtered[
            filtered["pattern_codes"].str.contains(pattern_code, case=False, na=False)
            | filtered["pattern_meanings"].str.contains(pattern_code, case=False, na=False)
        ]
    return filtered.reset_index(drop=True)


def build_findings_display_df(df: pd.DataFrame | None) -> pd.DataFrame | None:
    if df is None or df.empty:
        return df

    display = df.copy()
    display["서버명"] = display["server_name"]
    display["탐지이력 시각"] = display["generated_at"]
    display["경로"] = display["path"]
    display["위험도"] = display["severity_label"]
    display["사유"] = display["reason_meanings"].where(display["reason_meanings"] != "", display["reason_codes"])
    display["패턴"] = display["pattern_meanings"].where(display["pattern_meanings"] != "", display["pattern_codes"])
    return display[["서버명", "탐지이력 시각", "경로", "위험도", "사유", "패턴"]]


def summarize_findings(df: pd.DataFrame | None) -> dict:
    if df is None or df.empty:
        return {"total": 0, "top_severity": "-", "top_reason": "-", "top_pattern": "-"}

    severity_counts = df["severity_label"].value_counts()
    reason_counter = Counter()
    pattern_counter = Counter()
    for value in df["reason_meanings"].where(df["reason_meanings"] != "", df["reason_codes"]):
        reason_counter.update([item.strip() for item in str(value).split(",") if item.strip()])
    for value in df["pattern_meanings"].where(df["pattern_meanings"] != "", df["pattern_codes"]):
        pattern_counter.update([item.strip() for item in str(value).split(",") if item.strip()])

    return {
        "total": len(df),
        "top_severity": severity_counts.index[0] if not severity_counts.empty else "-",
        "top_reason": reason_counter.most_common(1)[0][0] if reason_counter else "-",
        "top_pattern": pattern_counter.most_common(1)[0][0] if pattern_counter else "-",
    }


def render_selected_finding_summary(detail: dict) -> None:
    st.markdown("### 선택한 탐지 결과")
    cols = st.columns(4)
    cols[0].metric("위험도", SEVERITY_LABELS.get((detail.get("severity") or "").lower(), detail.get("severity") or "-"))
    cols[1].metric("서버", detail.get("server_name") or "미연결 서버")
    cols[2].metric("호스트명", detail.get("hostname") or "-")
    cols[3].metric("확장자", detail.get("ext") or "-")
    st.write(f"**경로**: {detail.get('path') or '-'}")
    st.write(f"**실제 경로**: {detail.get('real_path') or '-'}")
    st.write(f"**사유**: {detail.get('reason_meanings') or detail.get('reason_codes') or '-'}")
    st.write(f"**패턴**: {detail.get('pattern_meanings') or detail.get('pattern_codes') or '-'}")
    st.write(f"**탐지이력 시각**: {format_display_datetime(detail.get('generated_at'))}")
    st.write(f"**수정 시각**: {format_display_datetime(detail.get('mod_time'))}")


render_portal_header(
    "Findings",
    "서버와 탐지이력을 먼저 선택하고, 그 결과 안에서 경로·위험도·사유·패턴으로 추가 필터링해 상세 내용을 확인합니다.",
)

servers_df = server_service.list_servers_df(active_only=False)
focus_server_id = str(st.session_state.pop("findings_focus_server_id", "") or "").strip()
server_options, server_map = normalize_server_options(servers_df)
default_server_id = focus_server_id if focus_server_id and focus_server_id in server_map else ""

if focus_server_id and default_server_id:
    st.info(f"서버 인벤토리에서 선택한 서버 기준으로 Findings를 열었습니다: {server_label(server_map, default_server_id)}")
else:
    st.info("서버를 먼저 선택하고, 그 다음 탐지이력을 선택하면 해당 실행의 탐지 결과를 상세히 확인할 수 있습니다.")

primary_cols = st.columns(2)
with primary_cols[0]:
    server_id = st.selectbox(
        "서버",
        options=server_options,
        index=server_options.index(default_server_id) if default_server_id in server_options else 0,
        format_func=lambda value: server_label(server_map, value),
    )

run_source_df = normalize_scan_runs_df(
    format_timestamp_columns(
        scan_service.list_scan_runs_df(server_id=server_id, limit=200) if server_id else None,
        ["scan_started_at", "generated_at", "uploaded_at", "created_at"],
    )
)
run_options, run_map = build_scan_run_options(run_source_df)

with primary_cols[1]:
    selected_run_id = st.selectbox(
        "탐지이력",
        options=run_options,
        format_func=lambda value: run_label(run_map, value),
        help="선택한 서버의 실제 탐지이력만 표시합니다.",
    )

if not server_id:
    st.info("먼저 서버를 선택해 주세요.")
    st.stop()

if not selected_run_id:
    if run_source_df is None or run_source_df.empty:
        st.info("선택한 서버에 등록된 탐지이력이 없습니다.")
    else:
        st.info("선택한 서버의 탐지이력 중 하나를 선택하면 탐지 결과와 상세 정보를 확인할 수 있습니다.")
    st.stop()

run_detail = scan_service.get_scan_run_detail(selected_run_id)
base_findings_df = normalize_findings_df(
    format_timestamp_columns(
        run_detail["findings"] if run_detail else None,
        ["generated_at", "mod_time", "created_at"],
    )
)

st.caption(
    f"서버: {server_label(server_map, server_id)} / "
    f"탐지이력: {run_label(run_map, selected_run_id)}"
)

available_reasons = option_values_from_csv(
    base_findings_df["reason_codes"].where(base_findings_df["reason_codes"] != "", base_findings_df["reason_meanings"])
) if base_findings_df is not None and not base_findings_df.empty else []
available_patterns = option_values_from_csv(
    base_findings_df["pattern_codes"].where(base_findings_df["pattern_codes"] != "", base_findings_df["pattern_meanings"])
) if base_findings_df is not None and not base_findings_df.empty else []

secondary_cols = st.columns(4)
with secondary_cols[0]:
    path_keyword = st.text_input("경로 필터", placeholder="/var/www 또는 .env")
with secondary_cols[1]:
    severity = st.selectbox(
        "위험도 필터",
        ["", "critical", "high", "medium", "low", "unknown"],
        format_func=lambda value: SEVERITY_LABELS.get(value, "전체") if value else "전체",
    )
with secondary_cols[2]:
    reason_code = st.selectbox("사유 필터", options=[""] + available_reasons, format_func=lambda value: value or "전체")
with secondary_cols[3]:
    pattern_code = st.selectbox("패턴 필터", options=[""] + available_patterns, format_func=lambda value: value or "전체")

findings_df = apply_secondary_filters(
    base_findings_df,
    path_keyword=path_keyword,
    severity=severity,
    reason_code=reason_code,
    pattern_code=pattern_code,
)

display_df = build_findings_display_df(findings_df)
summary = summarize_findings(findings_df)

summary_cols = st.columns(4)
summary_cols[0].metric("현재 조회 건수", summary["total"])
summary_cols[1].metric("가장 높은 위험도", summary["top_severity"])
summary_cols[2].metric("가장 많은 사유", summary["top_reason"])
summary_cols[3].metric("가장 많은 패턴", summary["top_pattern"])

st.markdown("### 탐지 결과 목록")
st.caption("서버와 탐지이력을 먼저 확정한 뒤, 그 범위 안에서 경로·위험도·사유·패턴으로 추가 필터링한 결과입니다. UUID 형태의 id는 화면에 표시하지 않습니다.")
dataframe_or_info(display_df, "현재 조건에 맞는 탐지 결과가 없습니다.")

selected_finding_id = ""
if findings_df is not None and not findings_df.empty:
    selected_finding_id = st.selectbox(
        "상세 확인 대상",
        options=findings_df["id"].tolist(),
        format_func=lambda value: (
            f"[{findings_df.loc[findings_df['id'] == value, 'severity_label'].iloc[0]}] "
            f"{findings_df.loc[findings_df['id'] == value, 'path'].iloc[0]}"
        ),
    )

if selected_finding_id:
    detail = scan_service.get_finding_detail(selected_finding_id)
    if detail:
        render_selected_finding_summary(detail)
        with st.expander("원본 상세 정보 보기", expanded=False):
            st.json(detail, expanded=False)
