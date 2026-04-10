from __future__ import annotations

import pandas as pd
import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.ui import (
    dataframe_or_info,
    format_timestamp_columns,
    render_metric_cards,
    render_portal_header,
)
from services.dashboard_service import DashboardService

try:
    import plotly.express as px
    import plotly.graph_objects as go

    PLOTLY_AVAILABLE = True
except Exception:
    px = None
    go = None
    PLOTLY_AVAILABLE = False


st.set_page_config(page_title="DetectBot 포털", page_icon="DB", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
dashboard_service = DashboardService()


def build_home_recent_runs_display_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df

    display = df.copy()
    display["서버"] = display["server_name"].fillna("")
    display["호스트명"] = display["host_hostname"].fillna(display.get("hostname", "")).fillna("")
    display["IP"] = display["host_primary_ip"].fillna(display.get("ip_address", "")).fillna("")
    display["입력 유형"] = display["input_type"].fillna("")
    display["정책"] = display["policy_name"].fillna("")
    display["탐지 건수"] = display["findings_count"].fillna(0).astype(int)
    display["실행 시각"] = display["generated_at"].fillna(display.get("scan_started_at", "")).fillna("")
    display["리포트 파일"] = display["file_name"].fillna("")
    return display[
        [
            "서버",
            "호스트명",
            "IP",
            "입력 유형",
            "정책",
            "탐지 건수",
            "실행 시각",
            "리포트 파일",
        ]
    ]


def build_reason_display_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    display = df.copy()
    display["사유 코드"] = display["reason_code"]
    display["의미"] = display["meaning"]
    display["건수"] = display["count"]
    return display[["사유 코드", "의미", "건수"]]


def build_pattern_display_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    display = df.copy()
    display["패턴 코드"] = display["pattern_code"]
    display["의미"] = display["meaning"]
    display["건수"] = display["count"]
    return display[["패턴 코드", "의미", "건수"]]


def build_severity_df(metrics: dict) -> pd.DataFrame:
    severity = metrics.get("severity_counts", {}) or {}
    rows = []
    for level in ["critical", "high", "medium", "low"]:
        rows.append({"severity": level, "count": int(severity.get(level, 0))})
    return pd.DataFrame(rows)


def build_risk_score(metrics: dict) -> int:
    severity = metrics.get("severity_counts", {}) or {}
    weighted_score = (
        int(severity.get("critical", 0)) * 100
        + int(severity.get("high", 0)) * 70
        + int(severity.get("medium", 0)) * 35
        + int(severity.get("low", 0)) * 10
    )
    findings_total = max(int(metrics.get("findings_total", 0)), 1)
    normalized = int(weighted_score / findings_total)
    return max(0, min(normalized, 100))


def build_trend_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()
    trend = df.copy()
    trend["generated_at"] = pd.to_datetime(trend["generated_at"], errors="coerce", utc=True)
    trend = trend.dropna(subset=["generated_at"])
    if trend.empty:
        return pd.DataFrame()
    trend["day"] = trend["generated_at"].dt.strftime("%Y-%m-%d")
    grouped = (
        trend.groupby("day", as_index=False)
        .agg(findings=("findings_count", "sum"), runs=("id", "count"))
        .sort_values("day")
    )
    return grouped.tail(7)


def render_risk_gauge(score: int) -> None:
    if not PLOTLY_AVAILABLE:
        st.metric("전체 위험도", f"{score}/100")
        return

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100"},
            title={"text": "전체 위험도"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#b91c1c"},
                "steps": [
                    {"range": [0, 30], "color": "#dcfce7"},
                    {"range": [30, 55], "color": "#fef3c7"},
                    {"range": [55, 80], "color": "#fed7aa"},
                    {"range": [80, 100], "color": "#fecaca"},
                ],
            },
        )
    )
    fig.update_layout(height=260, margin=dict(l=10, r=10, t=50, b=10))
    st.plotly_chart(fig, width="stretch")


def render_severity_donut(severity_df: pd.DataFrame) -> None:
    non_zero = severity_df[severity_df["count"] > 0]
    if non_zero.empty:
        st.info("아직 심각도 분포 데이터가 없습니다.")
        return

    if not PLOTLY_AVAILABLE:
        st.dataframe(non_zero, hide_index=True, use_container_width=True)
        return

    fig = px.pie(
        non_zero,
        names="severity",
        values="count",
        hole=0.68,
        color="severity",
        color_discrete_map={
            "critical": "#b91c1c",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#16a34a",
        },
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    fig.update_layout(height=260, margin=dict(l=10, r=10, t=30, b=10), showlegend=False)
    st.plotly_chart(fig, width="stretch")


def render_findings_trend(trend_df: pd.DataFrame) -> None:
    if trend_df is None or trend_df.empty:
        st.info("아직 최근 탐지 추이 데이터가 없습니다.")
        return

    if not PLOTLY_AVAILABLE:
        st.line_chart(trend_df.set_index("day")["findings"])
        return

    fig = px.area(
        trend_df,
        x="day",
        y="findings",
        markers=True,
        color_discrete_sequence=["#0f766e"],
    )
    fig.update_layout(
        height=240,
        margin=dict(l=10, r=10, t=20, b=10),
        xaxis_title="",
        yaxis_title="탐지 건수",
    )
    fig.update_traces(line={"width": 3}, fillcolor="rgba(15, 118, 110, 0.18)")
    st.plotly_chart(fig, width="stretch")


def render_action_panel(metrics: dict, recent_runs_df: pd.DataFrame) -> None:
    severity = metrics.get("severity_counts", {}) or {}
    urgent_count = int(severity.get("critical", 0)) + int(severity.get("high", 0))
    findings_total = int(metrics.get("findings_total", 0))

    if recent_runs_df is None or recent_runs_df.empty:
        recent_bad_runs = 0
    else:
        recent_bad_runs = int((recent_runs_df["findings_count"].fillna(0) > 0).sum())

    if urgent_count > 0:
        st.error(f"즉시 점검 필요: {urgent_count}건")
        st.caption("Critical 또는 High 심각도의 탐지가 존재합니다. 최근 스캔 결과를 먼저 확인하세요.")
    else:
        st.success("긴급 점검 항목 없음")
        st.caption("현재 대시보드 요약 기준으로 Critical 또는 High 탐지가 없습니다.")

    col1, col2 = st.columns(2)
    col1.metric("탐지가 있는 최근 실행", recent_bad_runs)
    col2.metric("전체 탐지 건수", findings_total)

    if findings_total == 0:
        st.info("현재 추이는 안정적으로 보입니다.")
    elif urgent_count >= max(1, findings_total // 3):
        st.warning("탐지 건수 중 긴급 심각도 비중이 아직 높습니다.")
    else:
        st.info("탐지는 남아 있지만, 대부분은 긴급 구간 밖에 있습니다.")


def render_top_list(df: pd.DataFrame, code_col: str, meaning_col: str, title: str, empty_message: str) -> None:
    st.markdown(f"### {title}")
    if df is None or df.empty:
        st.info(empty_message)
        return

    for _, row in df.head(5).iterrows():
        code = str(row.get(code_col) or "-")
        meaning = str(row.get(meaning_col) or "")
        count = int(row.get("count") or 0)
        st.markdown(f"- `{code}`: {meaning} ({count})")


render_portal_sidebar(settings)

render_portal_header(
    "DetectBot 포털",
    "위험도 현황, 최근 스캔 활동, 우선 확인이 필요한 신호를 한눈에 볼 수 있는 홈 화면입니다.",
)

if settings.config_error:
    st.warning(f"설정 경고: {settings.config_error}")

st.info(
    "이 홈 화면은 빠른 상황 파악에 초점을 둡니다. 상세 분석은 각 세부 페이지에서 확인하세요."
)

metrics = dashboard_service.get_dashboard_metrics()
render_metric_cards(metrics)

recent_runs_raw_df = dashboard_service.recent_scan_runs_df(limit=20)
recent_runs_df = format_timestamp_columns(
    recent_runs_raw_df.copy() if recent_runs_raw_df is not None else recent_runs_raw_df,
    ["scan_started_at", "generated_at", "uploaded_at"],
)
reason_df = dashboard_service.top_reason_counts_df(limit=10)
pattern_df = dashboard_service.top_pattern_counts_df(limit=10)

recent_runs_display_df = build_home_recent_runs_display_df(recent_runs_df)
reason_display_df = build_reason_display_df(reason_df)
pattern_display_df = build_pattern_display_df(pattern_df)
severity_df = build_severity_df(metrics)
trend_df = build_trend_df(recent_runs_raw_df)
risk_score = build_risk_score(metrics)

top_left, top_mid, top_right = st.columns((1.15, 1, 0.95))

with top_left:
    st.markdown("### 보안 상태")
    render_risk_gauge(risk_score)

with top_mid:
    st.markdown("### 심각도 분포")
    render_severity_donut(severity_df)

with top_right:
    st.markdown("### 조치 우선순위")
    render_action_panel(metrics, recent_runs_raw_df)

trend_col, runs_col = st.columns((1.05, 1.2))
with trend_col:
    st.markdown("### 최근 탐지 추이")
    render_findings_trend(trend_df)

with runs_col:
    st.markdown("### 최근 스캔 실행")
    dataframe_or_info(recent_runs_display_df, "아직 최근 스캔 실행 이력이 없습니다.")

list_col1, list_col2 = st.columns(2)
with list_col1:
    render_top_list(
        reason_df,
        "reason_code",
        "meaning",
        "주요 사유 코드",
        "아직 사유 통계가 없습니다.",
    )
    with st.expander("사유 상세 보기"):
        dataframe_or_info(reason_display_df, "아직 사유 통계가 없습니다.")

with list_col2:
    render_top_list(
        pattern_df,
        "pattern_code",
        "meaning",
        "주요 패턴 코드",
        "아직 패턴 통계가 없습니다.",
    )
    with st.expander("패턴 상세 보기"):
        dataframe_or_info(pattern_display_df, "아직 패턴 통계가 없습니다.")
