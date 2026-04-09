import pandas as pd
import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.models import CRITICALITIES, ENVIRONMENTS, OS_TYPES, WEB_SERVER_TYPES, ZONES
from lib.ui import (
    build_scan_run_display_df as _build_scan_run_display_df,
    build_server_inventory_display_df as _build_server_inventory_display_df,
    format_timestamp_columns,
    inject_portal_css,
    render_portal_header,
    render_selected_server_banner,
    render_selected_server_focus_card,
)
from services.scan_service import ScanService
from services.server_service import ServerService


st.set_page_config(page_title="DetectBot 포털 - 서버 인벤토리", page_icon="SV", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
inject_portal_css()
render_portal_sidebar(settings)

server_service = ServerService()
scan_service = ScanService()


def reset_filters():
    st.session_state["inventory_keyword"] = ""
    st.session_state["inventory_environment"] = "all"
    st.session_state["inventory_zone"] = "all"
    st.session_state["inventory_selected_server_id"] = ""


def load_servers_df():
    environment = "" if st.session_state.get("inventory_environment", "all") == "all" else st.session_state["inventory_environment"]
    zone = "" if st.session_state.get("inventory_zone", "all") == "all" else st.session_state["inventory_zone"]
    servers_df = format_timestamp_columns(
        server_service.list_servers_df(
            keyword=st.session_state.get("inventory_keyword", ""),
            environment=environment,
            zone=zone,
            active_only=False,
        ),
        ["created_at", "updated_at"],
    )
    if servers_df is None or servers_df.empty:
        return servers_df
    sort_columns = [column for column in ["updated_at", "server_name"] if column in servers_df.columns]
    ascending = [False, True][: len(sort_columns)]
    return servers_df.sort_values(by=sort_columns, ascending=ascending, na_position="last").reset_index(drop=True)


def selected_server(servers_df: pd.DataFrame):
    selected_id = st.session_state.get("inventory_selected_server_id", "")
    if selected_id and servers_df is not None and not servers_df.empty and selected_id in servers_df["id"].astype(str).tolist():
        return server_service.get_server(selected_id)
    if servers_df is None or servers_df.empty:
        st.session_state["inventory_selected_server_id"] = ""
        return None
    selected_id = str(servers_df.iloc[0]["id"])
    st.session_state["inventory_selected_server_id"] = selected_id
    return server_service.get_server(selected_id)


def sync_selected_server_from_table(selection, servers_df: pd.DataFrame):
    if servers_df is None or servers_df.empty:
        return

    selected_rows = []
    try:
        selected_rows = selection.selection.rows
    except Exception:
        selected_rows = []

    if not selected_rows:
        return

    next_selected_id = str(servers_df.iloc[selected_rows[0]]["id"])
    current_selected_id = st.session_state.get("inventory_selected_server_id", "")
    if next_selected_id != current_selected_id:
        st.session_state["inventory_selected_server_id"] = next_selected_id
        st.rerun()


def build_server_inventory_display_df(df: pd.DataFrame):
    display = _build_server_inventory_display_df(df)
    if display is None or display.empty:
        return display

    return display.rename(
        columns={
            "Server Name": "서버명",
            "Environment": "운영구분",
            "Criticality": "중요도",
            "Status": "상태",
            "Upload": "업로드",
            "Service": "서비스",
            "Owner": "담당",
            "Last Updated": "최근 수정",
        }
    )


def build_scan_run_display_df(df: pd.DataFrame):
    display = _build_scan_run_display_df(df)
    if display is None or display.empty:
        return display

    return display.rename(
        columns={
            "Latest": "최신",
            "Server Name": "서버명",
            "Input Type": "입력 유형",
            "Policy": "정책",
            "Findings": "탐지 건수",
            "Roots": "점검 루트",
            "Scanned Files": "스캔 파일",
            "Run Time": "실행 시각",
            "Report File": "리포트 파일",
        }
    )


render_portal_header(
    "서버 인벤토리",
    "등록된 서버를 조회하고, 선택한 서버의 상세 정보와 최근 이력을 확인하거나 수정할 수 있습니다.",
)

for key, value in {
    "inventory_keyword": "",
    "inventory_environment": "all",
    "inventory_zone": "all",
    "inventory_selected_server_id": "",
}.items():
    st.session_state.setdefault(key, value)

servers_df = load_servers_df()
selected = selected_server(servers_df)

render_selected_server_banner(selected, context_label="현재 선택된 서버")

guide_col, action_col = st.columns((1.8, 1))
with guide_col:
    if selected:
        st.info("목록에서 서버를 선택한 뒤, 상세 정보 확인, 수정/삭제, Findings 이동 작업을 이어서 진행할 수 있습니다.")
    else:
        st.info("먼저 서버 목록에서 대상을 선택해 주세요. 선택 후 상세 확인, 수정/삭제, Findings 이동이 가능합니다.")
with action_col:
    if st.button("선택한 서버의 Findings 보기", width="stretch", disabled=not selected):
        st.session_state["findings_focus_server_id"] = selected["id"]
        st.switch_page("pages/03_findings.py")

filter_cols = st.columns((1.8, 1, 1, 1))
with filter_cols[0]:
    st.text_input("서버 검색", key="inventory_keyword", placeholder="서버명, 호스트명, IP, 서비스명으로 검색")
with filter_cols[1]:
    st.selectbox("운영 구분 필터", options=["all"] + ENVIRONMENTS, key="inventory_environment")
with filter_cols[2]:
    st.selectbox("Zone 필터", options=["all"] + ZONES, key="inventory_zone")
with filter_cols[3]:
    if st.button("검색/필터 초기화", width="stretch"):
        reset_filters()
        st.rerun()

recent_runs_df = pd.DataFrame()
if selected:
    recent_runs_df = format_timestamp_columns(
        scan_service.list_scan_runs_df(server_id=selected["id"], limit=5),
        ["scan_started_at", "generated_at"],
    )

tab_list, tab_detail, tab_create, tab_edit = st.tabs(["목록", "상세", "등록", "수정/삭제"])

with tab_list:
    st.markdown("### 서버 목록")
    st.caption("목록에서 서버 한 대를 선택하면 아래의 상세 보기와 수정/삭제 작업을 바로 진행할 수 있습니다.")
    st.caption("Tip: click anywhere on a row to change the selected server.")
    display_df = build_server_inventory_display_df(servers_df)
    if display_df is None or display_df.empty:
        st.info("현재 검색 조건에 맞는 서버가 없습니다. 검색 조건을 초기화하거나 새 서버를 등록해 보세요.")
    else:
        preferred_indexes = [0, 1, 2, 10, 5, 6, 7, 8, 9, 3, 4, 11, 12]
        preferred_columns = [
            display_df.columns[index]
            for index in preferred_indexes
            if index < len(display_df.columns)
        ]
        display_df = display_df.loc[:, preferred_columns]
        selection = st.dataframe(
            display_df,
            width="stretch",
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
        )
        sync_selected_server_from_table(selection, servers_df)
        if selected:
            st.caption(f"Selected server: {selected.get('server_name', '-')}")

with tab_detail:
    st.markdown("### 선택 서버 상세")
    if not selected:
        st.info("목록 탭에서 서버를 선택하면 이곳에서 상세 정보와 최근 스캔 이력을 확인할 수 있습니다.")
    else:
        render_selected_server_focus_card(selected, mode="view")
        st.caption("수정 또는 Findings 이동 전에, 현재 선택한 서버가 맞는지 이 탭에서 먼저 확인해 주세요.")
        st.json(selected, expanded=False)
        st.markdown("### 최근 스캔 이력")
        if recent_runs_df is None or recent_runs_df.empty:
            st.info("이 서버에는 아직 스캔 이력이 없습니다.")
        else:
            st.dataframe(build_scan_run_display_df(recent_runs_df), width="stretch", hide_index=True)
            if st.button("Findings 열기", width="stretch"):
                st.session_state["findings_focus_server_id"] = selected["id"]
                st.switch_page("pages/03_findings.py")


def render_server_form(editing_server=None, form_key="server_form"):
    with st.form(form_key):
        server_name = st.text_input("서버명", value=(editing_server or {}).get("server_name", ""))
        hostname = st.text_input("호스트명", value=(editing_server or {}).get("hostname", ""))
        ip_address = st.text_input("IP 주소", value=(editing_server or {}).get("ip_address", ""))
        service_name = st.text_input("서비스명", value=(editing_server or {}).get("service_name", ""))
        owner_name = st.text_input("담당자", value=(editing_server or {}).get("owner_name", ""))
        environment = st.selectbox(
            "운영 구분",
            ENVIRONMENTS,
            index=ENVIRONMENTS.index((editing_server or {}).get("environment", "unknown")),
        )
        zone = st.selectbox(
            "Zone",
            ZONES,
            index=ZONES.index((editing_server or {}).get("zone", "unknown")),
        )
        os_type = st.selectbox(
            "OS 유형",
            OS_TYPES,
            index=OS_TYPES.index((editing_server or {}).get("os_type", "unknown")),
        )
        os_name = st.text_input("OS 이름", value=(editing_server or {}).get("os_name", ""))
        os_version = st.text_input("OS 버전", value=(editing_server or {}).get("os_version", ""))
        platform = st.text_input("플랫폼", value=(editing_server or {}).get("platform", ""))
        web_server_type = st.selectbox(
            "웹서버",
            WEB_SERVER_TYPES,
            index=WEB_SERVER_TYPES.index((editing_server or {}).get("web_server_type", "unknown")),
        )
        criticality = st.selectbox(
            "중요도",
            CRITICALITIES,
            index=CRITICALITIES.index((editing_server or {}).get("criticality", "medium")),
        )
        upload_enabled = st.checkbox("업로드 허용", value=bool((editing_server or {}).get("upload_enabled", True)))
        is_active = st.checkbox("사용 중", value=bool((editing_server or {}).get("is_active", True)))
        notes = st.text_area("비고", value=(editing_server or {}).get("notes", ""), height=100)
        submitted = st.form_submit_button("서버 저장", width="stretch")
        if submitted:
            if not server_name.strip():
                st.error("서버명은 필수입니다.")
                return
            server_id = server_service.save_server(
                {
                    "id": (editing_server or {}).get("id"),
                    "server_name": server_name,
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "environment": environment,
                    "zone": zone,
                    "os_type": os_type,
                    "os_name": os_name,
                    "os_version": os_version,
                    "platform": platform,
                    "web_server_type": web_server_type,
                    "service_name": service_name,
                    "criticality": criticality,
                    "owner_name": owner_name,
                    "upload_enabled": upload_enabled,
                    "is_active": is_active,
                    "notes": notes,
                }
            )
            st.session_state["inventory_selected_server_id"] = server_id
            st.success(f"서버를 저장했습니다: {server_name}")
            st.rerun()


with tab_create:
    st.markdown("### 서버 등록")
    st.caption("새 서버를 등록하면 인벤토리에 표시되고, 이후 스캔 및 Findings 흐름에서 사용할 수 있습니다.")
    render_server_form()

with tab_edit:
    st.markdown("### 수정 / 삭제")
    if not selected:
        st.info("먼저 목록 탭에서 서버를 선택해 주세요. 선택한 서버가 이 영역에 표시되며 수정 또는 삭제할 수 있습니다.")
    else:
        render_selected_server_focus_card(selected, mode="edit")
        st.caption("아래 폼은 현재 선택된 서버를 수정하는 영역입니다. 저장 또는 삭제 전에 선택 서버를 다시 확인해 주세요.")
        render_server_form(editing_server=selected, form_key="edit_server_form")
        if st.button("선택한 서버 삭제", type="secondary", width="stretch"):
            server_service.delete_server(selected["id"])
            st.session_state["inventory_selected_server_id"] = ""
            st.success("서버를 삭제했습니다.")
            st.rerun()
