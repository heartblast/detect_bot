import html
import json
from copy import deepcopy

import streamlit as st
import streamlit.components.v1 as components

try:
    import yaml
except Exception:
    yaml = None

from lib.config_builder import build_command, build_config_payload
from lib.scenario_builder import (
    INTENSITY_PROFILES,
    RECOMMENDED_PACKS,
    SCENARIOS,
    build_scenario_config,
    delete_preset,
    estimate_load,
    execution_checkpoints,
    load_saved_presets,
    parse_auto_extracted_paths,
    save_preset,
    summarize_rules,
    summarize_scope,
)
from lib.utils import non_empty_lines


ADVANCED_KEYS = [
    "newer_than_h",
    "max_depth",
    "workers",
    "max_size_mb",
    "follow_symlink",
    "hash_enabled",
    "allow_mime_prefixes",
    "allow_exts",
    "enable_rules",
    "disable_rules",
    "excludes",
    "content_scan",
    "content_max_bytes",
    "content_max_size_kb",
    "content_exts",
    "pii_scan",
    "pii_max_bytes",
    "pii_max_size_kb",
    "pii_max_matches",
    "pii_exts",
    "pii_mask",
    "pii_store_sample",
    "pii_context_keywords",
    "kafka_enabled",
    "kafka_brokers",
    "kafka_topic",
    "kafka_client_id",
    "kafka_tls",
    "kafka_sasl_enabled",
    "kafka_username",
    "kafka_password_env",
    "kafka_mask_sensitive",
]


def copy_button(label: str, value: str) -> None:
    escaped_label = html.escape(label)
    escaped_value = json.dumps(value)
    components.html(
        f"""
        <button
          style="width:100%;padding:0.55rem 0.8rem;border:1px solid #d0d7de;border-radius:0.5rem;background:#f8fafc;cursor:pointer;"
          onclick='navigator.clipboard.writeText({escaped_value}); this.innerText="Copied"; setTimeout(() => this.innerText="{escaped_label}", 1200);'>
          {escaped_label}
        </button>
        """,
        height=44,
    )


def sync_advanced_state(recommended_config: dict, signature: str) -> None:
    last_signature = st.session_state.get("wizard_signature")
    if last_signature == signature:
        return

    for field in ADVANCED_KEYS:
        state_key = f"wizard_adv_{field}"
        value = recommended_config.get(field)
        if isinstance(value, list):
            st.session_state[state_key] = "\n".join(value)
        else:
            st.session_state[state_key] = value

    st.session_state["wizard_signature"] = signature


def build_final_config(recommended_config: dict) -> dict:
    config = deepcopy(recommended_config)

    for field in ADVANCED_KEYS:
        state_key = f"wizard_adv_{field}"
        if field in {
            "allow_mime_prefixes",
            "allow_exts",
            "enable_rules",
            "disable_rules",
            "excludes",
            "content_exts",
            "pii_exts",
        }:
            config[field] = non_empty_lines(st.session_state.get(state_key, ""))
        else:
            config[field] = st.session_state.get(state_key, config.get(field))

    config["preset"] = "scenario_wizard"
    return config


def preset_payload() -> dict:
    keys = [
        "wizard_server_type",
        "wizard_nginx_mode",
        "wizard_nginx_dump_path",
        "wizard_apache_mode",
        "wizard_apache_dump_path",
        "wizard_extra_paths",
        "wizard_selected_scenarios",
        "wizard_intensity",
        "wizard_output_path",
        "wizard_selected_candidates",
    ]
    payload = {key: st.session_state.get(key) for key in keys}
    for field in ADVANCED_KEYS:
        payload[f"wizard_adv_{field}"] = st.session_state.get(f"wizard_adv_{field}")
    return payload


def apply_saved_preset(payload: dict) -> None:
    for key, value in payload.items():
        st.session_state[key] = value
    st.rerun()


st.title("시나리오 기반 신규 옵션 설정기")
st.caption("무슨 옵션을 넣을지보다 무엇을 점검할지에 집중해 설정을 만들 수 있는 신규 안내형 UI입니다.")

st.info(
    "기존 옵션 설정기는 그대로 유지됩니다. 이 화면은 보안 담당자와 운영 담당자가 "
    "점검 목적, 운영 영향 수준, 경로 검토 중심으로 손쉽게 설정을 만들기 위한 별도 페이지입니다."
)

st.markdown("### 추천 프리셋")
pack_cols = st.columns(len(RECOMMENDED_PACKS))
for idx, (pack_id, pack) in enumerate(RECOMMENDED_PACKS.items()):
    with pack_cols[idx]:
        with st.container(border=True):
            st.markdown(f"**{pack['label']}**")
            st.caption(pack["subtitle"])
            scenario_names = ", ".join(SCENARIOS[item]["label"] for item in pack["scenarios"])
            st.write(f"추천 시나리오: {scenario_names}")
            st.write(f"강도: {INTENSITY_PROFILES[pack['intensity']]['label']}")
            if st.button("이 프리셋 적용", key=f"pack_{pack_id}", use_container_width=True):
                st.session_state["wizard_selected_scenarios"] = pack["scenarios"]
                st.session_state["wizard_intensity"] = pack["intensity"]
                st.rerun()

top_left, top_right = st.columns([1.2, 0.8])

with top_left:
    st.markdown("### 쉬운 설정")
    st.radio(
        "어떤 서버를 점검하시겠습니까?",
        options=["nginx", "apache", "manual"],
        format_func=lambda x: {
            "nginx": "Nginx 덤프 사용",
            "apache": "Apache 덤프 사용",
            "manual": "수동 경로 지정",
        }[x],
        key="wizard_server_type",
        help="덤프 기반 자동 추출 또는 수동 경로 지정을 선택합니다.",
    )

    if st.session_state["wizard_server_type"] == "nginx":
        st.radio(
            "Nginx 설정 입력 방식",
            options=["파일 경로", "CLI 파이프 실행"],
            key="wizard_nginx_mode",
            horizontal=True,
            help="파일 경로는 후보 경로 미리 검토가 가능하고, CLI 파이프는 실제 실행 예시를 확인하는 방식입니다.",
        )
        if st.session_state["wizard_nginx_mode"] == "파일 경로":
            st.text_input(
                "Nginx 덤프 파일 경로",
                key="wizard_nginx_dump_path",
                placeholder="/tmp/nginx_dump.txt",
                help="nginx -T 결과를 저장한 파일 경로를 넣으면 자동 추출 후보를 미리 보여줍니다.",
            )
        else:
            st.info("실제 실행 시 `nginx -T 2>&1 | ... --nginx-dump -` 형태의 명령이 생성됩니다.")
    elif st.session_state["wizard_server_type"] == "apache":
        st.radio(
            "Apache 설정 입력 방식",
            options=["파일 경로", "CLI 파이프 실행"],
            key="wizard_apache_mode",
            horizontal=True,
            help="파일 경로를 주면 DocumentRoot 후보를 미리 검토할 수 있습니다.",
        )
        if st.session_state["wizard_apache_mode"] == "파일 경로":
            st.text_input(
                "Apache 덤프 파일 경로",
                key="wizard_apache_dump_path",
                placeholder="/tmp/apache_dump.txt",
                help="apachectl -S 결과 파일을 넣으면 자동 추출 후보를 표시합니다.",
            )
        else:
            st.info("실제 실행 시 `apachectl -S 2>&1 | ... --apache-dump -` 형태의 명령이 생성됩니다.")
    else:
        st.text_area(
            "직접 점검할 경로",
            key="wizard_extra_paths",
            height=120,
            placeholder="/var/www/html\n/data/upload",
            help="수동 경로 지정 방식에서는 점검할 웹루트, alias, 업로드 경로를 줄바꿈으로 입력합니다.",
        )

    st.markdown("#### 무엇을 중점 점검하시겠습니까?")
    scenario_cols = st.columns(2)
    selected_scenarios = st.multiselect(
        "점검 시나리오",
        options=list(SCENARIOS.keys()),
        default=st.session_state.get("wizard_selected_scenarios", ["integrated"]),
        format_func=lambda item: SCENARIOS[item]["label"],
        key="wizard_selected_scenarios",
        help="여러 시나리오를 함께 고르면 옵션이 결합되어 생성됩니다.",
    )

    for idx, scenario_id in enumerate(SCENARIOS):
        with scenario_cols[idx % 2]:
            with st.container(border=True):
                scenario = SCENARIOS[scenario_id]
                st.markdown(f"**{scenario['label']}**")
                st.write(scenario["summary"])
                st.caption(f"추천 상황: {scenario['recommended_for']}")
                st.caption(f"주요 탐지 대상: {scenario['risk_focus']}")
                st.caption(f"왜 필요한가: {scenario['why']}")

    st.radio(
        "운영 영향은 어느 수준까지 허용됩니까?",
        options=list(INTENSITY_PROFILES.keys()),
        format_func=lambda key: INTENSITY_PROFILES[key]["label"],
        key="wizard_intensity",
        horizontal=True,
        help="강도에 따라 최근 변경 시간, 탐색 깊이, 해시, 본문 스캔 범위가 자동 조정됩니다.",
    )
    intensity = INTENSITY_PROFILES[st.session_state["wizard_intensity"]]
    st.caption(
        f"{intensity['label']}: {intensity['description']} "
        f"(예상 부하 {intensity['load']})"
    )

    if st.session_state["wizard_server_type"] != "manual":
        st.text_area(
            "자동 추출 외 추가 점검 경로",
            key="wizard_extra_paths",
            height=100,
            placeholder="/data/upload\n/var/www/extra",
            help="자동 추출 대상 외에 별도로 보고 싶은 경로를 줄바꿈으로 추가합니다.",
        )

    st.text_input(
        "결과 파일 경로",
        key="wizard_output_path",
        value=st.session_state.get("wizard_output_path", "/tmp/dmz_webroot_scan_report.json"),
        help="JSON 결과 보고서를 저장할 경로입니다.",
    )

with top_right:
    st.markdown("### 저장/재사용")
    saved_presets = load_saved_presets()
    if saved_presets:
        selected_saved_preset = st.selectbox(
            "저장된 설정 불러오기",
            options=[""] + list(saved_presets.keys()),
            format_func=lambda item: "선택하세요" if item == "" else item,
        )
        action_col1, action_col2 = st.columns(2)
        with action_col1:
            if st.button("불러오기", use_container_width=True, disabled=selected_saved_preset == ""):
                apply_saved_preset(saved_presets[selected_saved_preset])
        with action_col2:
            if st.button("삭제", use_container_width=True, disabled=selected_saved_preset == ""):
                delete_preset(selected_saved_preset)
                st.rerun()
    else:
        st.caption("저장된 설정이 아직 없습니다. YAML 다운로드 파일과 함께 재사용하거나, 아래 이름으로 저장할 수 있습니다.")

    preset_name = st.text_input(
        "현재 설정 이름",
        placeholder="예: DMZ-Nginx-안전점검",
        help="자주 쓰는 서버군/점검 목적 조합을 저장해 다시 불러올 수 있습니다.",
    )
    if st.button("현재 설정 저장", use_container_width=True):
        save_preset(preset_name, preset_payload())
        st.success("설정을 저장했습니다.")

server_type = st.session_state.get("wizard_server_type", "nginx")
nginx_mode = st.session_state.get("wizard_nginx_mode", "파일 경로")
nginx_dump_path = st.session_state.get("wizard_nginx_dump_path", "")
apache_mode = st.session_state.get("wizard_apache_mode", "파일 경로")
apache_dump_path = st.session_state.get("wizard_apache_dump_path", "")
extra_paths_text = st.session_state.get("wizard_extra_paths", "")
selected_scenarios = st.session_state.get("wizard_selected_scenarios", ["integrated"])
intensity_key = st.session_state.get("wizard_intensity", "balanced")
output_path = st.session_state.get("wizard_output_path", "/tmp/dmz_webroot_scan_report.json")

dump_path = nginx_dump_path if server_type == "nginx" and nginx_mode == "파일 경로" else ""
if server_type == "apache" and apache_mode == "파일 경로":
    dump_path = apache_dump_path

auto_candidates = parse_auto_extracted_paths(server_type, dump_path)
all_candidate_paths = [item["path"] for item in auto_candidates]

if server_type != "manual":
    st.markdown("### 경로 검토")
    if auto_candidates:
        default_selected = st.session_state.get("wizard_selected_candidates", all_candidate_paths)
        filtered_defaults = [item for item in default_selected if item in all_candidate_paths]
        st.session_state["wizard_selected_candidates"] = filtered_defaults or all_candidate_paths
        st.dataframe(auto_candidates, use_container_width=True, hide_index=True)
        st.multiselect(
            "점검에 포함할 자동 추출 경로",
            options=all_candidate_paths,
            default=st.session_state["wizard_selected_candidates"],
            key="wizard_selected_candidates",
            help="선택에서 제외한 경로는 생성 명령에 --exclude로 반영됩니다.",
        )
        st.caption("자동 추출 후보를 검토한 뒤 제외한 경로는 명령 생성 시 `--exclude`로 처리합니다.")
    else:
        st.warning(
            "자동 추출 후보를 아직 읽지 못했습니다. 덤프 파일 경로가 없거나 파일을 읽을 수 없는 상태입니다. "
            "이 경우 생성된 명령은 덤프 기반 추출을 사용하되, 화면에서는 예상 추출 대상만 안내합니다."
        )
        st.caption(
            "Nginx는 root/alias, Apache는 DocumentRoot가 자동 추출 대상입니다. "
            "필요하면 추가 점검 경로를 수동으로 함께 넣어 주세요."
        )

selected_candidates = st.session_state.get("wizard_selected_candidates", all_candidate_paths if auto_candidates else [])
unselected_candidates = [path for path in all_candidate_paths if path not in selected_candidates]

recommended_config = build_scenario_config(
    selected_scenarios=selected_scenarios,
    intensity=intensity_key,
    server_type=server_type,
    nginx_mode=nginx_mode,
    nginx_dump_path=nginx_dump_path,
    apache_mode=apache_mode,
    apache_dump_path=apache_dump_path,
    extra_watch_dirs_text=extra_paths_text,
    selected_candidates=selected_candidates,
    unselected_candidates=unselected_candidates,
    output_path=output_path,
)

signature = json.dumps(
    {
        "selected_scenarios": selected_scenarios,
        "intensity": intensity_key,
        "server_type": server_type,
        "nginx_mode": nginx_mode,
        "nginx_dump_path": nginx_dump_path,
        "apache_mode": apache_mode,
        "apache_dump_path": apache_dump_path,
        "extra_paths": extra_paths_text,
        "selected_candidates": selected_candidates,
        "output_path": output_path,
    },
    ensure_ascii=False,
    sort_keys=True,
)
sync_advanced_state(recommended_config, signature)

with st.expander("고급 설정", expanded=False):
    st.caption("일반 사용자는 이 영역을 열지 않아도 됩니다. 필요 시 세부 옵션을 직접 조정할 수 있습니다.")

    col1, col2 = st.columns(2)
    with col1:
        st.number_input(
            "최근 변경 파일만 점검 (`newer-than-h`)",
            min_value=0,
            max_value=720,
            key="wizard_adv_newer_than_h",
            help="최근 N시간 이내 변경 파일을 우선 봅니다. 0이면 시간 제한을 두지 않습니다.",
        )
        st.number_input(
            "하위 폴더 탐색 깊이 (`max-depth`)",
            min_value=1,
            max_value=30,
            key="wizard_adv_max_depth",
            help="값이 커질수록 더 깊은 하위 경로까지 점검합니다.",
        )
        st.number_input(
            "병렬 작업 수 (`workers`)",
            min_value=1,
            max_value=64,
            key="wizard_adv_workers",
            help="동시 점검 작업 수입니다. 높을수록 빨라질 수 있지만 서버 부하도 올라갑니다.",
        )
        st.number_input(
            "읽을 최대 파일 크기 MB (`max-size-mb`)",
            min_value=1,
            max_value=2048,
            key="wizard_adv_max_size_mb",
            help="해시 계산이나 MIME 식별에 읽을 최대 파일 크기입니다.",
        )
        st.checkbox(
            "증적 보존용 SHA-256 계산 (`hash`)",
            key="wizard_adv_hash_enabled",
            help="의심 파일의 SHA-256을 계산해 증적성과 비교 가능성을 높입니다.",
        )
        st.checkbox(
            "심볼릭 링크 추적 (`follow-symlink`)",
            key="wizard_adv_follow_symlink",
            help="링크 대상까지 추적합니다. 경로 범위가 넓어질 수 있어 주의가 필요합니다.",
        )
    with col2:
        st.checkbox(
            "파일 본문 내 민감정보 패턴 점검 (`content-scan`)",
            key="wizard_adv_content_scan",
            help="파일 내용에서 계정, 토큰, 내부 접속정보 같은 패턴을 확인합니다.",
        )
        st.number_input(
            "본문 점검 최대 바이트 (`content-max-bytes`)",
            min_value=128,
            max_value=1048576,
            key="wizard_adv_content_max_bytes",
            help="파일당 읽을 최대 본문 길이입니다.",
        )
        st.number_input(
            "본문 점검 최대 파일 크기 KB (`content-max-size-kb`)",
            min_value=1,
            max_value=102400,
            key="wizard_adv_content_max_size_kb",
            help="이 크기 이하 파일만 본문 패턴을 점검합니다.",
        )
        st.checkbox(
            "개인정보 패턴 점검 (`pii-scan`)",
            key="wizard_adv_pii_scan",
            help="주민번호, 연락처, 이메일 등 개인정보 패턴을 추가로 찾습니다.",
        )
        st.number_input(
            "PII 점검 최대 바이트 (`pii-max-bytes`)",
            min_value=128,
            max_value=1048576,
            key="wizard_adv_pii_max_bytes",
        )
        st.number_input(
            "PII 점검 최대 파일 크기 KB (`pii-max-size-kb`)",
            min_value=1,
            max_value=102400,
            key="wizard_adv_pii_max_size_kb",
        )
        st.number_input(
            "PII 규칙당 최대 저장 개수 (`pii-max-matches`)",
            min_value=1,
            max_value=100,
            key="wizard_adv_pii_max_matches",
        )

    st.text_area(
        "정상 파일 확장자 허용 목록 (`allow-ext`)",
        key="wizard_adv_allow_exts",
        height=120,
        help="업무상 정상으로 보는 파일 확장자를 줄바꿈으로 입력합니다.",
    )
    st.text_area(
        "정상 콘텐츠 유형 허용 목록 (`allow-mime-prefix`)",
        key="wizard_adv_allow_mime_prefixes",
        height=100,
        help="정상으로 보는 MIME 유형 또는 접두사를 줄바꿈으로 입력합니다.",
    )
    st.text_area(
        "제외 경로 (`exclude`)",
        key="wizard_adv_excludes",
        height=100,
        help="점검에서 빼고 싶은 경로 접두사를 줄바꿈으로 입력합니다.",
    )
    rule_col1, rule_col2 = st.columns(2)
    with rule_col1:
        st.text_area(
            "추가 활성화 규칙 (`enable-rules`)",
            key="wizard_adv_enable_rules",
            height=90,
            help="현재 프로그램이 지원하는 규칙 이름을 줄바꿈으로 입력해 추가 활성화합니다.",
        )
    with rule_col2:
        st.text_area(
            "비활성화 규칙 (`disable-rules`)",
            key="wizard_adv_disable_rules",
            height=90,
            help="노이즈가 많거나 제외하고 싶은 규칙 이름을 줄바꿈으로 입력합니다.",
        )
    st.text_area(
        "본문 점검 확장자 (`content-ext`)",
        key="wizard_adv_content_exts",
        height=100,
        help="본문 점검을 적용할 파일 확장자입니다.",
    )
    st.text_area(
        "PII 점검 확장자 (`pii-ext`)",
        key="wizard_adv_pii_exts",
        height=100,
        help="개인정보 패턴 점검을 적용할 파일 확장자입니다.",
    )

    pii_col1, pii_col2 = st.columns(2)
    with pii_col1:
        st.checkbox("PII 마스킹 (`pii-mask`)", key="wizard_adv_pii_mask")
        st.checkbox("PII 샘플 저장 (`pii-store-sample`)", key="wizard_adv_pii_store_sample")
    with pii_col2:
        st.checkbox("문맥 키워드 활용 (`pii-context-keywords`)", key="wizard_adv_pii_context_keywords")

    with st.expander("Kafka 연계 설정", expanded=False):
        st.checkbox("Kafka 전송 사용 (`kafka-enabled`)", key="wizard_adv_kafka_enabled")
        st.text_input("Kafka brokers (`kafka-brokers`)", key="wizard_adv_kafka_brokers")
        st.text_input("Kafka topic (`kafka-topic`)", key="wizard_adv_kafka_topic")
        st.text_input("Kafka client id (`kafka-client-id`)", key="wizard_adv_kafka_client_id")
        st.checkbox("Kafka TLS (`kafka-tls`)", key="wizard_adv_kafka_tls")
        st.checkbox("Kafka SASL (`kafka-sasl-enabled`)", key="wizard_adv_kafka_sasl_enabled")
        st.text_input("Kafka username (`kafka-username`)", key="wizard_adv_kafka_username")
        st.text_input("Kafka password env (`kafka-password-env`)", key="wizard_adv_kafka_password_env")
        st.checkbox("Kafka 민감정보 마스킹 (`kafka-mask-sensitive`)", key="wizard_adv_kafka_mask_sensitive")

final_config = build_final_config(recommended_config)
command = build_command(final_config)
config_payload = build_config_payload(final_config)
yaml_text = yaml.safe_dump(config_payload, allow_unicode=True, sort_keys=False) if yaml is not None else None
rules_summary = summarize_rules(final_config, selected_scenarios)
scope_summary = summarize_scope(final_config, auto_candidates, selected_candidates, unselected_candidates)
load_level, load_reason = estimate_load(final_config)
checkpoints = execution_checkpoints(final_config, server_type, selected_candidates)

st.markdown("### 생성 결과")
metric_col1, metric_col2, metric_col3 = st.columns(3)
metric_col1.metric("예상 부하 수준", load_level)
metric_col2.metric("자동 추출 후보", len(auto_candidates))
metric_col3.metric("추가 수동 경로", len(final_config["watch_dirs"]))

left, right = st.columns([1.2, 1])
with left:
    st.markdown("#### 생성된 CLI 명령")
    st.code(command, language="bash")
    copy_col1, copy_col2 = st.columns(2)
    with copy_col1:
        copy_button("CLI 복사", command)
    with copy_col2:
        st.download_button(
            "CLI 파일 다운로드",
            data=command.encode("utf-8"),
            file_name="dmz_scan_command.sh",
            mime="text/plain",
            use_container_width=True,
        )

    st.markdown("#### 생성된 YAML 설정 미리보기")
    if yaml_text is None:
        st.warning("PyYAML이 설치되지 않아 YAML 미리보기를 표시하지 못했습니다.")
    else:
        st.code(yaml_text, language="yaml")
        yaml_col1, yaml_col2 = st.columns(2)
        with yaml_col1:
            copy_button("YAML 복사", yaml_text)
        with yaml_col2:
            st.download_button(
                "YAML 다운로드",
                data=yaml_text.encode("utf-8"),
                file_name="dmz_scan_config.yaml",
                mime="text/yaml",
                use_container_width=True,
            )

with right:
    st.markdown("#### 적용된 탐지 규칙 요약")
    for item in rules_summary:
        st.write(f"- {item}")

    st.markdown("#### 예상 점검 범위")
    for item in scope_summary:
        st.write(f"- {item}")

    st.markdown("#### 예상 부하 설명")
    st.write(load_reason)

    st.markdown("#### 실행 전 체크포인트")
    if checkpoints:
        for item in checkpoints:
            st.write(f"- {item}")
    else:
        st.write("- 바로 실행 가능한 상태입니다.")

st.markdown("#### JSON 설정 미리보기")
st.code(json.dumps(config_payload, ensure_ascii=False, indent=2), language="json")
