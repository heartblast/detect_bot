import json
import shlex
from copy import deepcopy

import streamlit as st

try:
    import yaml
except Exception:
    yaml = None

from lib.constants import (
    DEFAULT_ALLOW_MIME_PREFIXES,
    DEFAULT_ALLOW_EXTS,
    DEFAULT_CONTENT_EXTS,
    DEFAULT_PII_EXTS,
    RULE_OPTIONS,
)
from lib.presets import PRESETS
from lib.utils import apply_preset, state_get, non_empty_lines, csv_or_lines
from lib.config_builder import build_command, build_config, build_config_payload


if "preset_name" not in st.session_state:
    st.session_state["preset_name"] = "균형 모드"
    apply_preset("균형 모드")

st.title("🛡️ DMZ 웹서빙 경로 보안 점검 옵션 생성기")
st.caption("dmz_webroot_scanner v1.1.2 옵션에 맞춘 실행 명령과 설정 예시를 생성합니다.")

preset_col1, preset_col2 = st.columns([2, 3])
with preset_col1:
    preset_name = st.selectbox(
        "프리셋 선택",
        list(PRESETS.keys()),
        index=list(PRESETS.keys()).index(state_get("preset_name", "균형 모드")),
        key="preset_name",
    )
with preset_col2:
    if st.button("프리셋 적용", use_container_width=True):
        apply_preset(preset_name)
        st.rerun()

left, right = st.columns([1.2, 1])

with left:
    st.subheader("입력 옵션")

    st.radio(
        "점검 목적",
        ["테스트 점검", "운영 점검", "정기 점검"],
        key="purpose",
    )

    st.selectbox(
        "대상 웹서버 유형",
        ["nginx", "apache", "manual"],
        key="server_type",
    )

    if st.session_state["server_type"] == "nginx":
        st.selectbox(
            "Nginx 입력 방식",
            ["덤프 파일 경로", "표준입력(pipe) 명령"],
            key="nginx_input_mode",
        )
        if st.session_state["nginx_input_mode"] == "덤프 파일 경로":
            st.text_input("Nginx 덤프 파일 경로", key="nginx_dump_path", placeholder="/tmp/nginx_dump.txt")
    elif st.session_state["server_type"] == "apache":
        st.selectbox(
            "Apache 입력 방식",
            ["덤프 파일 경로", "표준입력(pipe) 명령"],
            key="apache_input_mode",
        )
        if st.session_state["apache_input_mode"] == "덤프 파일 경로":
            st.text_input("Apache 덤프 파일 경로", key="apache_dump_path", placeholder="/tmp/apache_dump.txt")
    else:
        st.info("manual은 웹서버 덤프 없이 --watch-dir 중심으로 구성합니다.")

    st.text_area(
        "추가 점검 경로 (--watch-dir, 줄바꿈 구분)",
        key="watch_dirs_text",
        height=110,
        placeholder="/var/www/html\n/data/upload",
    )

    c1, c2 = st.columns(2)
    with c1:
        st.number_input("최근 변경 시간 (시간)", min_value=0, max_value=720, key="newer_than_h")
        st.number_input("최대 탐색 깊이", min_value=1, max_value=30, key="max_depth")
        st.number_input("병렬 워커 수", min_value=1, max_value=64, key="workers")
    with c2:
        st.number_input("최대 읽기 크기 (MB)", min_value=1, max_value=102400, key="max_size_mb")
        st.checkbox("심볼릭 링크 추적", key="follow_symlink")
        st.checkbox("SHA-256 해시 계산", key="hash_enabled")

    st.markdown("#### 허용 정책")
    st.text_area(
        "허용 MIME Prefix (--allow-mime-prefix)",
        key="allow_mime_prefixes",
        height=120,
    )
    st.text_area(
        "허용 확장자 (--allow-ext)",
        key="allow_exts",
        height=150,
    )

    st.markdown("#### 룰 세부 제어")
    st.text_area(
        "추가 활성화 룰 (--enable-rules, 줄바꿈 또는 콤마 구분)",
        key="enable_rules_text",
        height=90,
        placeholder="high_risk_extension",
    )
    st.text_area(
        "비활성화 룰 (--disable-rules, 줄바꿈 또는 콤마 구분)",
        key="disable_rules_text",
        height=90,
        placeholder="large_file_in_web_path",
    )

    with st.expander("지원 룰 코드 보기"):
        st.code("\n".join(RULE_OPTIONS), language="text")

    st.markdown("#### 콘텐츠 스캔")
    st.checkbox("콘텐츠 기반 민감정보 탐지 사용 (--content-scan)", key="content_scan")
    if st.session_state.get("content_scan"):
        cc1, cc2 = st.columns(2)
        with cc1:
            st.number_input("콘텐츠 최대 읽기 바이트", min_value=128, max_value=1048576, key="content_max_bytes")
        with cc2:
            st.number_input("콘텐츠 대상 최대 파일 크기 (KB)", min_value=1, max_value=102400, key="content_max_size_kb")
        st.text_area(
            "콘텐츠 스캔 대상 확장자 (--content-ext)",
            key="content_exts",
            height=120,
        )

    st.markdown("#### PII 스캔")
    st.checkbox("개인정보 패턴 탐지 사용 (--pii-scan)", key="pii_scan")
    if st.session_state.get("pii_scan"):
        pc1, pc2 = st.columns(2)
        with pc1:
            st.number_input("PII 최대 읽기 바이트", min_value=128, max_value=1048576, key="pii_max_bytes")
            st.number_input("규칙별 최대 저장 샘플 수", min_value=1, max_value=100, key="pii_max_matches")
        with pc2:
            st.number_input("PII 대상 최대 파일 크기 (KB)", min_value=1, max_value=102400, key="pii_max_size_kb")
        st.text_area(
            "PII 스캔 대상 확장자 (--pii-ext)",
            key="pii_exts",
            height=120,
        )
        st.checkbox("PII 마스킹 (--pii-mask)", key="pii_mask")
        st.checkbox("마스킹된 샘플 저장 (--pii-store-sample)", key="pii_store_sample")
        st.checkbox("문맥 키워드 분석 (--pii-context-keywords)", key="pii_context_keywords")

    st.text_area(
        "제외 경로 (--exclude)",
        key="excludes_text",
        height=120,
    )
    st.text_input("리포트 저장 경로 (--out)", key="output_path")

    with st.expander("Kafka 연계 설정"):
        st.checkbox("Kafka 전송 사용 (--kafka-enabled)", key="kafka_enabled")
        if st.session_state.get("kafka_enabled"):
            st.text_input("브로커 목록 (--kafka-brokers)", key="kafka_brokers", placeholder="broker1:9092,broker2:9092")
            st.text_input("토픽 (--kafka-topic)", key="kafka_topic", placeholder="dmz.scan.findings")
            st.text_input("클라이언트 ID (--kafka-client-id)", key="kafka_client_id")
            st.checkbox("TLS 사용 (--kafka-tls)", key="kafka_tls")
            st.checkbox("SASL 사용 (--kafka-sasl-enabled)", key="kafka_sasl_enabled")
            st.text_input("사용자명 (--kafka-username)", key="kafka_username")
            st.text_input("비밀번호 환경변수명 (--kafka-password-env)", key="kafka_password_env")
            st.checkbox("민감정보 마스킹 (--kafka-mask-sensitive)", key="kafka_mask_sensitive")

config = build_config()
command = build_command(config)

config_payload = build_config_payload(config)

with right:
    st.subheader("생성 결과")

    a, b, c = st.columns(3)
    a.metric("점검 경로 수", len(config["watch_dirs"]))
    b.metric("활성 allow-ext 수", len(config["allow_exts"]))
    c.metric("제외 경로 수", len(config["excludes"]))

    st.markdown("#### 생성된 CLI 명령")
    st.code(command, language="bash")

    st.download_button(
        "명령어 다운로드",
        data=command.encode("utf-8"),
        file_name="dmz_scan_command.sh",
        mime="text/plain",
        use_container_width=True,
    )

    st.markdown("#### 설정파일 미리보기 (YAML)")
    yaml_text = yaml.safe_dump(config_payload, allow_unicode=True, sort_keys=False) if yaml else json.dumps(config_payload, ensure_ascii=False, indent=2)
    st.code(yaml_text, language="yaml")

    st.download_button(
        "YAML 다운로드",
        data=yaml_text.encode("utf-8"),
        file_name="dmz_scan_config.yaml",
        mime="text/yaml",
        use_container_width=True,
    )

    st.markdown("#### 설정파일 미리보기 (JSON)")
    json_text = json.dumps(config_payload, ensure_ascii=False, indent=2)
    st.code(json_text, language="json")

    st.download_button(
        "JSON 다운로드",
        data=json_text.encode("utf-8"),
        file_name="dmz_scan_config.json",
        mime="application/json",
        use_container_width=True,
    )

    notes = []

    if config["newer_than_h"] and config["newer_than_h"] <= 24:
        notes.append("최근 변경 파일 중심 점검으로 운영 영향이 비교적 낮습니다.")
    else:
        notes.append("점검 범위가 넓어질 수 있으므로 운영 시간대를 고려하는 것이 좋습니다.")

    if config["hash_enabled"]:
        notes.append("해시 계산이 활성화되어 처리 시간이 증가할 수 있습니다.")

    if config["content_scan"]:
        notes.append("콘텐츠 기반 민감정보 탐지가 활성화되어 설정파일 내 유출위험정보를 함께 점검합니다.")

    if config["pii_scan"]:
        notes.append("PII 탐지가 활성화되어 개인정보 패턴과 마스킹 샘플 저장 여부를 함께 검토해야 합니다.")

    if config["kafka_enabled"]:
        notes.append("Kafka 전송이 활성화되어 로컬 리포트와 별도로 토픽 접근통제 및 자격증명 관리가 필요합니다.")

    st.markdown("#### 실행 전 검토")
    for note in notes:
        st.write(f"- {note}")

st.divider()

with st.expander("사용 가이드", expanded=False):
    st.markdown(
        """
- Nginx는 `nginx -T 2>&1`, Apache는 `apachectl -S 2>&1` 기반 입력을 권장합니다.
- Apache는 환경에 따라 `DocumentRoot`가 덤프에 충분히 나타나지 않을 수 있으므로 `--watch-dir` 보강이 필요할 수 있습니다.
- `manual`은 실제 웹루트/업로드 경로를 직접 지정할 때 사용합니다.
- 운영 영향 최소화를 위해 `--newer-than-h`, `--max-depth`, `--exclude`, `--workers`를 함께 조정하세요.
- 콘텐츠 스캔과 PII 스캔은 텍스트 기반 파일을 중심으로 제한해서 사용하는 것이 좋습니다.
        """
    )