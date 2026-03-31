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


OPTION_HELP = {
    "preset_name": "자주 쓰는 옵션 조합을 미리 불러옵니다. 운영 점검, 안전 모드, 정밀 점검의 시작점으로 활용할 수 있습니다.",
    "purpose": "이번 점검의 목적이나 실행 모드를 선택합니다. 목적에 따라 권장 범위와 운영 중 허용 가능한 부하 수준이 달라질 수 있습니다.",
    "server_type": "점검 대상 웹서버 유형을 선택합니다. 서버 유형에 따라 설정 해석 방식과 웹서빙 경로 추출 방식이 달라질 수 있습니다.",
    "nginx_input_mode": "`nginx -T` 결과를 파일로 줄지 표준입력으로 넘길지 정합니다. 실제 운영 설정과 같은 시점의 덤프를 쓰는 것이 중요합니다.",
    "nginx_dump_path": "`nginx -T` 결과를 저장한 파일 경로입니다. 최신 덤프가 아니면 추출 경로가 실제 운영 상태와 달라질 수 있습니다.",
    "apache_input_mode": "Apache 설정 덤프를 파일 또는 표준입력으로 전달하는 방식입니다. 환경에 따라 `--watch-dir` 보강이 함께 필요할 수 있습니다.",
    "apache_dump_path": "Apache 설정 덤프 파일 위치를 지정합니다. DocumentRoot, Alias 같은 실제 웹서빙 경로를 찾는 데 사용됩니다.",
    "watch_dirs_text": "설정 덤프 대신 직접 점검할 경로를 추가합니다. 불필요한 경로를 많이 넣으면 검사 범위와 처리 시간이 함께 늘어날 수 있습니다.",
    "newer_than_h": "최근 N시간 이내에 변경된 파일만 우선적으로 점검합니다. 최근 변경 파일 위주로 빠르게 확인할 때 유용하지만 값을 크게 두면 사실상 전체 범위에 가까워질 수 있습니다.",
    "max_depth": "하위 디렉터리를 어디까지 탐색할지 제한합니다. 값을 크게 두면 검사 범위와 시간이 늘어나므로 운영 환경에서는 보수적으로 시작하는 편이 안전합니다.",
    "workers": "동시에 처리할 작업 수를 지정합니다. 값을 높이면 속도는 빨라질 수 있지만 대상 서버나 스토리지 부하가 커질 수 있습니다.",
    "max_size_mb": "한 파일에서 읽을 최대 크기 기준입니다. 대용량 파일이 많은 환경에서는 부하를 줄이는 데 도움이 되지만 값을 키우면 I/O 시간도 늘 수 있습니다.",
    "follow_symlink": "심볼릭 링크가 가리키는 경로까지 따라가며 점검합니다. 의도하지 않은 외부 경로까지 검사 범위가 넓어질 수 있으므로 주의가 필요합니다.",
    "hash_enabled": "파일 해시를 계산해 동일 파일 식별과 변경 추적에 활용합니다. 파일 수가 많거나 큰 파일이 많으면 점검 시간이 늘어날 수 있습니다.",
    "allow_mime_prefixes": "허용할 MIME 유형 범위를 지정합니다. 허용 범위를 너무 넓히면 정책 기반 탐지가 느슨해질 수 있습니다.",
    "allow_exts": "허용할 파일 확장자 목록을 지정합니다. 목록에 없는 확장자는 이상 파일 후보로 식별될 수 있으므로 실제 운영 정책에 맞게 유지하는 것이 중요합니다.",
    "enable_rules_text": "기본값 외에 더 적용할 탐지 규칙을 지정합니다. 탐지 범위와 결과 건수가 늘 수 있으므로 필요한 규칙만 추가하는 편이 좋습니다.",
    "disable_rules_text": "특정 탐지 규칙을 제외합니다. 오탐을 줄이는 데는 유용하지만 보안 기준이 낮아질 수 있으므로 운영 환경에서는 제한적으로 사용하는 것이 좋습니다.",
    "content_scan": "파일 내용 일부를 직접 확인해 민감정보나 의심 패턴을 탐지합니다. 정밀도는 높아지지만 파일 수가 많거나 큰 파일이 많으면 검사 시간이 늘어날 수 있습니다.",
    "content_max_bytes": "내용 검사 시 파일 앞부분에서 최대 몇 바이트까지 읽을지 제한합니다. 값을 줄이면 속도와 부하는 낮아지지만 탐지 범위도 줄 수 있습니다.",
    "content_max_size_kb": "내용 검사를 수행할 파일의 최대 크기를 제한합니다. 큰 파일 전체를 검사하지 않도록 하여 부하를 줄이는 데 사용합니다.",
    "content_exts": "내용 검사를 적용할 확장자 대상을 지정합니다. 필요한 파일 유형만 선택적으로 검사하면 범위와 부하를 함께 조절할 수 있습니다.",
    "pii_scan": "개인정보 패턴을 탐지합니다. 콘텐츠 스캔과 마찬가지로 처리 시간이 늘 수 있으므로 대상 확장자와 크기 제한을 함께 조정하는 것이 좋습니다.",
    "pii_max_bytes": "PII 탐지를 위해 읽을 최대 바이트 수를 제한합니다. 값을 줄이면 부하는 낮아지지만 탐지 범위도 함께 줄어듭니다.",
    "pii_max_matches": "규칙별로 저장할 샘플 수를 제한합니다. 값을 크게 두면 검토 정보는 늘지만 보고서 크기와 저장 부하도 커질 수 있습니다.",
    "pii_max_size_kb": "PII 탐지를 수행할 파일의 최대 크기를 제한합니다. 대용량 문서가 많은 환경에서는 보수적으로 두는 편이 안전합니다.",
    "pii_exts": "PII 탐지를 적용할 확장자를 지정합니다. 문서, 텍스트, 설정 파일처럼 필요한 유형만 골라 검사하는 데 유용합니다.",
    "pii_mask": "탐지된 개인정보를 결과에서 가려서 표시합니다. 운영 환경에서 결과를 공유하거나 저장할 때 특히 중요합니다.",
    "pii_store_sample": "탐지 결과의 예시 샘플을 저장합니다. 후속 분석에는 도움이 되지만 저장 정책과 민감정보 취급 기준을 함께 확인해야 합니다.",
    "pii_context_keywords": "주변 문맥 키워드를 함께 봐서 개인정보 패턴 해석을 보조합니다. 정밀도 개선에 도움이 될 수 있지만 처리량이 약간 늘 수 있습니다.",
    "excludes_text": "점검에서 제외할 경로나 패턴을 지정합니다. 로그, 캐시, 임시 디렉터리를 제외해 부하를 낮출 수 있지만 중요한 웹서빙 경로를 빼지 않도록 주의해야 합니다.",
    "output_path": "점검 결과 파일의 저장 위치를 지정합니다. 실행 환경에서 쓰기 권한이 있는 경로를 사용하고 결과물 접근통제도 함께 고려해야 합니다.",
    "kafka_enabled": "점검 결과를 Kafka로도 전송합니다. 후속 파이프라인 연계에는 유용하지만 토픽 접근통제와 자격증명 관리가 필요합니다.",
    "kafka_brokers": "Kafka 브로커 주소 목록입니다. 운영망과 관리망이 분리된 환경에서는 네트워크 경로도 함께 확인해야 합니다.",
    "kafka_topic": "점검 결과를 전송할 Kafka 토픽 이름입니다. 공용 토픽을 사용할 때는 민감정보 포함 여부를 특히 주의해야 합니다.",
    "kafka_client_id": "Kafka 연결을 식별하기 위한 클라이언트 ID입니다. 운영 로그 추적과 장애 분석에 도움이 됩니다.",
    "kafka_tls": "Kafka 전송 구간을 암호화합니다. 운영 환경에서는 기본적으로 검토할 만한 보안 옵션이지만 인증서 설정이 맞지 않으면 연결이 실패할 수 있습니다.",
    "kafka_sasl_enabled": "Kafka 인증에 SASL을 사용합니다. 인증이 필요한 브로커 환경에서는 필수일 수 있으며 계정과 비밀번호 관리가 함께 필요합니다.",
    "kafka_username": "SASL 인증에 사용할 계정명입니다. 운영용 계정은 최소 권한 원칙으로 분리하는 편이 안전합니다.",
    "kafka_password_env": "Kafka 비밀번호를 담고 있는 환경변수 이름입니다. 비밀번호를 설정 파일에 직접 쓰지 않도록 할 때 사용합니다.",
    "kafka_mask_sensitive": "Kafka로 보내는 결과에서 민감정보를 가려서 전송합니다. 외부 시스템으로 결과가 이동하는 환경에서는 특히 중요합니다.",
}


def option_help(key: str) -> str | None:
    return OPTION_HELP.get(key)


if "preset_name" not in st.session_state:
    st.session_state["preset_name"] = "균형 모드"
    apply_preset("균형 모드")

st.title("🛡️ DMZ 웹서빙 경로 보안 점검 옵션 생성기")
st.caption("detectbot v1.1.3 옵션에 맞춘 실행 명령과 설정 예시를 생성합니다.")
st.caption("각 옵션 오른쪽의 `?` 아이콘에서 사용 목적과 운영 시 주의사항을 확인할 수 있습니다.")

preset_col1, preset_col2 = st.columns([2, 3])
with preset_col1:
    preset_name = st.selectbox(
        "프리셋 선택",
        list(PRESETS.keys()),
        index=list(PRESETS.keys()).index(state_get("preset_name", "균형 모드")),
        key="preset_name",
        help=option_help("preset_name"),
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
        help=option_help("purpose"),
    )

    st.selectbox(
        "대상 웹서버 유형",
        ["nginx", "apache", "manual"],
        key="server_type",
        help=option_help("server_type"),
    )

    if st.session_state["server_type"] == "nginx":
        st.selectbox(
            "Nginx 입력 방식",
            ["덤프 파일 경로", "표준입력(pipe) 명령"],
            key="nginx_input_mode",
            help=option_help("nginx_input_mode"),
        )
        if st.session_state["nginx_input_mode"] == "덤프 파일 경로":
            st.text_input("Nginx 덤프 파일 경로", key="nginx_dump_path", placeholder="/tmp/nginx_dump.txt", help=option_help("nginx_dump_path"))
    elif st.session_state["server_type"] == "apache":
        st.selectbox(
            "Apache 입력 방식",
            ["덤프 파일 경로", "표준입력(pipe) 명령"],
            key="apache_input_mode",
            help=option_help("apache_input_mode"),
        )
        if st.session_state["apache_input_mode"] == "덤프 파일 경로":
            st.text_input("Apache 덤프 파일 경로", key="apache_dump_path", placeholder="/tmp/apache_dump.txt", help=option_help("apache_dump_path"))
    else:
        st.info("manual은 웹서버 덤프 없이 --watch-dir 중심으로 구성합니다.")

    st.text_area(
        "추가 점검 경로 (--watch-dir, 줄바꿈 구분)",
        key="watch_dirs_text",
        help=option_help("watch_dirs_text"),
        height=110,
        placeholder="/var/www/html\n/data/upload",
    )

    c1, c2 = st.columns(2)
    with c1:
        st.number_input("최근 변경 시간 (시간)", min_value=0, max_value=720, key="newer_than_h", help=option_help("newer_than_h"))
        st.number_input("최대 탐색 깊이", min_value=1, max_value=30, key="max_depth", help=option_help("max_depth"))
        st.number_input("병렬 워커 수", min_value=1, max_value=64, key="workers", help=option_help("workers"))
    with c2:
        st.number_input("최대 읽기 크기 (MB)", min_value=1, max_value=102400, key="max_size_mb", help=option_help("max_size_mb"))
        st.checkbox("심볼릭 링크 추적", key="follow_symlink", help=option_help("follow_symlink"))
        st.checkbox("SHA-256 해시 계산", key="hash_enabled", help=option_help("hash_enabled"))

    st.markdown("#### 허용 정책")
    st.text_area(
        "허용 MIME Prefix (--allow-mime-prefix)",
        key="allow_mime_prefixes",
        help=option_help("allow_mime_prefixes"),
        height=120,
    )
    st.text_area(
        "허용 확장자 (--allow-ext)",
        key="allow_exts",
        help=option_help("allow_exts"),
        height=150,
    )

    st.markdown("#### 룰 세부 제어")
    st.text_area(
        "추가 활성화 룰 (--enable-rules, 줄바꿈 또는 콤마 구분)",
        key="enable_rules_text",
        help=option_help("enable_rules_text"),
        height=90,
        placeholder="high_risk_extension",
    )
    st.text_area(
        "비활성화 룰 (--disable-rules, 줄바꿈 또는 콤마 구분)",
        key="disable_rules_text",
        help=option_help("disable_rules_text"),
        height=90,
        placeholder="large_file_in_web_path",
    )

    with st.expander("지원 룰 코드 보기"):
        st.code("\n".join(RULE_OPTIONS), language="text")

    st.markdown("#### 콘텐츠 스캔")
    st.checkbox("콘텐츠 기반 민감정보 탐지 사용 (--content-scan)", key="content_scan", help=option_help("content_scan"))
    if st.session_state.get("content_scan"):
        cc1, cc2 = st.columns(2)
        with cc1:
            st.number_input("콘텐츠 최대 읽기 바이트", min_value=128, max_value=1048576, key="content_max_bytes", help=option_help("content_max_bytes"))
        with cc2:
            st.number_input("콘텐츠 대상 최대 파일 크기 (KB)", min_value=1, max_value=102400, key="content_max_size_kb", help=option_help("content_max_size_kb"))
        st.text_area(
            "콘텐츠 스캔 대상 확장자 (--content-ext)",
            key="content_exts",
            help=option_help("content_exts"),
            height=120,
        )

    st.markdown("#### PII 스캔")
    st.checkbox("개인정보 패턴 탐지 사용 (--pii-scan)", key="pii_scan", help=option_help("pii_scan"))
    if st.session_state.get("pii_scan"):
        pc1, pc2 = st.columns(2)
        with pc1:
            st.number_input("PII 최대 읽기 바이트", min_value=128, max_value=1048576, key="pii_max_bytes", help=option_help("pii_max_bytes"))
            st.number_input("규칙별 최대 저장 샘플 수", min_value=1, max_value=100, key="pii_max_matches", help=option_help("pii_max_matches"))
        with pc2:
            st.number_input("PII 대상 최대 파일 크기 (KB)", min_value=1, max_value=102400, key="pii_max_size_kb", help=option_help("pii_max_size_kb"))
        st.text_area(
            "PII 스캔 대상 확장자 (--pii-ext)",
            key="pii_exts",
            help=option_help("pii_exts"),
            height=120,
        )
        st.checkbox("PII 마스킹 (--pii-mask)", key="pii_mask", help=option_help("pii_mask"))
        st.checkbox("마스킹된 샘플 저장 (--pii-store-sample)", key="pii_store_sample", help=option_help("pii_store_sample"))
        st.checkbox("문맥 키워드 분석 (--pii-context-keywords)", key="pii_context_keywords", help=option_help("pii_context_keywords"))

    st.text_area(
        "제외 경로 (--exclude)",
        key="excludes_text",
        help=option_help("excludes_text"),
        height=120,
    )
    st.text_input("리포트 저장 경로 (--out)", key="output_path", help=option_help("output_path"))

    with st.expander("Kafka 연계 설정"):
        st.checkbox("Kafka 전송 사용 (--kafka-enabled)", key="kafka_enabled", help=option_help("kafka_enabled"))
        if st.session_state.get("kafka_enabled"):
            st.text_input("브로커 목록 (--kafka-brokers)", key="kafka_brokers", placeholder="broker1:9092,broker2:9092", help=option_help("kafka_brokers"))
            st.text_input("토픽 (--kafka-topic)", key="kafka_topic", placeholder="dmz.scan.findings", help=option_help("kafka_topic"))
            st.text_input("클라이언트 ID (--kafka-client-id)", key="kafka_client_id", help=option_help("kafka_client_id"))
            st.checkbox("TLS 사용 (--kafka-tls)", key="kafka_tls", help=option_help("kafka_tls"))
            st.checkbox("SASL 사용 (--kafka-sasl-enabled)", key="kafka_sasl_enabled", help=option_help("kafka_sasl_enabled"))
            st.text_input("사용자명 (--kafka-username)", key="kafka_username", help=option_help("kafka_username"))
            st.text_input("비밀번호 환경변수명 (--kafka-password-env)", key="kafka_password_env", help=option_help("kafka_password_env"))
            st.checkbox("민감정보 마스킹 (--kafka-mask-sensitive)", key="kafka_mask_sensitive", help=option_help("kafka_mask_sensitive"))

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

    st.markdown("#### YAML Preview")
    if yaml is None:
        st.warning("PyYAML is not installed. Install it with `pip install pyyaml` to preview or download YAML config files.")
    else:
        yaml_text = yaml.safe_dump(config_payload, allow_unicode=True, sort_keys=False)
        st.code(yaml_text, language="yaml")

        st.download_button(
            "Download YAML",
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

