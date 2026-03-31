import json
from pathlib import Path

import streamlit as st

st.set_page_config(
    page_title="DMZ 웹루트 스캐너 도우미",
    page_icon="🛡️",
    layout="wide",
)

st.set_page_config(
    page_title="DMZ 웹루트 스캐너 도우미",
    page_icon="🛡️",
    layout="wide",
)

st.title("DMZ 웹루트 스캐너 사용 도우미")
st.caption("Detect Bot 사용과 분석 결과 해석을 돕는 Streamlit 페이지")

with st.sidebar:
    st.header("바로가기")
    st.page_link("pages/scenario_generator.py", label="시나리오 기반 설정기")
    st.page_link("pages/option_generator.py", label="옵션 생성기")
    st.page_link("pages/report_parser.py", label="JSON 리포트 해석기")

st.markdown("## 개요")
st.write(
    "이 화면은 Detect Bot의 실행 옵션을 만들고, "
    "스캔 결과 JSON을 해석하는 보조 UI입니다."
)

col1, col2 = st.columns(2)

with col1:
    st.markdown("### 1. 사용 흐름")
    st.markdown(
        """
        1. 웹서버 유형 선택
        2. 스캔 옵션 생성
        3. CLI에서 스캔 실행
        4. 결과 JSON 업로드
        5. findings / severity / reasons 확인
        """
    )

with col2:
    st.markdown("### 2. 주요 기능")
    st.markdown(
        """
        - 웹서빙 경로(root/alias/DocumentRoot) 기반 점검
        - 허용 MIME/확장자 위반 탐지
        - 고위험 확장자 탐지
        - 대용량 파일 탐지
        - 텍스트 기반 설정파일 내 민감정보/PII 탐지
        - 표준 JSON 결과 해석
        """
    )

st.markdown("## 빠른 시작 예시")

tab1, tab2, tab3 = st.tabs(["Nginx", "Apache", "JSON 결과"])

with tab1:
    st.code(
        """nginx -T 2>&1 | ./detectbot \
  --nginx-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --out /var/log/detectbot/report.json""",
        language="bash",
    )

with tab2:
    st.code(
        """apachectl -S 2>&1 | ./detectbot \
  --apache-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --out /var/log/detectbot/report.json""",
        language="bash",
    )

with tab3:
    uploaded = st.file_uploader("결과 JSON 업로드", type=["json"])
    if uploaded is not None:
        try:
            data = json.load(uploaded)
            st.success("JSON 로드 완료")
            st.write("roots 개수:", len(data.get("roots", [])))
            st.write("findings 개수:", len(data.get("findings", [])))
            st.write("stats:", data.get("stats", {}))
        except Exception as e:
            st.error(f"JSON 파싱 실패: {e}")

st.markdown("## 주의사항")
st.info(
    "MIME 판별은 sniff 기반이므로 100% 정확하지 않을 수 있습니다. "
    "Apache 환경은 dump 출력에 따라 roots 추출이 제한될 수 있습니다."
)
