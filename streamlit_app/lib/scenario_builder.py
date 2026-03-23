"""
Scenario-driven configuration helpers for the Streamlit wizard UI.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path

from lib.constants import (
    DEFAULT_ALLOW_EXTS,
    DEFAULT_ALLOW_MIME_PREFIXES,
    DEFAULT_CONTENT_EXTS,
    DEFAULT_PII_EXTS,
)
from lib.utils import non_empty_lines


SAFE_OUTPUT_PATH = "/tmp/dmz_webroot_scan_report.json"
SCENARIO_PRESET_FILE = Path(__file__).resolve().parents[1] / "data" / "scenario_presets.json"

DEFAULT_EXCLUDES = [
    "/var/cache",
    "/tmp",
    "/var/tmp",
    "node_modules",
]

STATIC_ASSET_EXTS = [
    ".html", ".htm", ".css", ".js", ".mjs",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
]

STATIC_ASSET_MIME_PREFIXES = [
    "text/html",
    "text/css",
    "application/javascript",
    "text/javascript",
    "image/",
    "font/",
    "application/font-",
]

CONFIG_SENSITIVE_EXTS = [
    ".env", ".yaml", ".yml", ".json", ".xml", ".properties",
    ".conf", ".ini", ".txt", ".config", ".cfg", ".toml",
]

PII_FOCUSED_EXTS = [
    ".yaml", ".yml", ".json", ".xml", ".properties", ".conf",
    ".ini", ".txt", ".log", ".csv", ".tsv",
]

INTENSITY_PROFILES = {
    "safe": {
        "label": "안전 점검",
        "description": "운영 영향 최소화가 필요한 일상 점검용입니다.",
        "load": "낮음",
        "defaults": {
            "newer_than_h": 24,
            "max_depth": 6,
            "workers": 2,
            "hash_enabled": False,
            "content_max_bytes": 32768,
            "content_max_size_kb": 256,
            "pii_max_bytes": 32768,
            "pii_max_size_kb": 128,
            "pii_max_matches": 3,
            "max_size_mb": 80,
        },
    },
    "balanced": {
        "label": "균형 점검",
        "description": "정기 점검에 적합한 기본 강도입니다.",
        "load": "보통",
        "defaults": {
            "newer_than_h": 72,
            "max_depth": 10,
            "workers": 4,
            "hash_enabled": False,
            "content_max_bytes": 65536,
            "content_max_size_kb": 1024,
            "pii_max_bytes": 65536,
            "pii_max_size_kb": 256,
            "pii_max_matches": 5,
            "max_size_mb": 100,
        },
    },
    "deep": {
        "label": "정밀 점검",
        "description": "사고 의심 시 범위를 넓혀 확인하는 강도입니다.",
        "load": "높음",
        "defaults": {
            "newer_than_h": 168,
            "max_depth": 18,
            "workers": 6,
            "hash_enabled": True,
            "content_max_bytes": 131072,
            "content_max_size_kb": 2048,
            "pii_max_bytes": 131072,
            "pii_max_size_kb": 512,
            "pii_max_matches": 10,
            "max_size_mb": 150,
        },
    },
}

SCENARIOS = {
    "staging": {
        "label": "반출용 스테이징 파일 점검",
        "summary": "웹루트나 업로드 경로에 임시 적재된 대용량·아카이브·비허용 파일을 찾습니다.",
        "recommended_for": "업로드 서버, 반출 의심, 대용량 적재 흔적 확인",
        "risk_focus": "신규 생성 파일, 대용량 파일, 아카이브, 허용 목록 밖 확장자/MIME, 확장자-MIME 불일치",
        "why": "웹서비스 경로에 업무용 산출물이나 반출 대기 파일이 머무르면 외부 노출과 유출 위험이 커집니다.",
        "load": "보통",
    },
    "residual": {
        "label": "로그/덤프/임시파일 잔존 점검",
        "summary": "운영 중 남아 있는 log, dump, trace, core, bak, tmp 계열 파일을 우선 확인합니다.",
        "recommended_for": "운영 서버 정기 점검, 장애 이후 정리 누락 확인",
        "risk_focus": "최근 변경 파일, 비허용 확장자, 임시 산출물 잔존 여부",
        "why": "장애 분석이나 배포 과정에서 생긴 임시 파일은 내부 정보 노출과 공격 표면 확대의 원인이 됩니다.",
        "load": "낮음",
    },
    "exports": {
        "label": "운영 추출본/배치 산출물 잔존 점검",
        "summary": "csv, sql, xlsx, json, txt 같은 업무 산출물이 웹 경로 아래 남아 있는지 봅니다.",
        "recommended_for": "배치 서버, 자료 추출 업무, 외부 반출 전 검토",
        "risk_focus": "배치 결과물, 보고서 추출본, 데이터 덤프, 텍스트 산출물",
        "why": "운영 산출물이 웹루트 하위에 잔존하면 직접 다운로드나 인덱싱을 통한 노출로 이어질 수 있습니다.",
        "load": "보통",
    },
    "secrets": {
        "label": "설정파일/키/토큰 노출 위험 점검",
        "summary": "설정 파일 자체와 본문 내 계정·토큰·내부 접속 정보를 함께 점검합니다.",
        "recommended_for": "설정 이관 직후, 배포 검증, 보안 점검",
        "risk_focus": ".env, yaml, json, xml, properties, conf, ini, txt 및 본문 내 비밀정보 패턴",
        "why": "노출된 설정 파일은 서비스 계정과 내부 연결 정보를 한 번에 드러낼 수 있어 피해 범위가 큽니다.",
        "load": "보통",
    },
    "integrated": {
        "label": "전체 통합 점검",
        "summary": "반출 징후, 잔존 파일, 설정 노출 위험을 균형 있게 묶은 기본 프리셋입니다.",
        "recommended_for": "정기 종합 점검, 서버 인수인계 전 점검",
        "risk_focus": "허용 목록 위반, 고위험 확장자, 대용량 파일, 민감정보 패턴",
        "why": "운영 부담을 통제하면서도 주요 리스크를 폭넓게 확인할 수 있는 기본 시나리오입니다.",
        "load": "보통",
    },
}

RECOMMENDED_PACKS = {
    "safe_check": {
        "label": "안전 점검",
        "subtitle": "일상 운영 서버를 빠르게 확인할 때",
        "scenarios": ["residual", "integrated"],
        "intensity": "safe",
    },
    "exfil_signs": {
        "label": "반출 징후 점검",
        "subtitle": "업로드/웹루트의 적재 파일을 우선 보고 싶을 때",
        "scenarios": ["staging"],
        "intensity": "balanced",
    },
    "config_exposure": {
        "label": "설정정보 노출 점검",
        "subtitle": "설정파일, 키, 토큰 노출 위험을 중점 확인할 때",
        "scenarios": ["secrets"],
        "intensity": "balanced",
    },
    "incident_deep": {
        "label": "사고 대응/정밀 점검",
        "subtitle": "사고 의심 상황에서 범위를 넓혀 확인할 때",
        "scenarios": ["staging", "residual", "secrets"],
        "intensity": "deep",
    },
}


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _remove_items(base: list[str], targets: list[str]) -> list[str]:
    target_set = {item.lower() for item in targets}
    return [item for item in base if item.lower() not in target_set]


def default_config() -> dict:
    return {
        "preset": "",
        "purpose": "시나리오 기반 점검",
        "server_type": "nginx",
        "nginx_input_mode": "파일 경로",
        "nginx_dump_path": "",
        "apache_input_mode": "파일 경로",
        "apache_dump_path": "",
        "watch_dirs": [],
        "newer_than_h": 72,
        "max_depth": 10,
        "workers": 4,
        "follow_symlink": False,
        "max_size_mb": 100,
        "hash_enabled": False,
        "allow_mime_prefixes": list(DEFAULT_ALLOW_MIME_PREFIXES),
        "allow_exts": list(DEFAULT_ALLOW_EXTS),
        "enable_rules": [],
        "disable_rules": [],
        "content_scan": False,
        "content_max_bytes": 65536,
        "content_max_size_kb": 1024,
        "content_exts": list(DEFAULT_CONTENT_EXTS),
        "pii_scan": False,
        "pii_max_bytes": 65536,
        "pii_max_size_kb": 256,
        "pii_max_matches": 5,
        "pii_exts": list(DEFAULT_PII_EXTS),
        "pii_mask": True,
        "pii_store_sample": True,
        "pii_context_keywords": True,
        "excludes": list(DEFAULT_EXCLUDES),
        "output_path": SAFE_OUTPUT_PATH,
        "kafka_enabled": False,
        "kafka_brokers": "",
        "kafka_topic": "",
        "kafka_client_id": "dmz_webroot_scanner",
        "kafka_tls": False,
        "kafka_sasl_enabled": False,
        "kafka_username": "",
        "kafka_password_env": "",
        "kafka_mask_sensitive": True,
    }


def build_scenario_config(
    selected_scenarios: list[str],
    intensity: str,
    server_type: str,
    nginx_mode: str,
    nginx_dump_path: str,
    apache_mode: str,
    apache_dump_path: str,
    extra_watch_dirs_text: str,
    selected_candidates: list[str],
    unselected_candidates: list[str],
    output_path: str,
) -> dict:
    config = default_config()
    intensity_key = intensity if intensity in INTENSITY_PROFILES else "balanced"
    config.update(deepcopy(INTENSITY_PROFILES[intensity_key]["defaults"]))

    config["server_type"] = server_type
    config["nginx_input_mode"] = nginx_mode
    config["nginx_dump_path"] = nginx_dump_path.strip()
    config["apache_input_mode"] = apache_mode
    config["apache_dump_path"] = apache_dump_path.strip()
    config["output_path"] = output_path.strip() or SAFE_OUTPUT_PATH

    watch_dirs = list(selected_candidates) if server_type == "manual" else []
    watch_dirs.extend(non_empty_lines(extra_watch_dirs_text))
    config["watch_dirs"] = _dedupe(watch_dirs)
    config["excludes"] = _dedupe(config["excludes"] + list(unselected_candidates))

    active = _dedupe(selected_scenarios) or ["integrated"]
    for scenario_id in active:
        _apply_scenario(config, scenario_id, intensity_key)

    if server_type == "manual":
        config["nginx_dump_path"] = ""
        config["apache_dump_path"] = ""
    elif server_type == "nginx":
        config["apache_dump_path"] = ""
    elif server_type == "apache":
        config["nginx_dump_path"] = ""

    return config


def _apply_scenario(config: dict, scenario_id: str, intensity: str) -> None:
    if scenario_id == "staging":
        config["content_scan"] = config["content_scan"] or intensity == "deep"
        config["hash_enabled"] = config["hash_enabled"] or intensity == "deep"
        config["max_size_mb"] = max(config["max_size_mb"], 120 if intensity == "deep" else 100)
    elif scenario_id == "residual":
        config["newer_than_h"] = min(config["newer_than_h"], 72 if intensity != "deep" else 168)
        config["allow_exts"] = _remove_items(config["allow_exts"], [".map"])
    elif scenario_id == "exports":
        config["allow_exts"] = list(STATIC_ASSET_EXTS)
        config["allow_mime_prefixes"] = list(STATIC_ASSET_MIME_PREFIXES)
        config["content_scan"] = config["content_scan"] or intensity == "deep"
    elif scenario_id == "secrets":
        config["allow_exts"] = list(STATIC_ASSET_EXTS)
        config["allow_mime_prefixes"] = list(STATIC_ASSET_MIME_PREFIXES)
        config["content_scan"] = True
        config["content_exts"] = list(CONFIG_SENSITIVE_EXTS)
        if intensity == "deep":
            config["pii_scan"] = True
            config["pii_exts"] = list(PII_FOCUSED_EXTS)
    elif scenario_id == "integrated":
        config["content_scan"] = True
        if intensity == "deep":
            config["pii_scan"] = True
            config["pii_exts"] = list(PII_FOCUSED_EXTS)


def parse_auto_extracted_paths(server_type: str, dump_path: str) -> list[dict]:
    path = dump_path.strip()
    if server_type not in {"nginx", "apache"} or not path:
        return []

    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return []

    text = file_path.read_text(encoding="utf-8", errors="ignore")
    if server_type == "nginx":
        return _parse_nginx_dump(text)
    return _parse_apache_dump(text)


def _parse_nginx_dump(text: str) -> list[dict]:
    candidates = []
    server_name = ""
    file_hint = ""
    root_re = re.compile(r"^\s*(root|alias)\s+([^;#]+);", re.IGNORECASE)
    file_re = re.compile(r"^#\s*configuration\s+file\s+(.+?):(\d+)", re.IGNORECASE)
    server_re = re.compile(r"^\s*server_name\s+([^;#]+);", re.IGNORECASE)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        file_match = file_re.match(line)
        if file_match:
            file_hint = f"{file_match.group(1).strip()}:{file_match.group(2)}"
            continue

        server_match = server_re.match(line)
        if server_match:
            server_name = server_match.group(1).strip()
            continue

        root_match = root_re.match(line)
        if not root_match:
            continue

        hint_parts = [root_match.group(1).lower()]
        if server_name:
            hint_parts.append(f"server_name={server_name}")
        if file_hint:
            hint_parts.append(file_hint)

        candidates.append(
            {
                "path": root_match.group(2).strip().strip('"').strip("'"),
                "source": f"nginx {root_match.group(1).lower()}",
                "hint": " | ".join(hint_parts),
            }
        )

    return _dedupe_candidate_rows(candidates)


def _parse_apache_dump(text: str) -> list[dict]:
    candidates = []
    document_root_re = re.compile(r'\bDocumentRoot\s+"?([^"\r\n]+)"?', re.IGNORECASE)
    for match in document_root_re.finditer(text):
        candidates.append(
            {
                "path": match.group(1).strip().strip('"').strip("'"),
                "source": "apache documentroot",
                "hint": "apachectl -S dump",
            }
        )
    return _dedupe_candidate_rows(candidates)


def _dedupe_candidate_rows(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for row in rows:
        path = row["path"].strip()
        if not path or path in seen:
            continue
        seen.add(path)
        out.append({"path": path, "source": row["source"], "hint": row["hint"]})
    return out


def summarize_rules(config: dict, selected_scenarios: list[str]) -> list[str]:
    summaries = []
    active = _dedupe(selected_scenarios) or ["integrated"]

    if any(s in active for s in ["staging", "residual", "exports", "integrated"]):
        summaries.append("허용 목록 밖 확장자와 MIME 유형을 우선 식별합니다.")
        summaries.append("고위험 확장자와 확장자-MIME 불일치 파일을 함께 점검합니다.")

    if any(s in active for s in ["staging", "integrated"]):
        summaries.append("웹 경로 아래 대용량 파일을 스테이징 징후로 확인합니다.")

    if "exports" in active:
        summaries.append("웹 자산형 허용 목록을 적용해 csv/json/sql/txt/xlsx 잔존 여부를 민감하게 봅니다.")

    if config.get("content_scan"):
        summaries.append("설정 파일 본문에서 계정, 토큰, 내부 접속정보 패턴을 추가 점검합니다.")

    if config.get("pii_scan"):
        summaries.append("텍스트 기반 파일에서 개인정보 패턴도 함께 확인합니다.")

    if config.get("hash_enabled"):
        summaries.append("의심 파일에 대해 SHA-256 계산을 포함해 증적성을 높입니다.")

    return summaries


def summarize_scope(
    config: dict,
    auto_candidates: list[dict],
    selected_candidates: list[str],
    unselected_candidates: list[str],
) -> list[str]:
    scope = []
    if config["server_type"] == "manual":
        scope.append(f"수동 지정 경로 {len(config['watch_dirs'])}개를 직접 점검합니다.")
    else:
        scope.append(f"{config['server_type']} 설정 기반 자동 추출 후보 {len(auto_candidates)}개를 기준으로 합니다.")
        if selected_candidates:
            scope.append(f"검토 후 유지한 자동 추출 경로는 {len(selected_candidates)}개입니다.")
        if unselected_candidates:
            scope.append(f"제외한 자동 추출 후보 {len(unselected_candidates)}개는 --exclude로 차단합니다.")
        if config["watch_dirs"]:
            scope.append(f"추가 수동 점검 경로 {len(config['watch_dirs'])}개를 함께 포함합니다.")

    scope.append(f"최근 {config['newer_than_h']}시간 변경 파일을 우선 보고, 하위 폴더는 {config['max_depth']}단계까지 탐색합니다.")
    return scope


def estimate_load(config: dict) -> tuple[str, str]:
    score = 0
    if config["max_depth"] >= 12:
        score += 1
    if config["newer_than_h"] >= 168 or config["newer_than_h"] == 0:
        score += 1
    if config["hash_enabled"]:
        score += 2
    if config["content_scan"]:
        score += 2
    if config["pii_scan"]:
        score += 2
    if config["workers"] >= 6:
        score += 1

    if score <= 2:
        return "낮음", "최근 변경 파일 중심으로 운영 영향이 비교적 작습니다."
    if score <= 5:
        return "보통", "정기 점검 수준의 범위와 부하입니다."
    return "높음", "본문 스캔과 해시 계산이 포함되어 I/O와 처리 시간이 늘어날 수 있습니다."


def execution_checkpoints(config: dict, server_type: str, selected_candidates: list[str]) -> list[str]:
    checkpoints = []
    if server_type in {"nginx", "apache"} and not selected_candidates:
        checkpoints.append("자동 추출 경로를 검토하지 못했다면 실행 전 실제 웹루트/alias 경로를 한 번 더 확인하세요.")
    if config["content_scan"]:
        checkpoints.append("본문 스캔은 텍스트 기반 파일에만 집중되도록 확장자 범위를 점검하세요.")
    if config["hash_enabled"]:
        checkpoints.append("SHA-256 계산을 켠 경우 대용량 파일이 많은 시간대를 피하는 것이 좋습니다.")
    if not config["output_path"]:
        checkpoints.append("결과 파일 경로가 비어 있지 않은지 확인하세요.")
    if server_type == "manual" and not config["watch_dirs"]:
        checkpoints.append("수동 경로 지정 방식은 최소 1개 이상의 점검 경로가 필요합니다.")
    return checkpoints


def load_saved_presets() -> dict:
    if not SCENARIO_PRESET_FILE.exists():
        return {}
    try:
        return json.loads(SCENARIO_PRESET_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_preset(name: str, payload: dict) -> None:
    name = name.strip()
    if not name:
        return

    presets = load_saved_presets()
    presets[name] = payload
    SCENARIO_PRESET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCENARIO_PRESET_FILE.write_text(
        json.dumps(presets, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def delete_preset(name: str) -> None:
    presets = load_saved_presets()
    if name not in presets:
        return
    presets.pop(name, None)
    SCENARIO_PRESET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCENARIO_PRESET_FILE.write_text(
        json.dumps(presets, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
