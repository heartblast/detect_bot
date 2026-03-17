"""
Utility functions for DMZ Webroot Scanner Streamlit UI
"""

from datetime import datetime
from copy import deepcopy

def safe_json_load(uploaded_file):
    """Safely load JSON from uploaded file"""
    import json
    try:
        return json.load(uploaded_file)
    except Exception as e:
        import streamlit as st
        st.error(f"JSON 파싱 실패: {e}")
        st.stop()


def normalize_list(value):
    """Normalize value to list"""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def fmt_dt(value):
    """Format datetime string"""
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def fmt_bytes(num):
    """Format bytes to human readable format"""
    if num is None:
        return "-"
    try:
        num = float(num)
    except Exception:
        return str(num)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if num < 1024 or unit == units[-1]:
            return f"{num:,.1f} {unit}"
        num /= 1024
    return f"{num} B"


def severity_rank(sev):
    """Get severity rank for sorting"""
    from lib.constants import SEVERITY_ORDER
    sev = (sev or "unknown").lower()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def non_empty_lines(text: str):
    """Get non-empty lines from text"""
    return [line.strip() for line in text.splitlines() if line.strip()]


def csv_or_lines(text: str):
    """Parse comma-separated or line-separated values"""
    items = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split(",") if p.strip()]
        items.extend(parts)
    return items


def apply_preset(preset_name: str):
    """Apply preset configuration to session state"""
    import streamlit as st
    from lib.presets import PRESETS

    preset = deepcopy(PRESETS[preset_name])
    for key, value in preset.items():
        if isinstance(value, list):
            st.session_state[key] = "\n".join(value)
        else:
            st.session_state[key] = value

    st.session_state.setdefault("nginx_input_mode", "덤프 파일 경로")
    st.session_state.setdefault("apache_input_mode", "덤프 파일 경로")
    st.session_state.setdefault("nginx_dump_path", "")
    st.session_state.setdefault("apache_dump_path", "")
    st.session_state.setdefault("watch_dirs_text", "")


def state_get(key, default):
    """Get value from session state with default"""
    import streamlit as st
    if key not in st.session_state:
        st.session_state[key] = default
    return st.session_state[key]