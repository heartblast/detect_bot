"""
Configuration builder functions for DMZ Webroot Scanner
"""

import shlex
from lib.utils import non_empty_lines, csv_or_lines


def build_common_flags_list(config: dict):
    """Build common CLI flags list"""
    flags = [
        "--server-type", config["server_type"],
        "--newer-than-h", str(config["newer_than_h"]),
        "--max-depth", str(config["max_depth"]),
        "--workers", str(config["workers"]),
        "--max-size-mb", str(config["max_size_mb"]),
        "--out", config["output_path"],
    ]

    if config["hash_enabled"]:
        flags.append("--hash")

    if config["follow_symlink"]:
        flags.append("--follow-symlink")

    for item in config["watch_dirs"]:
        flags += ["--watch-dir", item]

    for item in config["excludes"]:
        flags += ["--exclude", item]

    for item in config["allow_mime_prefixes"]:
        flags += ["--allow-mime-prefix", item]

    for item in config["allow_exts"]:
        flags += ["--allow-ext", item]

    for item in config["enable_rules"]:
        flags += ["--enable-rules", item]

    for item in config["disable_rules"]:
        flags += ["--disable-rules", item]

    if config["content_scan"]:
        flags.append("--content-scan")
        flags += ["--content-max-bytes", str(config["content_max_bytes"])]
        flags += ["--content-max-size-kb", str(config["content_max_size_kb"])]
        for item in config["content_exts"]:
            flags += ["--content-ext", item]

    if config["pii_scan"]:
        flags.append("--pii-scan")
        flags += ["--pii-max-bytes", str(config["pii_max_bytes"])]
        flags += ["--pii-max-size-kb", str(config["pii_max_size_kb"])]
        flags += ["--pii-max-matches", str(config["pii_max_matches"])]
        for item in config["pii_exts"]:
            flags += ["--pii-ext", item]
        if config["pii_mask"]:
            flags.append("--pii-mask")
        if config["pii_store_sample"]:
            flags.append("--pii-store-sample")
        if config["pii_context_keywords"]:
            flags.append("--pii-context-keywords")

    if config["kafka_enabled"]:
        flags.append("--kafka-enabled")
        if config["kafka_brokers"]:
            flags += ["--kafka-brokers", config["kafka_brokers"]]
        if config["kafka_topic"]:
            flags += ["--kafka-topic", config["kafka_topic"]]
        if config["kafka_client_id"]:
            flags += ["--kafka-client-id", config["kafka_client_id"]]
        if config["kafka_tls"]:
            flags.append("--kafka-tls")
        if config["kafka_sasl_enabled"]:
            flags.append("--kafka-sasl-enabled")
        if config["kafka_username"]:
            flags += ["--kafka-username", config["kafka_username"]]
        if config["kafka_password_env"]:
            flags += ["--kafka-password-env", config["kafka_password_env"]]
        if config["kafka_mask_sensitive"]:
            flags.append("--kafka-mask-sensitive")

    return flags


def build_common_flags_list_without_server_type(config: dict):
    """Build common flags list without server-type"""
    flags = build_common_flags_list(config)
    if len(flags) >= 2 and flags[0] == "--server-type":
        return flags[2:]
    return flags


def build_command(config: dict) -> str:
    """Build complete CLI command"""
    cmd = ["./dmz_webroot_scanner_linux_amd64_v1_1_2", "--scan"]

    if config["server_type"] == "nginx":
        if config["nginx_input_mode"] == "덤프 파일 경로" and config["nginx_dump_path"]:
            cmd += ["--nginx-dump", config["nginx_dump_path"]]
        elif config["nginx_input_mode"] == "표준입력(pipe) 명령":
            return (
                "nginx -T 2>&1 | ./dmz_webroot_scanner_linux_amd64_v1_1_2 --scan --server-type nginx --nginx-dump - "
                + " ".join(shlex.quote(p) for p in build_common_flags_list_without_server_type(config))
            )
    elif config["server_type"] == "apache":
        if config["apache_input_mode"] == "덤프 파일 경로" and config["apache_dump_path"]:
            cmd += ["--apache-dump", config["apache_dump_path"]]
        elif config["apache_input_mode"] == "표준입력(pipe) 명령":
            return (
                "apachectl -S 2>&1 | ./dmz_webroot_scanner_linux_amd64_v1_1_2 --scan --server-type apache --apache-dump - "
                + " ".join(shlex.quote(p) for p in build_common_flags_list_without_server_type(config))
            )

    cmd += build_common_flags_list_without_server_type(config)
    return " ".join(shlex.quote(part) for part in cmd)


def build_config() -> dict:
    """Build configuration from session state"""
    import streamlit as st

    return {
        "preset": st.session_state.get("preset_name"),
        "purpose": st.session_state.get("purpose"),
        "server_type": st.session_state.get("server_type"),
        "nginx_input_mode": st.session_state.get("nginx_input_mode"),
        "nginx_dump_path": st.session_state.get("nginx_dump_path", ""),
        "apache_input_mode": st.session_state.get("apache_input_mode"),
        "apache_dump_path": st.session_state.get("apache_dump_path", ""),
        "watch_dirs": non_empty_lines(st.session_state.get("watch_dirs_text", "")),
        "newer_than_h": st.session_state.get("newer_than_h"),
        "max_depth": st.session_state.get("max_depth"),
        "workers": st.session_state.get("workers"),
        "follow_symlink": st.session_state.get("follow_symlink"),
        "max_size_mb": st.session_state.get("max_size_mb"),
        "hash_enabled": st.session_state.get("hash_enabled"),
        "allow_mime_prefixes": non_empty_lines(st.session_state.get("allow_mime_prefixes", "")),
        "allow_exts": non_empty_lines(st.session_state.get("allow_exts", "")),
        "enable_rules": csv_or_lines(st.session_state.get("enable_rules_text", "")),
        "disable_rules": csv_or_lines(st.session_state.get("disable_rules_text", "")),
        "content_scan": st.session_state.get("content_scan", False),
        "content_max_bytes": st.session_state.get("content_max_bytes"),
        "content_max_size_kb": st.session_state.get("content_max_size_kb"),
        "content_exts": non_empty_lines(st.session_state.get("content_exts", "")),
        "pii_scan": st.session_state.get("pii_scan", False),
        "pii_max_bytes": st.session_state.get("pii_max_bytes"),
        "pii_max_size_kb": st.session_state.get("pii_max_size_kb"),
        "pii_max_matches": st.session_state.get("pii_max_matches"),
        "pii_exts": non_empty_lines(st.session_state.get("pii_exts", "")),
        "pii_mask": st.session_state.get("pii_mask", False),
        "pii_store_sample": st.session_state.get("pii_store_sample", False),
        "pii_context_keywords": st.session_state.get("pii_context_keywords", False),
        "excludes": non_empty_lines(st.session_state.get("excludes_text", "")),
        "output_path": st.session_state.get("output_path"),
        "kafka_enabled": st.session_state.get("kafka_enabled", False),
        "kafka_brokers": st.session_state.get("kafka_brokers", ""),
        "kafka_topic": st.session_state.get("kafka_topic", ""),
        "kafka_client_id": st.session_state.get("kafka_client_id", ""),
        "kafka_tls": st.session_state.get("kafka_tls", False),
        "kafka_sasl_enabled": st.session_state.get("kafka_sasl_enabled", False),
        "kafka_username": st.session_state.get("kafka_username", ""),
        "kafka_password_env": st.session_state.get("kafka_password_env", ""),
        "kafka_mask_sensitive": st.session_state.get("kafka_mask_sensitive", True),
    }


def build_config_payload(config: dict):
    """Build configuration payload for YAML/JSON export"""
    return {
        "server_type": config["server_type"],
        "scan": True,
        "newer_than_h": config["newer_than_h"],
        "max_depth": config["max_depth"],
        "workers": config["workers"],
        "follow_symlink": config["follow_symlink"],
        "max_size_mb": config["max_size_mb"],
        "hash": config["hash_enabled"],
        "watch_dir": config["watch_dirs"],
        "exclude": config["excludes"],
        "allow_mime_prefix": config["allow_mime_prefixes"],
        "allow_ext": config["allow_exts"],
        "enable_rules": config["enable_rules"],
        "disable_rules": config["disable_rules"],
        "content_scan": config["content_scan"],
        "content_max_bytes": config["content_max_bytes"] if config["content_scan"] else None,
        "content_max_size_kb": config["content_max_size_kb"] if config["content_scan"] else None,
        "content_ext": config["content_exts"] if config["content_scan"] else [],
        "pii_scan": config["pii_scan"],
        "pii_max_bytes": config["pii_max_bytes"] if config["pii_scan"] else None,
        "pii_max_size_kb": config["pii_max_size_kb"] if config["pii_scan"] else None,
        "pii_max_matches": config["pii_max_matches"] if config["pii_scan"] else None,
        "pii_ext": config["pii_exts"] if config["pii_scan"] else [],
        "pii_mask": config["pii_mask"] if config["pii_scan"] else False,
        "pii_store_sample": config["pii_store_sample"] if config["pii_scan"] else False,
        "pii_context_keywords": config["pii_context_keywords"] if config["pii_scan"] else False,
        "out": config["output_path"],
        "kafka": {
            "enabled": config["kafka_enabled"],
            "brokers": [x.strip() for x in config["kafka_brokers"].split(",") if x.strip()],
            "topic": config["kafka_topic"],
            "client_id": config["kafka_client_id"],
            "tls": config["kafka_tls"],
            "sasl_enabled": config["kafka_sasl_enabled"],
            "username": config["kafka_username"],
            "password_env": config["kafka_password_env"],
            "mask_sensitive": config["kafka_mask_sensitive"],
        },
    }