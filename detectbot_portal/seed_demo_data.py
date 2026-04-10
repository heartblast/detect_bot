from __future__ import annotations

import json
from pathlib import Path

from bootstrap import SAMPLE_DATASET_PATH, bootstrap_portal
from services.policy_service import PolicyService
from services.scan_service import ScanService
from services.server_service import ServerService


def _load_dataset() -> dict:
    if not SAMPLE_DATASET_PATH.is_file():
        return {"servers": [], "reports": []}
    return json.loads(SAMPLE_DATASET_PATH.read_text(encoding="utf-8"))


def _ensure_server(server_service: ServerService, payload: dict) -> str:
    hostname = str(payload.get("hostname") or "").strip()
    ip_address = str(payload.get("ip_address") or "").strip()

    existing = server_service.find_server_by_hostname(hostname) if hostname else None
    if existing is None and ip_address:
        existing = server_service.find_server_by_ip_address(ip_address)

    save_payload = {key: value for key, value in payload.items() if key != "seed_key"}
    if existing:
        save_payload["id"] = existing["id"]
    return server_service.save_server(save_payload)


def _existing_scan_keys(scan_service: ScanService) -> set[tuple[str, str]]:
    scans_df = scan_service.list_scan_runs_df(limit=5000)
    if scans_df is None or scans_df.empty:
        return set()
    keys: set[tuple[str, str]] = set()
    for _, row in scans_df.iterrows():
        keys.add((str(row.get("server_id") or ""), str(row.get("file_name") or "")))
    return keys


def main() -> None:
    bootstrap_portal(seed_demo_data=True)

    dataset = _load_dataset()
    server_service = ServerService()
    scan_service = ScanService()
    policy_id = PolicyService().ensure_default_policy()

    server_id_map: dict[str, str] = {}
    for server_payload in dataset.get("servers", []):
        seed_key = str(server_payload.get("seed_key") or "").strip()
        if not seed_key:
            continue
        server_id_map[seed_key] = _ensure_server(server_service, server_payload)

    existing_scan_keys = _existing_scan_keys(scan_service)
    added_scan_runs = 0
    for report_entry in dataset.get("reports", []):
        seed_key = str(report_entry.get("seed_key") or "").strip()
        server_id = server_id_map.get(seed_key, "")
        file_name = str(report_entry.get("file_name") or f"{seed_key}.json")
        if not server_id or (server_id, file_name) in existing_scan_keys:
            continue

        scan_service.ingest_report(
            json.dumps(report_entry.get("report", {}), ensure_ascii=False).encode("utf-8"),
            file_name,
            server_id=server_id,
            policy_id=policy_id,
            input_type=str(report_entry.get("input_type") or "manual_json"),
            uploaded_by=str(report_entry.get("uploaded_by") or "seed"),
            original_path=str(
                report_entry.get("original_path")
                or (Path("samples") / Path(file_name).name).as_posix()
            ),
            auto_create_server=False,
        )
        existing_scan_keys.add((server_id, file_name))
        added_scan_runs += 1

    servers_df = server_service.list_servers_df(active_only=False)
    scans_df = scan_service.list_scan_runs_df(limit=5000)
    print(
        f"Seed complete: servers={len(servers_df)}, scan_runs={len(scans_df)}, "
        f"new_scan_runs={added_scan_runs}"
    )


if __name__ == "__main__":
    main()
