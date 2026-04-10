from __future__ import annotations

import json
from pathlib import Path

from db.schema_init import initialize_schema
from services.policy_service import PolicyService
from services.scan_service import ScanService
from services.server_service import ServerService


SAMPLE_DATASET_PATH = Path(__file__).resolve().parent / "samples" / "demo_seed_dataset.json"


def _load_seed_dataset() -> dict:
    if not SAMPLE_DATASET_PATH.is_file():
        return {"servers": [], "reports": []}
    return json.loads(SAMPLE_DATASET_PATH.read_text(encoding="utf-8"))


def bootstrap_portal(seed_demo_data: bool = True) -> None:
    initialize_schema()
    if not seed_demo_data:
        return

    policy_service = PolicyService()
    server_service = ServerService()
    scan_service = ScanService()

    policy_id = policy_service.ensure_default_policy()
    servers_df = server_service.list_servers_df(active_only=False)
    scan_runs_df = scan_service.list_scan_runs_df(limit=1)
    if not (servers_df is None or servers_df.empty or scan_runs_df.empty):
        return

    dataset = _load_seed_dataset()
    server_id_map: dict[str, str] = {}
    if servers_df is None or servers_df.empty:
        for server_payload in dataset.get("servers", []):
            seed_key = str(server_payload.get("seed_key") or "").strip()
            payload = {key: value for key, value in server_payload.items() if key != "seed_key"}
            server_id = server_service.save_server(payload)
            if seed_key:
                server_id_map[seed_key] = server_id

    if scan_runs_df.empty:
        for report_entry in dataset.get("reports", []):
            seed_key = str(report_entry.get("seed_key") or "").strip()
            server_id = server_id_map.get(seed_key)
            if not server_id:
                continue
            report_payload = dict(report_entry.get("report", {}))
            file_name = str(report_entry.get("file_name") or f"{seed_key}.json")
            scan_service.ingest_report(
                json.dumps(report_payload, ensure_ascii=False).encode("utf-8"),
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
