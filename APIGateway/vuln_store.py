import json
import logging
import os
import re
from pathlib import Path

from opensearchpy.exceptions import NotFoundError, RequestError

logger = logging.getLogger(__name__)

VULN_INDEX = "siem-vuln-scans"

# ── Local file storage ────────────────────────────────────────────────────────
# Primary store: JSON files in a structured folder tree.
# Override root with VULN_STORAGE_PATH env var.
STORAGE_ROOT = Path(os.getenv("VULN_STORAGE_PATH", Path(__file__).parent / "vuln_data"))
_INDEX_FILE  = STORAGE_ROOT / "_index.json"


def _safe(s: str) -> str:
    return re.sub(r'[^\w\-. ]', '_', str(s)).strip() or "_"


def _scan_path(scan: dict) -> Path:
    return (
        STORAGE_ROOT
        / _safe(scan["mfi"])
        / str(scan["year"])
        / scan["quarter"]
        / scan["scan_type"]
        / f"{scan['scan_id']}.json"
    )


def _load_index() -> list:
    if not _INDEX_FILE.exists():
        return []
    try:
        with open(_INDEX_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_index(entries: list) -> None:
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    with open(_INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)


def _to_summary_entry(scan: dict, path: Path) -> dict:
    entry = {k: v for k, v in scan.items() if k not in ("findings", "hosts")}
    entry["storage_path"] = str(path)
    return entry


# ── OpenSearch (best-effort secondary store) ──────────────────────────────────

def _os_ensure_index(client) -> None:
    try:
        if client.indices.exists(index=VULN_INDEX):
            return
        client.indices.create(
            index=VULN_INDEX,
            body={
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "scan_id":     {"type": "keyword"},
                        "mfi":         {"type": "keyword"},
                        "quarter":     {"type": "keyword"},
                        "year":        {"type": "integer"},
                        "scan_type":   {"type": "keyword"},
                        "branch":      {"type": "keyword"},
                        "uploaded_at": {"type": "date"},
                        "filename":    {"type": "keyword"},
                    }
                },
            },
        )
    except Exception as exc:
        logger.warning("OpenSearch index setup skipped: %s", exc)


def _os_save(client, scan: dict) -> None:
    try:
        client.index(index=VULN_INDEX, id=scan["scan_id"], body=scan, refresh=False)
    except Exception as exc:
        logger.warning("OpenSearch save skipped for %s: %s", scan.get("scan_id"), exc)


def _os_delete(client, scan_id: str) -> None:
    try:
        client.delete(index=VULN_INDEX, id=scan_id, refresh="wait_for")
    except Exception as exc:
        logger.warning("OpenSearch delete skipped for %s: %s", scan_id, exc)


# ── Public API ────────────────────────────────────────────────────────────────

def ensure_index(client) -> None:
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    _os_ensure_index(client)


def save_scan(client, scan: dict) -> None:
    # 1. Write local file (always succeeds)
    path = _scan_path(scan)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=2)

    entry = _to_summary_entry(scan, path)
    index = [e for e in _load_index() if e.get("scan_id") != scan["scan_id"]]
    index.append(entry)
    _save_index(index)

    # 2. Mirror to OpenSearch (best-effort)
    _os_save(client, scan)


def list_scans(client, mfi: str = None) -> list:
    index = _load_index()
    if mfi:
        index = [e for e in index if e.get("mfi") == mfi]
    index.sort(key=lambda e: (
        -e.get("year", 0),
        e.get("quarter", ""),
        e.get("scan_type", ""),
    ))
    return index


def get_scan(client, scan_id: str) -> dict | None:
    entry = next((e for e in _load_index() if e.get("scan_id") == scan_id), None)
    if not entry:
        return None
    path = Path(entry.get("storage_path", ""))
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        scan = json.load(f)
    return {"id": scan["scan_id"], **scan}


def delete_scan(client, scan_id: str) -> bool:
    index = _load_index()
    entry = next((e for e in index if e.get("scan_id") == scan_id), None)
    if not entry:
        return False
    path = Path(entry.get("storage_path", ""))
    if path.exists():
        path.unlink()
    _save_index([e for e in index if e.get("scan_id") != scan_id])
    _os_delete(client, scan_id)
    return True


def update_scan_meta(client, scan_id: str, meta: dict) -> dict | None:
    index = _load_index()
    entry = next((e for e in index if e.get("scan_id") == scan_id), None)
    if not entry:
        return None

    old_path = Path(entry.get("storage_path", ""))
    if not old_path.exists():
        return None

    with open(old_path, "r", encoding="utf-8") as f:
        scan = json.load(f)

    for key in ("mfi", "branch", "quarter", "year", "scan_type"):
        if key in meta and meta[key] is not None:
            scan[key] = meta[key]

    new_path = _scan_path(scan)
    new_path.parent.mkdir(parents=True, exist_ok=True)
    if old_path != new_path:
        old_path.unlink(missing_ok=True)

    with open(new_path, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=2)

    new_entry = _to_summary_entry(scan, new_path)
    _save_index([e for e in index if e.get("scan_id") != scan_id] + [new_entry])

    _os_save(client, scan)
    return new_entry


def get_scans_for_report(client, mfi: str, year: int, quarter: str) -> list:
    matching = [
        e for e in _load_index()
        if e.get("mfi") == mfi and e.get("year") == year and e.get("quarter") == quarter
    ]
    scans = []
    for entry in matching:
        path = Path(entry.get("storage_path", ""))
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                scans.append(json.load(f))
    return scans


def get_trends(client) -> list:
    return [
        {
            "mfi":       e["mfi"],
            "quarter":   e["quarter"],
            "year":      e["year"],
            "scan_type": e["scan_type"],
            "summary":   e["summary"],
        }
        for e in _load_index()
        if "summary" in e
    ]
