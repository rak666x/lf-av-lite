import json
from pathlib import Path
from typing import Any, Dict, List

from .utils import get_data_dir


def history_path() -> Path:
    return get_data_dir() / "scan_history.json"


def ensure_history_file() -> None:
    p = history_path()
    if not p.exists():
        p.write_text("[]", encoding="utf8")


def read_history() -> List[Dict[str, Any]]:
    ensure_history_file()
    p = history_path()
    try:
        data = json.loads(p.read_text(encoding="utf8"))
        return data if isinstance(data, list) else []
    except Exception:
        p.write_text("[]", encoding="utf8")
        return []


def append_history(record: Dict[str, Any]) -> None:
    ensure_history_file()
    data = read_history()
    data.append(record)
    history_path().write_text(json.dumps(data, indent=2), encoding="utf8")
