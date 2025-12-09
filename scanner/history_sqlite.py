import sqlite3
import json
from pathlib import Path
from typing import Any, Dict, List

from .utils import get_data_dir


def db_path() -> Path:
    return get_data_dir() / "scan_history.db"


def init_db() -> None:
    p = db_path()
    conn = sqlite3.connect(str(p))
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                heuristics_enabled INTEGER NOT NULL,
                storage TEXT NOT NULL,
                files_scanned INTEGER NOT NULL,
                flagged INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def append_history(record: Dict[str, Any]) -> None:
    init_db()
    p = db_path()
    conn = sqlite3.connect(str(p))
    try:
        cur = conn.cursor()
        summary = record.get("summary", {}) or {}
        cur.execute("""
            INSERT INTO scans (
                timestamp, target, mode, heuristics_enabled, storage,
                files_scanned, flagged, report_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.get("timestamp", ""),
            record.get("target", ""),
            record.get("mode", ""),
            1 if record.get("heuristics_enabled", False) else 0,
            record.get("storage", "sqlite"),
            int(summary.get("files_scanned", 0)),
            int(summary.get("flagged", 0)),
            json.dumps(record)
        ))
        conn.commit()
    finally:
        conn.close()


def read_history() -> List[Dict[str, Any]]:
    init_db()
    p = db_path()
    conn = sqlite3.connect(str(p))
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT report_json
            FROM scans
            ORDER BY id DESC
            LIMIT 200
        """)
        rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for (rj,) in rows:
            try:
                out.append(json.loads(rj))
            except Exception:
                continue
        return out
    finally:
        conn.close()
