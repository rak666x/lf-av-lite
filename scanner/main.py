import argparse
import json
from pathlib import Path
from typing import Dict, List

from .utils import (
    iso_now, bool_from_str, normalize_storage,
    safe_is_file, safe_is_dir, iter_files_in_dir, is_text_like_extension
)
from .hashing import sha256_file
from .heuristics import evaluate_heuristics
from .signatures import load_signatures, update_signatures_from_file, extract_sha256_set
from .history_json import append_history as append_history_json, read_history as read_history_json
from .history_sqlite import append_history as append_history_sqlite, read_history as read_history_sqlite


EICAR_STR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def detect_eicar(path: Path) -> bool:
    """
    Detect EICAR test string in a safe, read-only way.
    We scan small-to-moderate text-like files.
    """
    try:
        # Guard by extension AND size for safety/perf
        if not is_text_like_extension(path.suffix.lower()):
            return False

        size = path.stat().st_size
        if size > 5 * 1024 * 1024:
            return False

        with path.open("rb") as f:
            data = f.read()
        return EICAR_STR in data
    except Exception:
        return False


def build_result_entry(
    path: Path,
    sha256: str,
    status: str,
    risk_score: int,
    reasons: List[str]
) -> Dict:
    return {
        "path": str(path),
        "sha256": sha256 or "",
        "status": status,
        "risk_score": int(risk_score),
        "reasons": reasons or []
    }


def scan_one_file(path: Path, heuristics_enabled: bool, sig_set) -> Dict:
    reasons: List[str] = []

    # Hash
    sha = sha256_file(path)
    if sha is None:
        return build_result_entry(
            path, "",
            "heuristic_flag",
            10,
            ["Could not read file (permission or access issue)."]
        )

    # EICAR test
    if detect_eicar(path):
        return build_result_entry(
            path, sha,
            "eicar_test",
            90,
            ["EICAR test string detected (harmless test signature)."]
        )

    # Signature match
    if sha.lower() in sig_set:
        return build_result_entry(
            path, sha,
            "signature_match",
            100,
            ["Offline signature match (educational signature set)."]
        )

    # Heuristics
    if heuristics_enabled:
        h = evaluate_heuristics(path, enable_entropy=True)
        score = h.get("risk_score", 0)
        reasons = h.get("reasons", []) or []

        if score >= 25:
            return build_result_entry(
                path, sha,
                "heuristic_flag",
                score,
                reasons
            )

    # Clean
    return build_result_entry(
        path, sha,
        "clean",
        0,
        []
    )


def persist_history(storage: str, record: Dict) -> None:
    if storage == "sqlite":
        append_history_sqlite(record)
    else:
        append_history_json(record)


def read_history(storage: str):
    if storage == "sqlite":
        return read_history_sqlite()
    return read_history_json()


def scan_target_file(path: Path, heuristics_enabled: bool, storage: str) -> Dict:
    sig_obj = load_signatures()
    sig_set = extract_sha256_set(sig_obj)

    results: List[Dict] = []

    entry = scan_one_file(path, heuristics_enabled, sig_set)
    results.append(entry)

    flagged = sum(1 for r in results if r.get("status") != "clean")

    report = {
        "timestamp": iso_now(),
        "target": str(path),
        "mode": "file",
        "heuristics_enabled": heuristics_enabled,
        "storage": storage,
        "summary": {
            "files_scanned": 1,
            "flagged": flagged
        },
        "results": results
    }

    persist_history(storage, report)
    return report


def scan_target_dir(path: Path, recursive: bool, heuristics_enabled: bool, storage: str) -> Dict:
    sig_obj = load_signatures()
    sig_set = extract_sha256_set(sig_obj)

    results: List[Dict] = []
    files_scanned = 0

    for f in iter_files_in_dir(path, recursive=recursive):
        files_scanned += 1
        results.append(scan_one_file(f, heuristics_enabled, sig_set))

    flagged = sum(1 for r in results if r.get("status") != "clean")

    report = {
        "timestamp": iso_now(),
        "target": str(path),
        "mode": "directory",
        "heuristics_enabled": heuristics_enabled,
        "storage": storage,
        "summary": {
            "files_scanned": files_scanned,
            "flagged": flagged
        },
        "results": results
    }

    persist_history(storage, report)
    return report


def json_ok(payload: Dict) -> None:
    print(json.dumps(payload, ensure_ascii=False))


def json_error(message: str, code: str = "error", extra: Dict = None) -> None:
    out = {"error": {"code": code, "message": message}}
    if extra:
        out["error"].update(extra)
    print(json.dumps(out, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(prog="av-lite-scanner", add_help=True)
    sub = parser.add_subparsers(dest="cmd")

    p_file = sub.add_parser("scan-file", help="Scan a single file")
    p_file.add_argument("--path", required=True)
    p_file.add_argument("--heuristics", default="true")
    p_file.add_argument("--storage", default="json")

    p_dir = sub.add_parser("scan-dir", help="Scan a directory")
    p_dir.add_argument("--path", required=True)
    p_dir.add_argument("--recursive", default="true")
    p_dir.add_argument("--heuristics", default="true")
    p_dir.add_argument("--storage", default="json")

    p_up = sub.add_parser("update-signatures", help="Offline signature update")
    p_up.add_argument("--file", required=True)

    p_hist = sub.add_parser("history", help="Read scan history")
    p_hist.add_argument("--storage", default="json")

    args = parser.parse_args()

    try:
        if args.cmd == "scan-file":
            target = Path(args.path).expanduser()

            if not safe_is_file(target):
                json_error("Target path is not a readable file.", code="invalid_target")
                raise SystemExit(2)

            heur = bool_from_str(args.heuristics, default=True)
            storage = normalize_storage(args.storage)

            report = scan_target_file(target, heur, storage)
            json_ok(report)
            return

        if args.cmd == "scan-dir":
            target = Path(args.path).expanduser()

            if not safe_is_dir(target):
                json_error("Target path is not a readable directory.", code="invalid_target")
                raise SystemExit(2)

            recursive = bool_from_str(args.recursive, default=True)
            heur = bool_from_str(args.heuristics, default=True)
            storage = normalize_storage(args.storage)

            report = scan_target_dir(target, recursive, heur, storage)
            json_ok(report)
            return

        if args.cmd == "update-signatures":
            local = Path(args.file).expanduser()

            if not safe_is_file(local):
                json_error("Signature update file does not exist or is not a file.", code="invalid_signature_file")
                raise SystemExit(2)

            details = update_signatures_from_file(local)
            json_ok({
                "status": "ok",
                "details": f"Added {details['added']} hashes. Total now {details['total']}.",
                "meta": details
            })
            return

        if args.cmd == "history":
            storage = normalize_storage(args.storage)
            h = read_history(storage)
            json_ok({
                "status": "ok",
                "storage": storage,
                "history": h
            })
            return

        parser.print_help()

    except ValueError as ve:
        json_error(str(ve), code="validation_error")
        raise SystemExit(2)
    except PermissionError:
        json_error("Permission error while accessing files.", code="permission_error")
        raise SystemExit(3)
    except FileNotFoundError:
        json_error("File not found.", code="not_found")
        raise SystemExit(2)
    except Exception as e:
        json_error("Unexpected error occurred.", code="unexpected", extra={"detail": str(e)})
        raise SystemExit(1)


if __name__ == "__main__":
    main()
