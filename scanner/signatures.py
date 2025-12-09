import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

from .utils import get_data_dir


DEFAULT_SIGNATURES = {
    "version": "1.0",
    "updated": "2025-01-01",
    "hashes": {
        "sha256": [
            # Fake/test hashes ONLY (do not correspond to real malware)
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ],
        "notes": "These are fake/test hashes for educational use."
    }
}


def signatures_path() -> Path:
    return get_data_dir() / "signatures.json"


def ensure_default_signatures() -> None:
    p = signatures_path()
    if not p.exists():
        p.write_text(json.dumps(DEFAULT_SIGNATURES, indent=2), encoding="utf8")


def load_signatures() -> Dict:
    ensure_default_signatures()
    p = signatures_path()
    try:
        return json.loads(p.read_text(encoding="utf8"))
    except Exception:
        # If corrupt, restore defaults
        p.write_text(json.dumps(DEFAULT_SIGNATURES, indent=2), encoding="utf8")
        return DEFAULT_SIGNATURES


def extract_sha256_set(sig_obj: Dict) -> Set[str]:
    hashes = sig_obj.get("hashes", {})
    sha_list = hashes.get("sha256", [])
    out = set()
    for h in sha_list:
        if isinstance(h, str) and len(h) == 64:
            out.add(h.lower())
    return out


def validate_signature_schema(obj: Dict) -> Tuple[bool, str]:
    if not isinstance(obj, dict):
        return False, "Signature file root must be an object."

    if "version" not in obj or "updated" not in obj or "hashes" not in obj:
        return False, "Signature file missing required keys: version, updated, hashes."

    hashes = obj.get("hashes")
    if not isinstance(hashes, dict):
        return False, "hashes must be an object."

    sha_list = hashes.get("sha256")
    if sha_list is None or not isinstance(sha_list, list):
        return False, "hashes.sha256 must be a list."

    for h in sha_list:
        if not isinstance(h, str) or len(h) != 64:
            return False, "Each sha256 hash must be a 64-character hex string."

    return True, "ok"


def merge_signatures(existing: Dict, incoming: Dict) -> Dict:
    existing_set = extract_sha256_set(existing)
    incoming_set = extract_sha256_set(incoming)

    merged = sorted(existing_set.union(incoming_set))
    out = {
        "version": str(incoming.get("version", existing.get("version", "1.0"))),
        "updated": str(incoming.get("updated", existing.get("updated", ""))),
        "hashes": {
            "sha256": merged,
            "notes": existing.get("hashes", {}).get("notes", "Educational signature set.")
        }
    }
    # Preserve incoming notes if provided explicitly
    inc_notes = incoming.get("hashes", {}).get("notes")
    if isinstance(inc_notes, str) and inc_notes.strip():
        out["hashes"]["notes"] = inc_notes.strip()

    return out


def update_signatures_from_file(local_path: Path) -> Dict:
    ensure_default_signatures()
    existing = load_signatures()

    raw = local_path.read_text(encoding="utf8")
    incoming = json.loads(raw)

    ok, msg = validate_signature_schema(incoming)
    if not ok:
        raise ValueError(msg)

    merged = merge_signatures(existing, incoming)
    signatures_path().write_text(json.dumps(merged, indent=2), encoding="utf8")

    added = len(extract_sha256_set(merged)) - len(extract_sha256_set(existing))
    return {
        "added": added,
        "total": len(extract_sha256_set(merged)),
        "version": merged.get("version"),
        "updated": merged.get("updated")
    }
