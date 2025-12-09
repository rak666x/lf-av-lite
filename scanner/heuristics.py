import math
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from .utils import has_double_extension
from .filetype_checks import extension_header_mismatch


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".dll", ".jar"
}

# Extensions commonly used in masquerading chains
""
BENIGN_DOC_LIKE = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf"
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for c in freq:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return ent


def file_entropy(path: Path, max_bytes: int = 1024 * 1024) -> Optional[float]:
    """
    Compute entropy over up to max_bytes for speed.
    """
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return shannon_entropy(data)
    except Exception:
        return None


def hidden_like_name_score(name: str) -> Tuple[int, List[str]]:
    """
    Very simple, explainable naming checks.
    """
    reasons = []
    score = 0
    lower = name.lower()

    # Lots of dots can be suspicious
    dot_count = lower.count(".")
    if dot_count >= 3:
        score += 8
        reasons.append("Unusually many dots in filename.")

    # Leading/trailing whitespace
    if name != name.strip():
        score += 10
        reasons.append("Filename has leading/trailing whitespace.")

    # Common "urgency" bait terms (lightweight, non-judgmental)
    bait_terms = ("invoice", "urgent", "payment", "security", "update", "scan", "statement")
    if any(t in lower for t in bait_terms) and any(ext in lower for ext in (".exe", ".scr", ".js", ".vbs", ".ps1", ".bat")):
        score += 6
        reasons.append("Filename contains common lure terms combined with a script/executable extension.")

    return score, reasons


def double_extension_score(filename: str, ext: str) -> Tuple[int, List[str]]:
    reasons = []
    score = 0
    lower = filename.lower()

    if has_double_extension(filename):
        # Look for doc-like + executable pattern anywhere in chain
        parts = lower.split(".")
        # rebuild extensions list ignoring base name
        exts = ["." + p for p in parts[1:]]
        if any(e in BENIGN_DOC_LIKE for e in exts) and any(e in SUSPICIOUS_EXTENSIONS for e in exts):
            score += 25
            reasons.append("Possible double-extension masquerading (e.g., document name ending with executable/script).")
        else:
            score += 12
            reasons.append("Multiple extensions detected (could be masquerading).")

    return score, reasons


def suspicious_extension_score(ext: str) -> Tuple[int, List[str]]:
    if ext in SUSPICIOUS_EXTENSIONS:
        return 12, [f"Suspicious or high-risk extension: {ext}."]
    return 0, []


def header_mismatch_score(path: Path) -> Tuple[int, List[str]]:
    mismatch, expected, actual = extension_header_mismatch(path)
    if mismatch:
        return 30, [f"Extension/header mismatch: expected {expected}, found {actual}."]
    return 0, []


def entropy_score(path: Path, threshold: float = 7.2) -> Tuple[int, List[str]]:
    """
    Entropy threshold is intentionally conservative and explainable.
    High entropy can indicate packing/encryption/obfuscation.
    """
    ent = file_entropy(path)
    if ent is None:
        return 0, []

    if ent >= threshold:
        return 18, [f"High entropy ({ent:.2f}) may indicate packing or obfuscation."]
    return 0, []


def evaluate_heuristics(path: Path, enable_entropy: bool = True) -> Dict:
    """
    Returns:
      {
        "risk_score": int,
        "reasons": [...],
        "signals": {...}
      }
    """
    reasons: List[str] = []
    score = 0

    filename = path.name
    ext = path.suffix.lower()

    s, r = suspicious_extension_score(ext)
    score += s
    reasons += r

    s, r = double_extension_score(filename, ext)
    score += s
    reasons += r

    s, r = hidden_like_name_score(filename)
    score += s
    reasons += r

    s, r = header_mismatch_score(path)
    score += s
    reasons += r

    ent_val = None
    if enable_entropy:
        s, r = entropy_score(path)
        score += s
        reasons += r
        # recompute once for reporting if needed
        ent_val = file_entropy(path)

    # Cap at 99 for heuristic-only
    if score > 99:
        score = 99

    return {
        "risk_score": score,
        "reasons": reasons,
        "signals": {
            "extension": ext,
            "entropy": ent_val
        }
    }
