import os
from pathlib import Path
from datetime import datetime
from typing import Iterator, Optional, Tuple


def get_base_dir() -> Path:
    # scanner/ is one level down from av-lite/
    return Path(__file__).resolve().parent.parent


def get_data_dir() -> Path:
    d = get_base_dir() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def iso_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def safe_is_file(p: Path) -> bool:
    try:
        return p.is_file()
    except Exception:
        return False


def safe_is_dir(p: Path) -> bool:
    try:
        return p.is_dir()
    except Exception:
        return False


def iter_files_in_dir(
    directory: Path,
    recursive: bool = True
) -> Iterator[Path]:
    """
    Yield files in a directory safely.
    """
    if not safe_is_dir(directory):
        return

    try:
        if recursive:
            for root, _, files in os.walk(directory):
                for f in files:
                    yield Path(root) / f
        else:
            for child in directory.iterdir():
                if safe_is_file(child):
                    yield child
    except PermissionError:
        # caller will handle counting/notes; we just stop iteration here
        return
    except Exception:
        return


def normalize_storage(storage: str) -> str:
    return "sqlite" if str(storage).lower().strip() == "sqlite" else "json"


def bool_from_str(val: str, default: bool = False) -> bool:
    if val is None:
        return default
    v = str(val).lower().strip()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return default


def split_name_extensions(filename: str) -> Tuple[str, str]:
    """
    Returns (stem_lower, ext_lower). ext includes leading dot or ''.
    """
    p = Path(filename)
    return p.stem.lower(), p.suffix.lower()


def has_double_extension(filename: str) -> bool:
    parts = filename.lower().split(".")
    # At least 3 parts means name.ext1.ext2
    return len(parts) >= 3


def is_text_like_extension(ext: str) -> bool:
    return ext.lower() in {
        ".txt", ".md", ".log", ".json", ".xml", ".html", ".htm", ".css",
        ".js", ".vbs", ".ps1", ".bat", ".cmd", ".py", ".csv", ".ini", ".yml", ".yaml"
    }
