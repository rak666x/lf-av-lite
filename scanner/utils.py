import os
import fnmatch
from pathlib import Path
from datetime import datetime
from typing import Iterator, Optional, Tuple, List


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
    recursive: bool = True,
    excludes: Optional[List[str]] = None
) -> Iterator[Path]:
    if not safe_is_dir(directory):
        return

    # Normalize patterns: to lowercase and / separators
    raw_patterns = excludes or []
    norm_patterns = [
        str(p).replace("\\", "/").lower().rstrip("/")
        for p in raw_patterns
        if str(p).strip()
    ]

    def is_excluded(p: Path) -> bool:
        s = p.as_posix().lower()
        for pat in norm_patterns:
            if not pat:
                continue
            # If pattern has glob chars, use fnmatch
            if any(ch in pat for ch in "*?[]"):
                if fnmatch(s, pat):
                    return True
            else:
                # Treat as prefix: exclude everything under that path
                if s.startswith(pat):
                    return True
        return False

    try:
        if recursive:
            for root, dirs, files in os.walk(directory):
                root_path = Path(root)

                # Optionally prune directories based on exclusions
                dirs[:] = [
                    d for d in dirs
                    if not is_excluded(root_path / d)
                ]

                for f in files:
                    file_path = root_path / f
                    if not safe_is_file(file_path):
                        continue
                    if is_excluded(file_path):
                        continue
                    yield file_path
        else:
            for child in directory.iterdir():
                if not safe_is_file(child):
                    continue
                if is_excluded(child):
                    continue
                yield child
    except PermissionError:
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
