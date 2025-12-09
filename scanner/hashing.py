import hashlib
from pathlib import Path
from typing import Optional


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> Optional[str]:
    """
    Compute SHA-256 of a file. Returns hex digest or None on failure.
    """
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        return None
    except Exception:
        return None
