from pathlib import Path
from typing import Optional, Tuple

# Very lightweight magic-byte checks
MAGIC = {
    "pe": b"MZ",           # Windows PE executables
    "pdf": b"%PDF",
    "zip": b"PK\x03\x04",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "gif": b"GIF8"
}

EXT_EXPECTATIONS = {
    ".exe": "pe",
    ".dll": "pe",
    ".scr": "pe",
    ".sys": "pe",
    ".pdf": "pdf",
    ".zip": "zip",
    ".jar": "zip",
    ".docx": "zip",
    ".xlsx": "zip",
    ".pptx": "zip",
    ".png": "png",
    ".jpg": "jpg",
    ".jpeg": "jpg",
    ".gif": "gif"
}


def read_header(path: Path, size: int = 16) -> Optional[bytes]:
    try:
        with path.open("rb") as f:
            return f.read(size)
    except Exception:
        return None


def detect_magic_type(header: bytes) -> Optional[str]:
    if not header:
        return None

    for t, sig in MAGIC.items():
        if header.startswith(sig):
            return t
    return None


def expected_type_for_extension(ext: str) -> Optional[str]:
    return EXT_EXPECTATIONS.get(ext.lower())


def extension_header_mismatch(path: Path) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Returns (mismatch, expected_type, actual_type)
    """
    ext = path.suffix.lower()
    expected = expected_type_for_extension(ext)
    if not expected:
        return (False, None, None)

    header = read_header(path)
    if header is None:
        return (False, expected, None)

    actual = detect_magic_type(header)
    if actual is None:
        # unknown header doesn't necessarily mean mismatch
        return (False, expected, None)

    return (actual != expected, expected, actual)
