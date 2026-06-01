from __future__ import annotations

import os
from pathlib import Path


def clean_path(path: str) -> str:
    # Why try to avoid: Path("[heap]").resolve() == PosixPath('/home/user/<cwd>/[heap]')
    # FIXME: This is quite flaky and should be standardized in the codebase, see #3641 .
    if path.startswith("/proc/") and "/root/" in path:
        return os.path.normpath(path)
    if not (path.startswith("target:") or path.startswith("[")):
        return str(Path(path).resolve())
    return str(Path(path))
