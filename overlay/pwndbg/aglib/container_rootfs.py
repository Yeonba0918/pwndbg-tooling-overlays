from __future__ import annotations

import ast
import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass

import pwndbg
import pwndbg.aglib.proc
import pwndbg.lib.path
from pwndbg.dbg_mod import EventType

log = logging.getLogger(__name__)

_DEFAULT_SYSROOT_VALUES = {"", "/", "target:", "remote:"}
_COMMON_LIB_DIRS = (
    "lib",
    "lib64",
    "usr/lib",
    "usr/lib64",
    "usr/local/lib",
    "usr/local/lib64",
    "lib/x86_64-linux-gnu",
    "lib/i386-linux-gnu",
    "usr/lib/x86_64-linux-gnu",
    "usr/lib/i386-linux-gnu",
)
_COMMON_DEBUG_DIRS = (
    "usr/lib/debug",
    "usr/lib/debug/lib",
    "usr/lib/debug/usr/lib",
)
_LIBTHREAD_DB_BASENAMES = ("libthread_db.so.1", "libthread_db.so")
_LIBC_CANDIDATE_RE = re.compile(r"^libc(?:6)?(?:[-_\.].+)?(?:\.so(?:\.\d+)*)?$")


@dataclass(frozen=True)
class RootfsPreflightResult:
    sysroot: str | None
    normalized_libc_path: str | None
    chosen_libthread_db_path: str | None
    configured: bool


def infer_container_sysroot(pid: int | None = None, *, procfs: str = "/proc") -> str | None:
    if pid is None:
        try:
            pid = pwndbg.aglib.proc.pid()
        except Exception:
            return None

    if pid is None or pid <= 0:
        return None

    proc_root = os.path.join(procfs, str(pid), "root")
    if not os.path.isdir(proc_root):
        return None

    return os.path.normpath(proc_root)


def merge_search_paths(current: str | None, additions: Iterable[str]) -> str:
    merged: list[str] = []
    seen: set[str] = set()

    for value in (current or "").split(os.pathsep):
        if not value:
            continue
        normalized = value if value.startswith("$") else os.path.normpath(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        merged.append(value)

    for value in additions:
        if not value:
            continue
        normalized = value if value.startswith("$") else os.path.normpath(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        merged.append(value)

    return os.pathsep.join(merged)


def normalize_shared_library_path(path: str, sysroot: str | None = None) -> str:
    if not path or path.startswith("["):
        return path

    path_no_prefix = path[7:] if path.startswith("target:") else path

    if sysroot:
        normalized_sysroot = os.path.normpath(sysroot)
        if path_no_prefix == normalized_sysroot or path_no_prefix.startswith(
            normalized_sysroot + os.sep
        ):
            return os.path.normpath(path_no_prefix)

        if os.path.isabs(path_no_prefix):
            candidate = os.path.join(normalized_sysroot, path_no_prefix.lstrip(os.sep))
        else:
            candidate = os.path.join(normalized_sysroot, path_no_prefix)

        candidate = os.path.normpath(candidate)
        if os.path.exists(candidate):
            return candidate

    return pwndbg.lib.path.clean_path(path_no_prefix)


def normalize_shared_library_path_for_current_inferior(path: str) -> str:
    return normalize_shared_library_path(path, infer_container_sysroot())


def _collect_loaded_objfiles() -> list[str]:
    if not pwndbg.dbg.is_gdblib_available():
        return []

    from pwndbg.gdblib import info as gdb_info

    paths: list[str] = []
    seen: set[str] = set()
    for section in gdb_info.sections():
        objfile = section.objfile
        if not objfile or objfile in seen or objfile.startswith("["):
            continue
        seen.add(objfile)
        paths.append(objfile)
    return paths


def _likely_library_dirs(sysroot: str, raw_paths: Iterable[str]) -> list[str]:
    library_dirs: list[str] = []
    seen: set[str] = set()

    for path in raw_paths:
        normalized = normalize_shared_library_path(path, sysroot)
        if not normalized or normalized.startswith(("target:", "[")):
            continue
        parent = os.path.dirname(normalized)
        if parent and os.path.isdir(parent) and parent not in seen:
            seen.add(parent)
            library_dirs.append(parent)

    for relpath in _COMMON_LIB_DIRS:
        candidate = os.path.join(sysroot, relpath)
        if os.path.isdir(candidate) and candidate not in seen:
            seen.add(candidate)
            library_dirs.append(candidate)

    return library_dirs


def _likely_debug_dirs(sysroot: str) -> list[str]:
    dirs: list[str] = []
    for relpath in _COMMON_DEBUG_DIRS:
        candidate = os.path.join(sysroot, relpath)
        if os.path.isdir(candidate):
            dirs.append(candidate)
    return dirs


def _find_libthread_db_path(library_dirs: Iterable[str]) -> str | None:
    for directory in library_dirs:
        for basename in _LIBTHREAD_DB_BASENAMES:
            candidate = os.path.join(directory, basename)
            if os.path.exists(candidate):
                return candidate
    return None


def _find_normalized_libc_path(raw_paths: Iterable[str], sysroot: str) -> str | None:
    exact_match: str | None = None
    fuzzy_match: str | None = None

    for path in raw_paths:
        normalized = normalize_shared_library_path(path, sysroot)
        basename = os.path.basename(normalized)
        if basename in {"libc.so.6", "libc.so"}:
            exact_match = normalized
            break
        if fuzzy_match is None and _LIBC_CANDIDATE_RE.match(basename):
            fuzzy_match = normalized

    return exact_match or fuzzy_match


def _quote_gdb_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _normalize_gdb_parameter_value(value: object) -> str:
    current = str(value or "")

    while current:
        try:
            parsed = ast.literal_eval(current)
        except Exception:
            break
        if not isinstance(parsed, str) or parsed == current:
            break
        current = parsed

    return current


def _maybe_set_gdb_sysroot(sysroot: str) -> bool:
    import gdb

    try:
        current = _normalize_gdb_parameter_value(gdb.parameter("sysroot"))
    except gdb.error:
        current = ""
    if current == sysroot:
        return False

    if current and current not in _DEFAULT_SYSROOT_VALUES and current != sysroot:
        normalized_current = os.path.normpath(current)
        if not (
            normalized_current == sysroot
            or normalized_current.startswith("/proc/")
            and "/root" in normalized_current
        ):
            log.debug(
                "container-rootfs: leaving user-configured sysroot unchanged: %s", current
            )
            return False

    gdb.execute(f"set sysroot {_quote_gdb_string(sysroot)}", to_string=True, from_tty=False)
    return True


def _append_gdb_path_setting(name: str, additions: Iterable[str]) -> bool:
    import gdb

    filtered_additions = [entry for entry in additions if entry]
    if not filtered_additions:
        return False

    try:
        current = _normalize_gdb_parameter_value(gdb.parameter(name))
    except gdb.error:
        return False
    merged = merge_search_paths(current, filtered_additions)
    if merged == current:
        return False

    gdb.execute(f"set {name} {_quote_gdb_string(merged)}", to_string=True, from_tty=False)
    return True


def ensure_gdb_container_rootfs_preflight() -> RootfsPreflightResult:
    return _ensure_gdb_container_rootfs_preflight(reload_shared_libraries=True)


def _ensure_gdb_container_rootfs_preflight(
    *, reload_shared_libraries: bool
) -> RootfsPreflightResult:
    if not pwndbg.dbg.is_gdblib_available():
        return RootfsPreflightResult(None, None, None, False)

    inferior = pwndbg.dbg.selected_inferior()
    if not inferior.alive() or inferior.is_remote() or pwndbg.aglib.proc.is_core_file():
        return RootfsPreflightResult(None, None, None, False)

    sysroot = infer_container_sysroot(inferior.pid())
    if sysroot is None:
        return RootfsPreflightResult(None, None, None, False)

    raw_paths = _collect_loaded_objfiles()
    normalized_libc_path = _find_normalized_libc_path(raw_paths, sysroot)
    library_dirs = _likely_library_dirs(sysroot, raw_paths)
    debug_dirs = _likely_debug_dirs(sysroot)
    libthread_db_path = _find_libthread_db_path(library_dirs)

    log.debug("container-rootfs: inferred sysroot: %s", sysroot)
    if normalized_libc_path:
        log.debug("container-rootfs: normalized libc path: %s", normalized_libc_path)
    if libthread_db_path:
        log.debug("container-rootfs: chosen libthread_db path: %s", libthread_db_path)

    changed = _maybe_set_gdb_sysroot(sysroot)
    changed |= _append_gdb_path_setting("solib-search-path", library_dirs)
    changed |= _append_gdb_path_setting(
        "libthread-db-search-path",
        [os.path.dirname(libthread_db_path)] if libthread_db_path else library_dirs,
    )
    changed |= _append_gdb_path_setting("debug-file-directory", debug_dirs)

    needs_reload = reload_shared_libraries and (changed or not pwndbg.libc.has_debug_info())

    if needs_reload:
        import gdb
        from pwndbg.lib.cache import CacheUntilEvent

        try:
            gdb.execute("nosharedlibrary", to_string=True, from_tty=False)
        except gdb.error:
            pass

        try:
            gdb.execute("sharedlibrary", to_string=True, from_tty=False)
        except gdb.error:
            pass
        pwndbg.lib.cache.clear_cache(CacheUntilEvent.OBJFILE)

    return RootfsPreflightResult(sysroot, normalized_libc_path, libthread_db_path, changed)


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.STOP)
@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def _container_rootfs_preflight_on_event() -> None:
    _ensure_gdb_container_rootfs_preflight(reload_shared_libraries=False)
