#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_BACKUP_SUFFIX = ".bak.autoheap"


@dataclass(frozen=True)
class InstallPaths:
    pwndbg_bin: Path
    gdb_pwndbg_bin: Path
    bundle_root: Path
    root_gdbinit: Path
    backup_suffix: str


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_text(path: Path, content: str, mode: int) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def detect_bundle_root(pwndbg_bin: Path) -> Path:
    resolved = pwndbg_bin.resolve()
    candidates = [
        resolved.parent.parent,
        Path("/usr/local/lib/pwndbg-gdb"),
        Path("/opt/pwndbg-gdb"),
        Path.home() / ".local/lib/pwndbg-gdb",
    ]

    for candidate in candidates:
        if (candidate / "exe/gdb").exists() and (candidate / "exe/gdbinit.py").exists():
            return candidate

    raise FileNotFoundError(
        f"Could not detect pwndbg bundle root from {pwndbg_bin}. "
        "Expected a directory containing exe/gdb and exe/gdbinit.py."
    )


def render_pwndbg_wrapper(bundle_root: Path) -> str:
    bundle = bundle_root.as_posix()
    return f"""#!/bin/bash
set -euo pipefail

dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
if [[ ! -x "$dir/exe/gdb" && -x {bundle}/exe/gdb ]]; then
    dir="{bundle}"
fi
export TERMINFO_DIRS=/etc/terminfo:/lib/terminfo:/usr/share/terminfo:/run/current-system/sw/share/terminfo:$dir/share/terminfo
export PYTHONNOUSERSITE=1
export PYTHONHOME="$dir"
export PYTHONPATH=""
export PATH="$dir/bin/:$PATH"

pid=""
pid_pending=0
expect_value=0
explicit_file=0
passthrough=()

for arg in "$@"; do
    if [[ $pid_pending -eq 1 ]]; then
        pid="$arg"
        pid_pending=0
        continue
    fi

    if [[ $expect_value -eq 1 ]]; then
        passthrough+=("$arg")
        expect_value=0
        continue
    fi

    case "$arg" in
        -p|--pid)
            pid_pending=1
            continue
            ;;
        -p[0-9]*)
            pid="${{arg#-p}}"
            continue
            ;;
        -pid=*|--pid=*)
            pid="${{arg#*=}}"
            continue
            ;;
        -ex|-iex|-ix|-x|--eval-command|--early-init-eval-command|--init-command|--command|--directory|--cd|--symbols|--se)
            passthrough+=("$arg")
            expect_value=1
            continue
            ;;
        --args)
            explicit_file=1
            passthrough+=("$arg")
            continue
            ;;
    esac

    if [[ "$arg" != -* ]]; then
        explicit_file=1
    fi
    passthrough+=("$arg")
done

gdb_bin="$dir/exe/gdb"
gdbinit_py="$dir/exe/gdbinit.py"
ldso="$dir/lib/ld-linux-x86-64.so.2"

if [[ -n "$pid" && "$explicit_file" -eq 0 ]]; then
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    sysroot="/proc/$pid/root"
    if [[ -n "$exe" && -e "$sysroot$exe" ]]; then
        exe_dir="$(dirname "$exe")"
        solib_search_path="$sysroot$exe_dir:$sysroot/lib:$sysroot/lib64:$sysroot/usr/lib:$sysroot/usr/lib64:$sysroot/usr/local/lib:$sysroot/lib/x86_64-linux-gnu:$sysroot/usr/lib/x86_64-linux-gnu"
        libthread_db_search_path="\\$sdir:\\$pdir:$sysroot/lib/x86_64-linux-gnu:$sysroot/usr/lib/x86_64-linux-gnu"
        debug_file_directory="/usr/lib/debug:$sysroot/usr/lib/debug"

        exec "$ldso" "$gdb_bin" --quiet --early-init-eval-command="set auto-load safe-path /" \\
            --command="$gdbinit_py" \\
            "$sysroot$exe" \\
            -ex "set sysroot $sysroot" \\
            -ex "set solib-search-path $solib_search_path" \\
            -ex "set libthread-db-search-path $libthread_db_search_path" \\
            -ex "set debug-file-directory $debug_file_directory" \\
            -ex "attach $pid" \\
            "${{passthrough[@]}}"
    fi
fi

exec "$ldso" "$gdb_bin" --quiet --early-init-eval-command="set auto-load safe-path /" --command="$gdbinit_py" "${{passthrough[@]}}"
"""


def render_gdb_pwndbg_wrapper(pwndbg_bin: Path) -> str:
    return f"""#!/bin/sh
exec {pwndbg_bin.as_posix()} "$@"
"""


def backup_path(path: Path, suffix: str) -> Path:
    return path.with_name(path.name + suffix)


def ensure_backup(path: Path, suffix: str) -> Path:
    backup = backup_path(path, suffix)
    if not backup.exists():
        shutil.copy2(path, backup)
    return backup


def patch_root_gdbinit(path: Path, suffix: str, *, dry_run: bool) -> tuple[bool, str]:
    try:
        exists = path.exists()
    except PermissionError:
        return False, f"{path}: permission denied"

    if not exists:
        return False, f"{path}: not found"

    try:
        original = _read_text(path)
    except PermissionError:
        return False, f"{path}: permission denied"
    patched_lines: list[str] = []
    changed = False

    for line in original.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("#"):
            patched_lines.append(line)
            continue

        if "pwndbg/gdbinit.py" in stripped and stripped.startswith("source "):
            patched_lines.append("# " + line if not line.startswith("# ") else line)
            changed = True
            continue

        patched_lines.append(line)

    if not changed:
        return False, f"{path}: already clean"

    if not dry_run:
        ensure_backup(path, suffix)
        _write_text(path, "".join(patched_lines), path.stat().st_mode)

    return True, f"{path}: commented legacy source line"


def restore_file(path: Path, suffix: str, *, dry_run: bool) -> tuple[bool, str]:
    backup = backup_path(path, suffix)
    try:
        exists = backup.exists()
    except PermissionError:
        return False, f"{path}: permission denied"
    if not exists:
        return False, f"{path}: backup not found"
    if not dry_run:
        shutil.copy2(backup, path)
    return True, f"{path}: restored from {backup.name}"


def file_status(path: Path, expected: str) -> str:
    if not path.exists():
        return "missing"
    try:
        current = _read_text(path)
    except Exception:
        return "unreadable"
    return "patched" if current == expected else "custom"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Patch an installed portable pwndbg/gdb-pwndbg pair so PID attach works across container rootfs boundaries."
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("status", "apply", "restore"),
        default="status",
        help="Operation to run.",
    )
    parser.add_argument(
        "--pwndbg-bin",
        default=shutil.which("pwndbg") or "/usr/local/bin/pwndbg",
        help="Path to the installed pwndbg launcher.",
    )
    parser.add_argument(
        "--gdb-pwndbg-bin",
        default=shutil.which("gdb-pwndbg") or "/usr/bin/gdb-pwndbg",
        help="Path to the gdb-pwndbg launcher.",
    )
    parser.add_argument(
        "--root-gdbinit",
        default="/root/.gdbinit",
        help="Path to the root gdbinit file to sanitize.",
    )
    parser.add_argument(
        "--backup-suffix",
        default=DEFAULT_BACKUP_SUFFIX,
        help="Suffix used for backup files.",
    )
    parser.add_argument(
        "--skip-root-gdbinit",
        action="store_true",
        help="Do not modify the root gdbinit file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    install = InstallPaths(
        pwndbg_bin=Path(args.pwndbg_bin),
        gdb_pwndbg_bin=Path(args.gdb_pwndbg_bin),
        bundle_root=detect_bundle_root(Path(args.pwndbg_bin)),
        root_gdbinit=Path(args.root_gdbinit),
        backup_suffix=args.backup_suffix,
    )

    rendered_pwndbg = render_pwndbg_wrapper(install.bundle_root)
    rendered_gdb_pwndbg = render_gdb_pwndbg_wrapper(install.pwndbg_bin)

    if args.command == "status":
        print(f"bundle_root: {install.bundle_root}")
        print(f"{install.pwndbg_bin}: {file_status(install.pwndbg_bin, rendered_pwndbg)}")
        print(
            f"{install.gdb_pwndbg_bin}: {file_status(install.gdb_pwndbg_bin, rendered_gdb_pwndbg)}"
        )
        if not args.skip_root_gdbinit:
            changed, message = patch_root_gdbinit(
                install.root_gdbinit, install.backup_suffix, dry_run=True
            )
            status = "needs cleanup" if changed else "ok"
            print(f"{install.root_gdbinit}: {status} ({message})")
        return 0

    if args.command == "restore":
        for path in (install.pwndbg_bin, install.gdb_pwndbg_bin):
            _changed, message = restore_file(
                path, install.backup_suffix, dry_run=args.dry_run
            )
            print(message)
        if not args.skip_root_gdbinit:
            _changed, message = restore_file(
                install.root_gdbinit, install.backup_suffix, dry_run=args.dry_run
            )
            print(message)
        return 0

    # apply
    for path, rendered in (
        (install.pwndbg_bin, rendered_pwndbg),
        (install.gdb_pwndbg_bin, rendered_gdb_pwndbg),
    ):
        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist")

        current_status = file_status(path, rendered)
        if current_status != "patched" and not args.dry_run:
            ensure_backup(path, install.backup_suffix)
            mode = path.stat().st_mode
            _write_text(path, rendered, stat.S_IMODE(mode) or 0o755)
        print(f"{path}: {'would patch' if args.dry_run else 'patched'} ({current_status})")

    if not args.skip_root_gdbinit:
        _changed, message = patch_root_gdbinit(
            install.root_gdbinit, install.backup_suffix, dry_run=args.dry_run
        )
        print(message)

    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
