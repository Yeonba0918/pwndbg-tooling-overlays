from __future__ import annotations

import os

from pwndbg.aglib.container_rootfs import infer_container_sysroot
from pwndbg.aglib.container_rootfs import merge_search_paths
from pwndbg.aglib.container_rootfs import normalize_shared_library_path


def test_infer_container_sysroot_from_proc_root(tmp_path):
    procfs = tmp_path / "proc"
    rootfs = tmp_path / "rootfs"
    (procfs / "1337").mkdir(parents=True)
    rootfs.mkdir()
    os.symlink(rootfs, procfs / "1337" / "root")

    assert infer_container_sysroot(1337, procfs=str(procfs)) == str(procfs / "1337" / "root")


def test_infer_container_sysroot_skips_missing_root(tmp_path):
    procfs = tmp_path / "proc"
    (procfs / "7331").mkdir(parents=True)

    assert infer_container_sysroot(7331, procfs=str(procfs)) is None


def test_normalize_shared_library_relative_path_under_sysroot(tmp_path):
    rootfs = tmp_path / "rootfs"
    libc_path = rootfs / "glibc" / "libc.so.6"
    libc_path.parent.mkdir(parents=True)
    libc_path.write_text("")

    assert normalize_shared_library_path("glibc/libc.so.6", str(rootfs)) == str(libc_path)


def test_normalize_shared_library_absolute_path_under_sysroot(tmp_path):
    rootfs = tmp_path / "rootfs"
    libc_path = rootfs / "opt" / "ctf" / "libc.so.6"
    libc_path.parent.mkdir(parents=True)
    libc_path.write_text("")

    assert normalize_shared_library_path("/opt/ctf/libc.so.6", str(rootfs)) == str(libc_path)


def test_normalize_shared_library_target_prefixed_path_under_sysroot(tmp_path):
    rootfs = tmp_path / "rootfs"
    libc_path = rootfs / "lib" / "x86_64-linux-gnu" / "libc.so.6"
    libc_path.parent.mkdir(parents=True)
    libc_path.write_text("")

    assert (
        normalize_shared_library_path("target:/lib/x86_64-linux-gnu/libc.so.6", str(rootfs))
        == str(libc_path)
    )


def test_merge_search_paths_preserves_order_and_deduplicates():
    current = "$sdir:/tmp/rootfs/lib:/tmp/rootfs/usr/lib"
    additions = ["/tmp/rootfs/lib", "/tmp/rootfs/lib64", "$sdir", "/tmp/rootfs/usr/lib"]

    assert (
        merge_search_paths(current, additions)
        == "$sdir:/tmp/rootfs/lib:/tmp/rootfs/usr/lib:/tmp/rootfs/lib64"
    )
