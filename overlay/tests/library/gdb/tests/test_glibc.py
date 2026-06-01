from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from unittest.mock import patch

import gdb
import pytest

import pwndbg.libc
import pwndbg.libc.glibc

from . import get_binary

# We used the same binary as heap tests since it will use libc, and many functions are mainly for debugging the heap
HEAP_MALLOC_CHUNK = get_binary("heap_malloc_chunk.native.out")


@pytest.mark.parametrize(
    "have_debugging_information", [True, False], ids=["does-not-have-(*)", "have-(*)"]
)
def test_finding_glibc_filepath(start_binary, have_debugging_information):
    # Check if we can find the libc if nothing special happens
    if not have_debugging_information:
        # Make sure the (*) in the output of `info sharedlibrary` won't affect the result
        gdb.execute("set debug-file-directory")
        gdb.execute("set debuginfod enabled off")

    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")
    if not have_debugging_information:
        assert "(*)" in gdb.execute("info sharedlibrary", to_string=True)

    libc_path = pwndbg.libc.filepath()
    assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC
    assert libc_path is not None

    # Create 3 copies of the libc with the filenames: libc-2.36.so, libc6_2.36-0ubuntu4_amd64.so, libc.so
    # Note: The version in the above filename doesn't matter, just some tests for the common libc names we might use with LD_PRELOAD
    test_libc_names = ["libc-2.36.so", "libc6_2.36-0ubuntu4_amd64.so", "libc.so"]
    with tempfile.TemporaryDirectory() as tmp_dir:
        for test_libc_name in test_libc_names:
            test_libc_path = os.path.join(tmp_dir, test_libc_name)
            shutil.copy(libc_path, test_libc_path)
            gdb.execute(f"set environment LD_PRELOAD={test_libc_path}")
            start_binary(HEAP_MALLOC_CHUNK)
            gdb.execute("break break_here")
            gdb.execute("continue")
            # Check if we can find the libc loaded by LD_PRELOAD
            if not have_debugging_information:
                assert "(*)" in gdb.execute("info sharedlibrary", to_string=True)
            assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC
            assert str(pwndbg.libc.filepath()) == test_libc_path

        # Unfortunatly, if we used LD_PRELOAD to load libc, we might cannot find the libc's filename
        # In this case, the "unknown" libc implementation will be returned and the ld mapping will
        # be returned instead of the libc one.
        test_libc_path = os.path.join(tmp_dir, "a_weird_name_that_does_not_look_like_a_1ibc.so")
        shutil.copy(libc_path, test_libc_path)
        gdb.execute(f"set environment LD_PRELOAD={test_libc_path}")
        start_binary(HEAP_MALLOC_CHUNK)
        gdb.execute("break break_here")
        gdb.execute("continue")

        assert pwndbg.libc.which() == pwndbg.libc.LibcType.UNKNOWN
        assert pwndbg.libc.filepath().name == "ld-linux-x86-64.so.2"


def test_set_glibc_version(start_binary):
    # Needed for glibc.version() as it requires an alive process.
    start_binary(HEAP_MALLOC_CHUNK)

    # Make sure glibc is loaded.
    gdb.execute("break main")
    gdb.execute("continue")

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC

    errmsg = "Invalid GLIBC version:"
    err = gdb.execute("set glibc 2.31a", to_string=True)
    assert err.startswith(errmsg)

    err = gdb.execute("set glibc 2.31", to_string=True)
    assert err == ""
    assert pwndbg.libc.version() == (2, 31)

    err = gdb.execute("set glibc 2.34", to_string=True)
    assert err == ""
    assert pwndbg.libc.version() == (2, 34)


def _host_libc_path(binary_path: str) -> str:
    ldd_output = subprocess.check_output(["ldd", binary_path], text=True)
    match = re.search(r"libc\.so\.6 => (\S+)", ldd_output)
    assert match is not None
    return match.group(1)


def _host_interpreter_path(binary_path: str) -> str:
    return subprocess.check_output(["patchelf", "--print-interpreter", binary_path], text=True).strip()


def _prepare_rootfs_binary(
    src_binary: str,
    *,
    needed_path: str,
    interpreter_path: str | None = None,
    strip_libc: bool = False,
) -> tuple[str, str]:
    if shutil.which("patchelf") is None:
        pytest.skip("patchelf is required for fake-rootfs GDB tests")
    if strip_libc and shutil.which("strip") is None:
        pytest.skip("strip is required for stripped-libc fake-rootfs GDB tests")

    rootfs = tempfile.mkdtemp()
    binary_path = os.path.join(rootfs, "heap")
    shutil.copy(src_binary, binary_path)

    libc_path = os.path.join(rootfs, needed_path.lstrip("/"))
    os.makedirs(os.path.dirname(libc_path), exist_ok=True)
    shutil.copy(_host_libc_path(src_binary), libc_path)
    if strip_libc:
        subprocess.check_call(["strip", "--strip-unneeded", libc_path])

    subprocess.check_call(["patchelf", "--replace-needed", "libc.so.6", needed_path, binary_path])

    if interpreter_path is not None:
        loader_path = os.path.join(rootfs, interpreter_path.lstrip("/"))
        os.makedirs(os.path.dirname(loader_path), exist_ok=True)
        shutil.copy(_host_interpreter_path(src_binary), loader_path)
        subprocess.check_call(["patchelf", "--set-interpreter", interpreter_path, binary_path])

    return rootfs, binary_path


def _start_binary_in_fake_rootfs(binary_path: str, rootfs: str) -> None:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        pytest.skip("bwrap is required for fake-rootfs GDB tests")

    os.environ["PWNDBG_IN_TEST"] = "1"
    gdb.execute("set debuginfod enabled off")
    gdb.execute("set debug-file-directory")
    gdb.execute(f"file {binary_path}")
    gdb.execute("set exception-verbose on")
    gdb.execute("set width 80")
    gdb.execute("set context-reserve-lines never")
    os.environ["COLUMNS"] = "80"
    gdb.execute("cd /")
    gdb.execute(
        "set exec-wrapper "
        + " ".join(
            [
                bwrap,
                "--bind",
                rootfs,
                "/",
                "--ro-bind",
                "/bin",
                "/bin",
                "--ro-bind",
                "/lib",
                "/lib",
                "--ro-bind",
                "/lib64",
                "/lib64",
                "--ro-bind",
                "/usr",
                "/usr",
                "--chdir",
                "/",
            ]
        )
    )
    gdb.execute("exec-file /heap")
    gdb.execute("starti")


def _launch_to_break_here(binary_path: str, rootfs: str) -> None:
    _start_binary_in_fake_rootfs(binary_path, rootfs)
    gdb.execute("break break_here")
    gdb.execute("continue")


def test_heap_with_relative_libc_path_via_fake_rootfs():
    rootfs, binary_path = _prepare_rootfs_binary(
        HEAP_MALLOC_CHUNK,
        needed_path="glibc/libc.so.6",
        strip_libc=True,
    )
    try:
        with patch("pwndbg.aglib.container_rootfs.infer_container_sysroot", return_value=rootfs):
            _launch_to_break_here(binary_path, rootfs)

            sharedlibrary = gdb.execute("info sharedlibrary", to_string=True)
            assert "glibc/libc.so.6" in sharedlibrary
            assert str(pwndbg.libc.filepath()) == os.path.join(rootfs, "glibc", "libc.so.6")

            heap_output = gdb.execute("heap allocated_chunk --count 1", to_string=True)
            assert "Allocated chunk" in heap_output
            assert "Addr:" in heap_output
    finally:
        shutil.rmtree(rootfs)


def test_heap_with_custom_patchelf_libc_and_loader_paths():
    rootfs, binary_path = _prepare_rootfs_binary(
        HEAP_MALLOC_CHUNK,
        needed_path="/opt/ctf/libc.so.6",
        interpreter_path="/opt/ctf/ld-linux-x86-64.so.2",
    )
    try:
        with patch("pwndbg.aglib.container_rootfs.infer_container_sysroot", return_value=rootfs):
            _launch_to_break_here(binary_path, rootfs)

            sharedlibrary = gdb.execute("info sharedlibrary", to_string=True)
            assert "/opt/ctf/libc.so.6" in sharedlibrary
            assert str(pwndbg.libc.filepath()) == os.path.join(rootfs, "opt", "ctf", "libc.so.6")

            heap_output = gdb.execute("heap allocated_chunk --count 1", to_string=True)
            assert "Allocated chunk" in heap_output
            assert "Addr:" in heap_output
    finally:
        shutil.rmtree(rootfs)
