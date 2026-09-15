"""Atomic directory publication without replacing an existing destination.

macOS renamex_np(RENAME_EXCL) and Linux renameat2(RENAME_NOREPLACE) enforce
exclusivity in the kernel. Never fall back to ordinary rename after a failure.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import sys


def publish_directory(source: Path, destination: Path) -> None:
    if not source.is_absolute() or not destination.is_absolute() or source.is_symlink() or not source.is_dir():
        raise OSError(errno.EINVAL, "Publication requires an absolute regular source directory and destination")
    source_bytes, destination_bytes = os.fsencode(source), os.fsencode(destination)
    if b"\0" in source_bytes or b"\0" in destination_bytes:
        raise OSError(errno.EINVAL, "Publication paths must not contain NUL")
    library = ctypes.CDLL(None, use_errno=True)
    try:
        if sys.platform == "darwin":
            operation = library.renamex_np
            operation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            operation.restype = ctypes.c_int
            result = operation(source_bytes, destination_bytes, 0x4)  # SDK sys/stdio.h: RENAME_EXCL
        elif sys.platform.startswith("linux"):
            operation = library.renameat2
            operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            operation.restype = ctypes.c_int
            result = operation(-100, source_bytes, -100, destination_bytes, 1)  # AT_FDCWD, RENAME_NOREPLACE
        else:
            raise OSError(errno.ENOTSUP, "Atomic no-replace publication is unsupported on this platform")
    except AttributeError as error:
        raise OSError(errno.ENOTSUP, "Atomic no-replace publication is unavailable") from error
    if result != 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "Atomic no-replace publication failed")
