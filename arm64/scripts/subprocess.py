#!/usr/bin/env python3
"""Transparent stdlib subprocess proxy with one fail-closed path correction.

This file is temporary and exists only because reconstruct_qtbase_grm3u1.py
passes a repository-relative source-tree path while also setting cwd to that
path's parent.  Python resolves the same path twice.  Only the exact
`dpkg-source -b <cwd>/<name>` shape is normalized to `<name>`; every other
subprocess API and invocation is delegated unchanged to the Python stdlib.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sysconfig
from typing import Any

_STDLIB_PATH = pathlib.Path(sysconfig.get_path("stdlib")) / "subprocess.py"
_SPEC = importlib.util.spec_from_file_location(
    "_hancom_gooroom_stdlib_subprocess", _STDLIB_PATH
)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"cannot load stdlib subprocess module from {_STDLIB_PATH}")
_REAL = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_REAL)

for _NAME in dir(_REAL):
    if _NAME != "run":
        globals()[_NAME] = getattr(_REAL, _NAME)


def run(*popenargs: Any, **kwargs: Any):
    positional = list(popenargs)
    command = kwargs.get("args", positional[0] if positional else None)
    cwd = kwargs.get("cwd")

    if (
        isinstance(command, list)
        and len(command) == 3
        and command[:2] == ["dpkg-source", "-b"]
        and cwd is not None
    ):
        candidate = pathlib.Path(command[2])
        working_directory = pathlib.Path(cwd)
        if (
            not candidate.is_absolute()
            and candidate.parent == working_directory
            and candidate.name
        ):
            normalized = list(command)
            normalized[2] = candidate.name
            if "args" in kwargs:
                kwargs["args"] = normalized
            else:
                positional[0] = normalized

    return _REAL.run(*positional, **kwargs)
