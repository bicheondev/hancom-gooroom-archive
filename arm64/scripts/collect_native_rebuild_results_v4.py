#!/usr/bin/env python3
"""CLI-compatible entry point for Git-or-DSC result collector v3."""

from __future__ import annotations

import sys

import collect_native_rebuild_results_v3 as base


ALIASES = {
    "--artifacts": "--artifacts-dir",
    "--artifact-dir": "--artifacts-dir",
    "--artifact-root": "--artifacts-dir",
    "--input": "--artifacts-dir",
    "--input-dir": "--artifacts-dir",
    "--output": "--output-dir",
    "--actions-run-id": "--run-id",
    "--actions-run-url": "--run-url",
    "--batch-name": "--batch",
}


def normalize(arguments: list[str]) -> list[str]:
    output = []
    for argument in arguments:
        replaced = False
        for old, new in ALIASES.items():
            if argument == old:
                output.append(new)
                replaced = True
                break
            if argument.startswith(old + "="):
                output.append(new + argument[len(old) :])
                replaced = True
                break
        if not replaced:
            output.append(argument)
    return output


if __name__ == "__main__":
    sys.argv[1:] = normalize(sys.argv[1:])
    raise SystemExit(base.main())
