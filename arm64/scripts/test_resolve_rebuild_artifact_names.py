#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("resolve_rebuild_artifact_names.py")
spec = importlib.util.spec_from_file_location("resolver", SCRIPT)
assert spec is not None and spec.loader is not None
resolver = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = resolver
spec.loader.exec_module(resolver)


def artifact(name: str, ident: int, expired: bool = False):
    return {"name": name, "id": ident, "expired": expired}


def expect_failure(callback, fragment: str) -> None:
    try:
        callback()
    except RuntimeError as error:
        assert fragment in str(error), error
    else:
        raise AssertionError("expected RuntimeError")


rows = [{"source": "demo-source", "package": "demo"}]
selected, method = resolver.resolve_artifact(
    "exact-name", rows, [artifact("exact-name", 1)]
)
assert selected["id"] == 1 and method == "exact"

selected, method = resolver.resolve_artifact(
    "1.0_grm1",
    rows,
    [artifact("demo-source-1.0_grm1", 2), artifact("other", 3)],
)
assert selected["id"] == 2 and method == "unique-source-suffix"

selected, method = resolver.resolve_artifact(
    "exact-name",
    rows,
    [artifact("exact-name", 1, expired=True), artifact("demo-source-exact-name", 2)],
)
assert selected["id"] == 2 and method == "unique-source-suffix"

expect_failure(
    lambda: resolver.resolve_artifact(
        "1.0_grm1",
        rows,
        [artifact("demo-source-a-1.0_grm1", 1), artifact("demo-source-b-1.0_grm1", 2)],
    ),
    "2 source-qualified suffix matches",
)

selected, method = resolver.resolve_artifact(
    "historical-short-name",
    rows,
    [artifact("exact-package-rebuild-arm64-demo-source-42", 4)],
)
assert selected["id"] == 4 and method == "unique-source-qualified"

expect_failure(
    lambda: resolver.resolve_artifact("missing", rows, [artifact("unrelated", 1)]),
    "0 source-qualified matches",
)

input_rows = [
    {
        "package": "demo",
        "source": "demo-source",
        "actions_run_id": "42",
        "artifact_name": "1.0_grm1",
    },
    {
        "package": "demo-data",
        "source": "demo-source",
        "actions_run_id": "42",
        "artifact_name": "1.0_grm1",
    },
]
resolved, evidence = resolver.resolve_rows(
    input_rows,
    "owner/repo",
    lambda repository, run_id: [artifact("demo-source-1.0_grm1", 99)],
)
assert all(row["artifact_name"] == "demo-source-1.0_grm1" for row in resolved)
assert all(row["resolved_artifact_id"] == "99" for row in resolved)
assert evidence[0]["package_count"] == 2
print("resolve_rebuild_artifact_names tests: OK")
