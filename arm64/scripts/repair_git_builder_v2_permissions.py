#!/usr/bin/env python3
"""Return Docker-produced build outputs to the invoking host user."""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text and new in text:
        return text
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    text = args.target.read_text(encoding="utf-8")
    text = replace_once(
        text,
        ': "${SNAPSHOT:?SNAPSHOT is required}"\n',
        ': "${SNAPSHOT:?SNAPSHOT is required}"\n'
        ': "${HOST_UID:?HOST_UID is required}"\n'
        ': "${HOST_GID:?HOST_GID is required}"\n',
        "container host identity",
    )
    text = replace_once(
        text,
        'cp -av "$ROOT/build/output/." /out/ || true\nexit "$BUILD_RC"\n',
        'cp -av "$ROOT/build/output/." /out/ || true\n'
        'chown -R "$HOST_UID:$HOST_GID" /out || true\n'
        'exit "$BUILD_RC"\n',
        "output ownership restoration",
    )
    text = replace_once(
        text,
        '  --env "SNAPSHOT=$SNAPSHOT" \\\n',
        '  --env "SNAPSHOT=$SNAPSHOT" \\\n'
        '  --env "HOST_UID=$(id -u)" \\\n'
        '  --env "HOST_GID=$(id -g)" \\\n',
        "Docker host identity environment",
    )
    args.target.write_text(text, encoding="utf-8")
    print(f"updated {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
