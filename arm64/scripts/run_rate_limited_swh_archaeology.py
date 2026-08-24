#!/usr/bin/env python3
"""Run Software Heritage archaeology with rate-aware fail-closed transport.

The underlying archaeology program remains unchanged. This launcher replaces
its transport at runtime, records retry/pacing evidence, and refuses to publish
a negative result after an exhausted HTTP 429, transient server error, or
network failure.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from swh_rate_limited_transport import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_MAX_RETRY_DELAY,
    DEFAULT_MIN_INTERVAL,
    RateAwareTransport,
)


def load_archaeology_module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(
        "archaeology_software_heritage_exact_sources",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load archaeology module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _output_dir(argv: Sequence[str]) -> Path:
    for index, value in enumerate(argv):
        if value == "--output-dir":
            if index + 1 >= len(argv):
                raise ValueError("--output-dir requires a value")
            return Path(argv[index + 1])
        if value.startswith("--output-dir="):
            return Path(value.split("=", 1)[1])
    raise ValueError("underlying archaeology arguments lack --output-dir")


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def annotate_output(
    output_dir: Path,
    transport: RateAwareTransport,
) -> bool:
    summary_path = output_dir / "summary.json"
    if not summary_path.is_file():
        raise RuntimeError(
            f"archaeology did not produce summary.json: {summary_path}"
        )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if not isinstance(summary, dict):
        raise RuntimeError("archaeology summary is not a JSON object")

    transport_summary = transport.summary()
    complete = transport.terminal_transient_error_count == 0
    summary["transport"] = transport_summary
    summary["evidence_complete"] = complete
    summary["terminal_transport_error_count"] = (
        transport.terminal_transient_error_count
    )
    summary["rate_limit_retry_count"] = transport.rate_limit_retry_count
    _write_json(summary_path, summary)

    incomplete_targets = 0
    for result_path in sorted(output_dir.glob("*/result.json")):
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError(f"target result is not an object: {result_path}")
        target_dir = result_path.parent
        terminal_errors = 0
        for attempts_path in target_dir.glob("*-attempts.json"):
            value = json.loads(attempts_path.read_text(encoding="utf-8"))
            if not isinstance(value, list):
                raise RuntimeError(
                    f"attempt evidence is not an array: {attempts_path}"
                )
            terminal_errors += sum(
                1
                for row in value
                if isinstance(row, dict)
                and row.get("terminal_transient") is True
            )
        result["evidence_complete"] = terminal_errors == 0
        result["terminal_transport_error_count"] = terminal_errors
        if terminal_errors:
            incomplete_targets += 1
            result["status"] = "incomplete-transport"
            result["promotion_allowed"] = False
        _write_json(result_path, result)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["transport_incomplete_target_count"] = incomplete_targets
    summary["evidence_complete"] = complete and incomplete_targets == 0
    _write_json(summary_path, summary)
    return bool(summary["evidence_complete"])


def parse_args(
    argv: Sequence[str] | None = None,
) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description=(
            "Rate-aware launcher for Software Heritage exact-source archaeology"
        ),
        add_help=False,
    )
    parser.add_argument(
        "--swh-min-interval",
        type=float,
        default=float(
            os.environ.get(
                "SWH_MIN_INTERVAL_SECONDS",
                DEFAULT_MIN_INTERVAL,
            )
        ),
    )
    parser.add_argument(
        "--swh-max-retries",
        type=int,
        default=int(
            os.environ.get("SWH_MAX_RETRIES", DEFAULT_MAX_RETRIES)
        ),
    )
    parser.add_argument(
        "--swh-max-retry-delay",
        type=float,
        default=float(
            os.environ.get(
                "SWH_MAX_RETRY_DELAY_SECONDS",
                DEFAULT_MAX_RETRY_DELAY,
            )
        ),
    )
    return parser.parse_known_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    wrapper_args, archaeology_args = parse_args(argv)
    output_dir = _output_dir(archaeology_args)
    script = Path(__file__).with_name(
        "archaeology_software_heritage_exact_sources.py"
    )
    module = load_archaeology_module(script)
    transport = RateAwareTransport(
        min_interval=wrapper_args.swh_min_interval,
        max_retries=wrapper_args.swh_max_retries,
        max_retry_delay=wrapper_args.swh_max_retry_delay,
        bearer_token=os.environ.get("SWH_BEARER_TOKEN"),
    )
    module.request_bytes = transport.request_bytes

    old_argv = sys.argv
    try:
        sys.argv = [str(script), *archaeology_args]
        exit_code = int(module.main())
    finally:
        sys.argv = old_argv

    complete = annotate_output(output_dir, transport)
    print(json.dumps(transport.summary(), sort_keys=True))
    if exit_code != 0:
        return exit_code
    if not complete:
        print(
            "Software Heritage traversal is incomplete after bounded retries; "
            "refusing to publish a negative result.",
            file=sys.stderr,
        )
        return 75
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
