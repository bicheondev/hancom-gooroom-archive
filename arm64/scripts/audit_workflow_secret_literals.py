#!/usr/bin/env python3
"""Reject literal credentials in active GitHub Actions workflow files.

Reports never include a detected value. They retain only path, line number,
reason, a short non-secret prefix classification, length, and SHA-256 so an
operator can prove that a later cleanup removed the same literal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


TOKEN_PATTERNS = (
    ("github-classic-token", re.compile(r"\bgh[psuor]_[A-Za-z0-9_]{20,}\b")),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("authorization-bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{20,}")),
)
ALLOWED_GH_TOKEN_EXPRESSIONS = {
    "${{ github.token }}",
    "${{ secrets.GITHUB_TOKEN }}",
}
GH_TOKEN_LINE = re.compile(r"^(?P<indent>\s*)GH_TOKEN:\s*(?P<value>.*)\s*$")
EXPRESSION = re.compile(r"^\$\{\{\s*(?:github\.token|secrets\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}$")


def fingerprint(value: str) -> dict[str, Any]:
    return {
        "length": len(value),
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "value_class": (
            "github-expression"
            if value.startswith("${{")
            else "literal-or-shell-expression"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    findings: list[dict[str, Any]] = []
    checked_files = 0
    for path in sorted(args.workflow_dir.glob("*.yml")):
        checked_files += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), 1):
            token_line = GH_TOKEN_LINE.match(line)
            if token_line:
                value = token_line.group("value").strip().strip("'\"")
                if value not in ALLOWED_GH_TOKEN_EXPRESSIONS and not EXPRESSION.fullmatch(value):
                    findings.append(
                        {
                            "path": str(path),
                            "line": line_number,
                            "reason": "GH_TOKEN-is-not-a-GitHub-expression",
                            **fingerprint(value),
                        }
                    )
            for reason, pattern in TOKEN_PATTERNS:
                for match in pattern.finditer(line):
                    findings.append(
                        {
                            "path": str(path),
                            "line": line_number,
                            "reason": reason,
                            **fingerprint(match.group(0)),
                        }
                    )

    # Deduplicate a token caught both as a GH_TOKEN value and a general token
    # pattern without ever persisting the token itself.
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        key = (
            finding["path"],
            finding["line"],
            finding["sha256"],
            finding["reason"],
        )
        unique[key] = finding
    findings = sorted(
        unique.values(), key=lambda row: (row["path"], row["line"], row["reason"])
    )

    summary = {
        "schema": 1,
        "policy": "no-literal-credentials-in-active-workflow-yaml",
        "checked_workflow_count": checked_files,
        "finding_count": len(findings),
        "passed": not findings,
    }
    result = {"summary": summary, "findings": findings}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "workflow-secret-audit.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
