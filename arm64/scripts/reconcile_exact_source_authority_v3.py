#!/usr/bin/env python3
"""Reconcile recovered exact sources into a single v3 authority overlay."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = 3
SAFE_RE = re.compile(r"[^A-Za-z0-9._+~-]")


def safe(value: str) -> str:
    return SAFE_RE.sub("_", value)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-evidence", type=Path, required=True)
    parser.add_argument("--bundle-authority", type=Path, required=True)
    parser.add_argument("--candidate-comparisons", type=Path, required=True)
    parser.add_argument("--base-status", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = args.reference_evidence.resolve()
    bundles_root = args.bundle_authority.resolve()
    comparisons_root = args.candidate_comparisons.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    targets: list[dict[str, Any]] = load_json(reference / "target-findings.json", [])
    if len(targets) != 7:
        raise SystemExit(f"expected 7 reference source blockers, found {len(targets)}")
    target_by_source = {row["source"]: row for row in targets}

    release_assets: list[dict[str, Any]] = load_json(
        bundles_root / "release-assets.json", []
    )
    comparison_results: list[dict[str, Any]] = load_json(
        comparisons_root / "results.json", []
    )
    base_status: dict[str, Any] = load_json(args.base_status, {})

    authorized_assets: dict[str, list[dict[str, Any]]] = {}
    candidate_assets: dict[str, list[dict[str, Any]]] = {}
    for row in release_assets:
        source = row.get("source", "")
        if source not in target_by_source:
            continue
        if row.get("version") != target_by_source[source]["source_version"]:
            continue
        if row.get("category") == "authorized":
            authorized_assets.setdefault(source, []).append(row)
        elif row.get("category") == "candidate":
            candidate_assets.setdefault(source, []).append(row)

    comparison_by_source = {
        row.get("source", ""): row
        for row in comparison_results
        if row.get("promotion_allowed")
    }

    authority_rows: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for source, target in sorted(target_by_source.items()):
        version = target["source_version"]
        direct = authorized_assets.get(source, [])
        reconstructed = comparison_by_source.get(source)
        candidate = candidate_assets.get(source, [])
        row: dict[str, Any] = {
            "source": source,
            "version": version,
            "binary_packages": target.get("binary_packages", []),
            "authorized": False,
            "authority": "",
            "release_asset": None,
            "evidence": [],
            "reason": "no recovered source authority passed all gates",
        }
        if len(direct) > 1:
            unique_hashes = sorted({item.get("bundle_sha256", "") for item in direct})
            if len(unique_hashes) > 1:
                conflicts.append(
                    {
                        "source": source,
                        "version": version,
                        "reason": "conflicting authorized bundle hashes",
                        "bundle_sha256": unique_hashes,
                    }
                )
                row["reason"] = "conflicting authorized bundle hashes"
                authority_rows.append(row)
                continue
        if direct:
            selected = sorted(
                direct,
                key=lambda item: (
                    0 if item.get("authority") == "historical-inrelease-chain" else 1,
                    item.get("bundle_sha256", ""),
                ),
            )[0]
            row.update(
                {
                    "authorized": True,
                    "authority": selected.get("authority", "recovered-source-bundle"),
                    "release_asset": selected,
                    "evidence": [
                        "arm64/locks/recovered-source-bundles/latest/release-assets.json"
                    ],
                    "reason": "complete exact source bundle passed its upstream authority gate",
                }
            )
        elif reconstructed:
            matching_candidates = candidate
            if len(matching_candidates) != 1:
                row["reason"] = (
                    "AMD64 reconstruction matched but the exact candidate release asset is missing or ambiguous"
                )
            else:
                selected = matching_candidates[0]
                row.update(
                    {
                        "authorized": True,
                        "authority": "exact-amd64-reference-package-reconstruction",
                        "release_asset": selected,
                        "evidence": [
                            reconstructed.get("evidence_path", ""),
                            "arm64/locks/source-candidate-amd64-comparisons/latest/results.json",
                            "arm64/locks/recovered-source-bundles/latest/release-assets.json",
                        ],
                        "reason": "every exact reference binary package matched its rebuilt data and control trees",
                    }
                )
        authority_rows.append(row)

    authorized = [row for row in authority_rows if row["authorized"]]
    unresolved = [row for row in authority_rows if not row["authorized"]]
    base_source_blockers = int(base_status.get("source_blocker_count", len(targets)))
    projected_source_blockers = max(0, base_source_blockers - len(authorized))
    projected_exact_packaging = int(
        base_status.get("exact_packaging_source_locked_count", 0)
    ) + len(authorized)
    projected_exact_buildable = int(
        base_status.get("exact_buildable_source_locked_count", 0)
    ) + len(authorized)
    native_build_blockers = int(base_status.get("native_build_blocker_count", 0))

    summary = {
        "schema": SCHEMA,
        "policy": "exact-source-authority-separated-from-native-arm64-build-authority",
        "reference_blocker_count": len(targets),
        "newly_authorized_source_count": len(authorized),
        "remaining_reference_source_blocker_count": len(unresolved),
        "conflict_count": len(conflicts),
        "authorized_sources": [row["source"] for row in authorized],
        "unresolved_sources": [row["source"] for row in unresolved],
        "base_status": {
            "source_blocker_count": base_source_blockers,
            "exact_packaging_source_locked_count": int(
                base_status.get("exact_packaging_source_locked_count", 0)
            ),
            "exact_buildable_source_locked_count": int(
                base_status.get("exact_buildable_source_locked_count", 0)
            ),
            "native_build_blocker_count": native_build_blockers,
        },
        "projected_status": {
            "source_blocker_count": projected_source_blockers,
            "exact_packaging_source_locked_count": projected_exact_packaging,
            "exact_buildable_source_locked_count": projected_exact_buildable,
            "native_build_blocker_count": native_build_blockers,
            "package_layer_ready": bool(
                projected_source_blockers == 0 and native_build_blockers == 0
            ),
            "iso_assembly_allowed": False,
        },
        "native_arm64_build_credit_granted": False,
    }
    write_json(output / "summary.json", summary)
    write_json(output / "authorities.json", authority_rows)
    write_json(output / "conflicts.json", conflicts)

    lock_root = output / "locks"
    for row in authorized:
        descriptor = {
            "schema": SCHEMA,
            "source": row["source"],
            "version": row["version"],
            "binary_packages": row["binary_packages"],
            "authority": row["authority"],
            "release_asset": row["release_asset"],
            "evidence": row["evidence"],
            "native_arm64_build_status": "pending",
            "build_credit_granted": False,
        }
        write_json(
            lock_root / safe(row["source"]) / safe(row["version"]) / "authority.json",
            descriptor,
        )

    tsv_lines = ["source\tversion\tauthorized\tauthority\treason"]
    for row in authority_rows:
        tsv_lines.append(
            "\t".join(
                [
                    row["source"],
                    row["version"],
                    "yes" if row["authorized"] else "no",
                    row["authority"],
                    row["reason"].replace("\t", " ").replace("\n", " "),
                ]
            )
        )
    (output / "authorities.tsv").write_text("\n".join(tsv_lines) + "\n", encoding="utf-8")

    lines = [
        "# Exact source authority v3",
        "",
        f"- Newly authorized exact sources: **{len(authorized)}**",
        f"- Remaining reference source blockers: **{len(unresolved)}**",
        f"- Native ARM64 build blockers retained: **{native_build_blockers}**",
        f"- Conflicts: **{len(conflicts)}**",
        "",
        "| Source | Exact version | Source authority | ARM64 build |",
        "|---|---|---|---|",
    ]
    for row in authority_rows:
        lines.append(
            f"| `{row['source']}` | `{row['version']}` | "
            f"{row['authority'] if row['authorized'] else 'blocked'} | pending |"
        )
    lines.extend(
        [
            "",
            "Source authorization does not grant native ARM64 build credit.",
            "ISO assembly remains disabled until the independent native-build gates pass.",
            "",
        ]
    )
    (output / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
