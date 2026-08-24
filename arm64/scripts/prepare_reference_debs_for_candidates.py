#!/usr/bin/env python3
"""Extract exact AMD64 reference .debs for quarantined source candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recover_exact_sources_from_reference_apt import (  # noqa: E402
    download_url,
    hash_file,
    load_repo_entries,
    url_join,
    variant_uris,
    write_json,
)

SCHEMA = 1


def choose_stanza(target: dict[str, Any], package: str) -> dict[str, Any] | None:
    rows = []
    for stanza in target.get("package_index_stanzas", []):
        if stanza.get("package") != package:
            continue
        if not stanza.get("filename") or not stanza.get("sha256"):
            continue
        rows.append(stanza)
    if not rows:
        return None
    rows.sort(
        key=lambda row: (
            0 if row.get("index_path", "").startswith("iso:/") else 1,
            row.get("index_path", ""),
            row.get("filename", ""),
        )
    )
    return rows[0]


def family_from_index_path(value: str) -> str | None:
    lower = value.lower()
    if "_hancom_" in lower or "hancom_dists_hancom" in lower or "iso:/dists/hancom" in lower:
        return "hancom"
    if "_gooroom_" in lower or "gooroom_dists_gooroom" in lower or "iso:/dists/gooroom" in lower:
        return "gooroom"
    return None


def extract_from_iso(iso: Path, filename: str, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.run(
        [
            "xorriso",
            "-osirrox",
            "on",
            "-indev",
            str(iso),
            "-extract",
            "/" + filename.lstrip("/"),
            str(destination),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "method": "reference-iso",
        "returncode": process.returncode,
        "stdout": process.stdout[-4000:],
        "stderr": process.stderr[-4000:],
        "ok": process.returncode == 0 and destination.is_file(),
    }


def repository_urls(stanza: dict[str, Any], entries: list[Any]) -> list[str]:
    family = family_from_index_path(stanza.get("index_path", ""))
    urls: list[str] = []
    for entry in entries:
        entry_family = entry.path.rsplit("/", 1)[-1]
        if family and entry_family != family:
            continue
        for uri in variant_uris(entry.uri):
            urls.append(url_join(uri, stanza["filename"]))
    return list(dict.fromkeys(urls))


def acquire_reference_deb(
    iso: Path,
    stanza: dict[str, Any],
    entries: list[Any],
    destination: Path,
) -> tuple[bool, list[dict[str, Any]]]:
    probes: list[dict[str, Any]] = []
    expected_hash = stanza["sha256"]
    expected_size = int(stanza["size"]) if str(stanza.get("size", "")).isdigit() else None

    probe = extract_from_iso(iso, stanza["filename"], destination)
    if probe["ok"]:
        probe["size"] = destination.stat().st_size
        probe["sha256"] = hash_file(destination)
        probe["size_match"] = expected_size is None or probe["size"] == expected_size
        probe["sha256_match"] = probe["sha256"] == expected_hash
        probes.append(probe)
        if probe["size_match"] and probe["sha256_match"]:
            return True, probes
        destination.unlink(missing_ok=True)
    else:
        probes.append(probe)

    for url in repository_urls(stanza, entries):
        probe = download_url(url, destination)
        probe["method"] = "official-repository"
        probe["size_match"] = expected_size is None or probe["size"] == expected_size
        probe["sha256_match"] = probe["sha256"] == expected_hash
        probes.append(probe)
        if probe["ok"] and probe["size_match"] and probe["sha256_match"]:
            return True, probes
        destination.unlink(missing_ok=True)
    return False, probes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-iso", type=Path, required=True)
    parser.add_argument("--reference-evidence", type=Path, required=True)
    parser.add_argument("--bundle-authority", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    iso = args.reference_iso.resolve()
    evidence = args.reference_evidence.resolve()
    bundle_authority = args.bundle_authority.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    bundle_rows = json.loads((bundle_authority / "release-assets.json").read_text())
    candidate_sources = sorted(
        {row["source"] for row in bundle_rows if row.get("category") == "candidate"}
    )
    targets = json.loads((evidence / "target-findings.json").read_text())
    target_by_source = {row["source"]: row for row in targets}
    entries = load_repo_entries(evidence)

    source_results: list[dict[str, Any]] = []
    all_probes: list[dict[str, Any]] = []
    for source in candidate_sources:
        target = target_by_source.get(source)
        if target is None:
            source_results.append(
                {
                    "source": source,
                    "status": "missing-reference-target",
                    "complete": False,
                    "packages": [],
                }
            )
            continue
        source_dir = output / "debs" / source
        source_dir.mkdir(parents=True, exist_ok=True)
        package_results: list[dict[str, Any]] = []
        for package in target.get("binary_packages", []):
            stanza = choose_stanza(target, package)
            if stanza is None:
                package_results.append(
                    {
                        "package": package,
                        "status": "missing-exact-package-stanza",
                        "recovered": False,
                    }
                )
                continue
            destination = source_dir / Path(stanza["filename"]).name
            recovered, probes = acquire_reference_deb(
                iso, stanza, entries, destination
            )
            all_probes.extend(
                [{**probe, "source": source, "package": package} for probe in probes]
            )
            package_results.append(
                {
                    "package": package,
                    "version": stanza["version"],
                    "architecture": stanza["architecture"],
                    "filename": stanza["filename"],
                    "reference_sha256": stanza["sha256"],
                    "reference_size": int(stanza["size"]) if str(stanza.get("size", "")).isdigit() else None,
                    "recovered": recovered,
                    "artifact_path": str(destination.relative_to(output)) if recovered else "",
                    "verified_sha256": hash_file(destination) if recovered else "",
                    "verified_size": destination.stat().st_size if recovered else 0,
                }
            )
        complete = bool(package_results) and all(row.get("recovered") for row in package_results)
        source_results.append(
            {
                "source": source,
                "version": target["source_version"],
                "status": "complete" if complete else "incomplete",
                "complete": complete,
                "packages": package_results,
            }
        )

    summary = {
        "schema": SCHEMA,
        "policy": "exact-reference-package-stanza-sha256-from-locked-iso-or-official-repository",
        "candidate_source_count": len(candidate_sources),
        "complete_source_count": sum(row["complete"] for row in source_results),
        "incomplete_source_count": sum(not row["complete"] for row in source_results),
        "reference_deb_count": sum(
            row.get("recovered", False)
            for source in source_results
            for row in source.get("packages", [])
        ),
        "network_probe_count": len(all_probes),
    }
    write_json(output / "summary.json", summary)
    write_json(output / "sources.json", source_results)
    write_json(output / "network-probes.json", all_probes)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
