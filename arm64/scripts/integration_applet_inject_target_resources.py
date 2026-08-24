#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def command(arguments: list[str], *, text: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_unique(root: Path, filename: str) -> Path:
    matches = sorted(path for path in root.rglob(filename) if path.is_file())
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one {filename} below {root}, found {len(matches)}"
        )
    return matches[0]


def manifests(source: Path) -> list[Path]:
    result = {
        path
        for pattern in ("gresource.xml", "*.gresource.xml", "*gresources.xml")
        for path in source.rglob(pattern)
        if path.is_file()
    }
    return sorted(result)


def target_resources(binary: Path) -> dict[str, bytes]:
    listed = command(["gresource", "list", str(binary)], text=True).stdout
    result: dict[str, bytes] = {}
    for resource_path in sorted(line.strip() for line in listed.splitlines() if line.strip()):
        result[resource_path] = command(
            ["gresource", "extract", str(binary), resource_path]
        ).stdout
    if not result:
        raise RuntimeError(f"no GResources were extracted from {binary}")
    return result


def normalized_prefix(value: str | None) -> str:
    if not value:
        return ""
    value = "/" + value.strip("/")
    return "" if value == "/" else value


def resource_path(prefix: str, alias: str) -> str:
    return f"{prefix}/{alias.lstrip('/')}" if prefix else f"/{alias.lstrip('/')}"


def relative_reference(path: Path, manifest: Path) -> str:
    return path.relative_to(manifest.parent).as_posix()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()

    source = Path(arguments.source).resolve()
    target_root = Path(arguments.target_root).resolve()
    output = Path(arguments.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    target_binary = find_unique(target_root, "libgooroom-integration-applet.so")
    target = target_resources(target_binary)
    target_names = set(target)

    manifest_paths = manifests(source)
    if not manifest_paths:
        raise RuntimeError("no source GResource manifests were found")

    documents: dict[Path, ET.ElementTree] = {}
    groups: list[dict[str, Any]] = []
    mapped: dict[str, dict[str, Any]] = {}

    for manifest in manifest_paths:
        tree = ET.parse(manifest)
        documents[manifest] = tree
        for group in tree.getroot().findall(".//gresource"):
            prefix = normalized_prefix(group.attrib.get("prefix"))
            descriptor = {
                "manifest": manifest,
                "tree": tree,
                "group": group,
                "prefix": prefix,
            }
            groups.append(descriptor)
            for element in list(group.findall("file")):
                reference = (element.text or "").strip()
                if not reference:
                    continue
                alias = element.attrib.get("alias") or reference
                full_path = resource_path(prefix, alias)
                mapped[full_path] = {
                    **descriptor,
                    "element": element,
                    "reference": reference,
                    "alias": alias,
                }

    removed: list[dict[str, Any]] = []
    for full_path in sorted(set(mapped) - target_names):
        row = mapped[full_path]
        row["group"].remove(row["element"])
        removed.append(
            {
                "resource_path": full_path,
                "manifest": row["manifest"].relative_to(source).as_posix(),
                "reference": row["reference"],
            }
        )
        mapped.pop(full_path, None)

    injected: list[dict[str, Any]] = []
    for full_path in sorted(target_names - set(mapped)):
        candidates = [
            group
            for group in groups
            if not group["prefix"]
            or full_path == group["prefix"]
            or full_path.startswith(group["prefix"] + "/")
        ]
        if not candidates:
            raise RuntimeError(f"no compatible GResource prefix for {full_path}")
        selected = max(candidates, key=lambda row: len(row["prefix"]))
        prefix = selected["prefix"]
        alias = full_path[len(prefix) :].lstrip("/") if prefix else full_path.lstrip("/")
        recovered = selected["manifest"].parent / "vendor-recovered" / alias
        recovered.parent.mkdir(parents=True, exist_ok=True)
        recovered.write_bytes(target[full_path])

        element = ET.SubElement(selected["group"], "file", {"alias": alias})
        element.text = relative_reference(recovered, selected["manifest"])
        mapped[full_path] = {
            **selected,
            "element": element,
            "reference": element.text,
            "alias": alias,
        }
        injected.append(
            {
                "resource_path": full_path,
                "manifest": selected["manifest"].relative_to(source).as_posix(),
                "source_path": recovered.relative_to(source).as_posix(),
                "alias": alias,
                "size": len(target[full_path]),
                "sha256": sha256(target[full_path]),
            }
        )

    replaced: list[dict[str, Any]] = []
    missing_source_files: list[str] = []
    for full_path in sorted(target_names & set(mapped)):
        row = mapped[full_path]
        file_path = row["manifest"].parent / row["reference"]
        if not file_path.exists():
            missing_source_files.append(file_path.relative_to(source).as_posix())
            file_path.parent.mkdir(parents=True, exist_ok=True)
        previous = file_path.read_bytes() if file_path.exists() else None
        payload = target[full_path]
        file_path.write_bytes(payload)
        replaced.append(
            {
                "resource_path": full_path,
                "source_path": file_path.relative_to(source).as_posix(),
                "changed": previous != payload,
                "previous_sha256": sha256(previous) if previous is not None else None,
                "target_sha256": sha256(payload),
                "size": len(payload),
            }
        )

    for manifest, tree in documents.items():
        try:
            ET.indent(tree, space="  ")
        except AttributeError:
            pass
        tree.write(manifest, encoding="utf-8", xml_declaration=True)

    final_names = set(mapped)
    report = {
        "schema": 1,
        "source": "gooroom-integration-applet",
        "target_binary": target_binary.relative_to(target_root).as_posix(),
        "target_resource_count": len(target_names),
        "source_manifest_count": len(manifest_paths),
        "final_manifest_resource_count": len(final_names),
        "resource_path_set_exact": final_names == target_names,
        "injected_resource_count": len(injected),
        "removed_resource_count": len(removed),
        "replaced_resource_count": len(replaced),
        "changed_replacement_count": sum(bool(row["changed"]) for row in replaced),
        "injected": injected,
        "removed": removed,
        "replaced": replaced,
        "missing_source_files_recreated": missing_source_files,
        "target_only_after_reconstruction": sorted(target_names - final_names),
        "source_only_after_reconstruction": sorted(final_names - target_names),
    }
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not report["resource_path_set_exact"]:
        raise RuntimeError("reconstructed GResource path set is not exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
