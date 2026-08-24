#!/usr/bin/env python3
"""Comparison-only audit for an exact vendor DEB and a public Git baseline."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import audit_gooroom_greeter_han3u2 as common


def run(command: list[str]) -> str:
    env = os.environ.copy()
    env["LC_ALL"] = "C.UTF-8"
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr[-4000:]}"
        )
    return completed.stdout


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def control_fields(deb: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    current = ""
    for line in run(["dpkg-deb", "-f", str(deb)]).splitlines():
        if line[:1].isspace() and current:
            fields[current] += "\n" + line[1:]
        elif ":" in line:
            current, value = line.split(":", 1)
            current = current.strip()
            fields[current] = value.lstrip()
    return fields


def package_record(deb: Path) -> dict[str, Any]:
    return {
        "filename": deb.name,
        "bytes": deb.stat().st_size,
        "sha256": common.sha256_file(deb),
        "control": control_fields(deb),
    }


def verify(record: dict[str, Any], expected: dict[str, Any], role: str) -> None:
    control = record["control"]
    actual_source = control.get("Source", control.get("Package", "")).split(" ", 1)[0]
    pairs = {
        "Package": (control.get("Package", ""), expected["package"]),
        "Version": (control.get("Version", ""), expected["version"]),
        "Architecture": (control.get("Architecture", ""), expected["architecture"]),
        "Source": (actual_source, expected["source"]),
    }
    if expected.get("sha256"):
        pairs["SHA256"] = (record["sha256"], expected["sha256"])
    mismatch = {
        key: {"actual": actual, "expected": wanted}
        for key, (actual, wanted) in pairs.items()
        if actual != wanted
    }
    if mismatch:
        raise RuntimeError(f"{role} identity mismatch: {mismatch}")


def normalized(text: str) -> list[str]:
    return [re.sub(r"\s+", " ", line.strip()) for line in text.splitlines() if line.strip()]


def elf_record(path: Path) -> dict[str, Any]:
    header: dict[str, str] = {}
    for line in run(["readelf", "-hW", str(path)]).splitlines():
        match = re.match(r"\s*([^:]+):\s*(.*)$", line)
        if match:
            header[match.group(1).strip()] = match.group(2).strip()

    section_lines = normalized(run(["readelf", "-SW", str(path)]))
    section_names = []
    for line in section_lines:
        match = re.match(r"\[\s*\d+\]\s+(\S+)", line)
        if match:
            section_names.append(match.group(1))

    dynamic_lines = normalized(run(["readelf", "-dW", str(path)]))
    needed = sorted(
        set(
            match.group(1)
            for line in dynamic_lines
            for match in [re.search(r"\(NEEDED\).*?\[(.*?)\]", line)]
            if match
        )
    )

    symbol_lines = run(["readelf", "-WsW", str(path)]).splitlines()
    imports: set[str] = set()
    exports: set[str] = set()
    for line in symbol_lines:
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].rstrip(":").isdigit():
            continue
        _, _, _, _, bind, visibility, index, name = parts
        if index == "UND":
            imports.add(name)
        elif bind in {"GLOBAL", "WEAK", "GNU_UNIQUE"} and visibility in {
            "DEFAULT",
            "PROTECTED",
        }:
            exports.add(name)

    notes = run(["readelf", "-nW", str(path)])
    build_ids = sorted(set(re.findall(r"Build ID:\s*([0-9a-f]+)", notes, re.I)))
    semantic = {
        "class": header.get("Class"),
        "data": header.get("Data"),
        "type": header.get("Type"),
        "machine": header.get("Machine"),
        "os_abi": header.get("OS/ABI"),
        "section_names": section_names,
        "sections_sha256": hashlib.sha256("\n".join(section_lines).encode()).hexdigest(),
        "needed": needed,
        "imports": sorted(imports),
        "exports": sorted(exports),
    }
    return {
        "bytes": path.stat().st_size,
        "sha256": common.sha256_file(path),
        "build_ids": [value.lower() for value in build_ids],
        "semantic": semantic,
        "semantic_sha256": sha256_json(semantic),
    }


def extract(deb: Path, payload: Path, control: Path) -> None:
    payload.mkdir()
    control.mkdir()
    run(["dpkg-deb", "-x", str(deb), str(payload)])
    run(["dpkg-deb", "-e", str(deb), str(control)])


def elf_map(root: Path, inventory: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        relative: elf_record(root / relative)
        for relative, item in inventory.items()
        if item.get("elf") is True
    }


def compare(
    target: dict[str, dict[str, Any]],
    base: dict[str, dict[str, Any]],
    target_elf: dict[str, Any],
    base_elf: dict[str, Any],
) -> dict[str, Any]:
    target_paths = set(target)
    base_paths = set(base)
    changed = []
    non_elf_changes = []
    elf_changes = []
    symlink_changes = []
    for path in sorted(target_paths & base_paths):
        left, right = base[path], target[path]
        if left == right:
            continue
        fields = sorted(key for key in set(left) | set(right) if left.get(key) != right.get(key))
        changed.append({"path": path, "fields": fields})
        if left.get("type") == right.get("type") == "symlink":
            symlink_changes.append(
                {"path": path, "base": left.get("target"), "target": right.get("target")}
            )
        elif not left.get("elf") and not right.get("elf") and left.get("sha256") != right.get("sha256"):
            non_elf_changes.append(
                {"path": path, "base_sha256": left.get("sha256"), "target_sha256": right.get("sha256")}
            )
        elif path in target_elf and path in base_elf:
            semantic_fields = sorted(
                key
                for key in set(target_elf[path]["semantic"]) | set(base_elf[path]["semantic"])
                if target_elf[path]["semantic"].get(key) != base_elf[path]["semantic"].get(key)
            )
            if semantic_fields:
                elf_changes.append(
                    {
                        "path": path,
                        "fields": semantic_fields,
                        "base_semantic_sha256": base_elf[path]["semantic_sha256"],
                        "target_semantic_sha256": target_elf[path]["semantic_sha256"],
                    }
                )
    return {
        "target_only": sorted(target_paths - base_paths),
        "base_only": sorted(base_paths - target_paths),
        "common_count": len(target_paths & base_paths),
        "changed_common": changed,
        "non_elf_hash_changes": non_elf_changes,
        "elf_semantic_changes": elf_changes,
        "symlink_changes": symlink_changes,
    }


def control_delta(target: dict[str, str], base: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {"field": key, "base": base.get(key), "target": target.get(key)}
        for key in sorted(set(target) | set(base))
        if target.get(key) != base.get(key)
    ]


def markdown(report: dict[str, Any]) -> str:
    delta = report["comparison"]["payload"]
    lines = [
        "# Hancom delta audit: gooroom-applauncher-applet",
        "",
        "Comparison-only evidence; missing Hancom source is not claimed as recovered.",
        "",
        f"- Source status: `{report['source_status']}`",
        f"- Reconstruction status: `{report['reconstruction_status']}`",
        f"- Byte identity claimed: `{str(report['byte_identity_claimed']).lower()}`",
        f"- Target SHA-256: `{report['packages']['target']['sha256']}`",
        f"- Public commit: `{report['authority']['base_source']['commit']}`",
        f"- Public tree: `{report['authority']['base_source']['tree']}`",
        "",
        "## Counts",
        "",
        f"- Target-only: {len(delta['target_only'])}",
        f"- Base-only: {len(delta['base_only'])}",
        f"- Changed common: {len(delta['changed_common'])}",
        f"- Non-ELF changes: {len(delta['non_elf_hash_changes'])}",
        f"- ELF semantic changes: {len(delta['elf_semantic_changes'])}",
        f"- Symlink changes: {len(delta['symlink_changes'])}",
        f"- Control changes: {len(report['comparison']['control_fields'])}",
        "",
        "## Interpretation gate",
        "",
        "Every material payload and ELF delta must be explained before reconstruction or ARM64 promotion. `audit_complete` does not mean source recovery.",
        "",
    ]
    for title, paths in (
        ("Target-only paths", delta["target_only"]),
        ("Base-only paths", delta["base_only"]),
        ("Changed common paths", [item["path"] for item in delta["changed_common"]]),
    ):
        lines.extend([f"## {title}", ""])
        lines.extend([f"- `{path}`" for path in paths[:200]] or ["None."])
        lines.append("")
    return "\n".join(lines)


def build(target_deb: Path, base_deb: Path, lock: dict[str, Any]) -> dict[str, Any]:
    target_record = package_record(target_deb)
    base_record = package_record(base_deb)
    verify(target_record, lock["target"], "target")
    verify(
        base_record,
        {
            "package": lock["target"]["package"],
            "source": lock["target"]["source"],
            "version": lock["base_source"]["version"],
            "architecture": lock["target"]["architecture"],
        },
        "base",
    )
    with tempfile.TemporaryDirectory(prefix="hancom-delta-") as temporary:
        root = Path(temporary)
        tp, tc, bp, bc = (root / name for name in ("tp", "tc", "bp", "bc"))
        extract(target_deb, tp, tc)
        extract(base_deb, bp, bc)
        target_manifest = common.manifest(tp)
        base_manifest = common.manifest(bp)
        target_control = common.manifest(tc)
        base_control = common.manifest(bc)
        target_elf = elf_map(tp, target_manifest)
        base_elf = elf_map(bp, base_manifest)
    target_record.update({"payload": target_manifest, "elf": target_elf, "control_archive": target_control})
    base_record.update({"payload": base_manifest, "elf": base_elf, "control_archive": base_control})
    comparison = {
        "control_fields": control_delta(target_record["control"], base_record["control"]),
        "control_archive": compare(target_control, base_control, {}, {}),
        "payload": compare(target_manifest, base_manifest, target_elf, base_elf),
    }
    report = {
        "schema": 1,
        "policy": "exact-vendor-amd64-binary-vs-version-matched-public-git-baseline",
        "source_status": "comparison-only",
        "reconstruction_status": "not-attempted",
        "byte_identity_claimed": False,
        "authority": {
            "artifact": lock["artifact"],
            "target": lock["target"],
            "base_source": lock["base_source"],
        },
        "packages": {"target": target_record, "base": base_record},
        "comparison": comparison,
        "audit_complete": True,
    }
    report["comparison_sha256"] = sha256_json(comparison)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-deb", type=Path, required=True)
    parser.add_argument("--base-deb", type=Path, required=True)
    parser.add_argument("--input-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = build(args.target_deb, args.base_deb, load(args.input_lock))
    common.write_json(args.output_dir / "audit.json", report)
    (args.output_dir / "audit-summary.md").write_text(markdown(report), encoding="utf-8")
    print(json.dumps({
        "audit_complete": True,
        "comparison_sha256": report["comparison_sha256"],
        "target_only": len(report["comparison"]["payload"]["target_only"]),
        "base_only": len(report["comparison"]["payload"]["base_only"]),
        "changed_common": len(report["comparison"]["payload"]["changed_common"]),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
