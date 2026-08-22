#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


EXPECTED_PACKAGE = "gooroom-integration-applet"
EXPECTED_VERSION = "0.3.1+grm3u1+han3u3"
EXPECTED_ENTRIES = 67
EXPECTED_ELFS = 2


def run(*args: str, text: bool = True) -> str:
    p = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text)
    return p.stdout if text else p.stdout


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def control(deb: Path) -> dict[str, str]:
    fields = [
        "Package", "Source", "Version", "Architecture", "Maintainer",
        "Section", "Priority", "Depends", "Description"
    ]
    out = {}
    for field in fields:
        p = subprocess.run(
            ["dpkg-deb", "-f", str(deb), field],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        out[field] = p.stdout.rstrip("\n") if p.returncode == 0 else ""
    return out


def canonical_path(rel: str) -> str:
    # Cross-architecture Debian multiarch directories are semantically the same
    # payload location even though the triplet necessarily changes.
    rel = rel.replace("x86_64-linux-gnu", "{multiarch}")
    rel = rel.replace("aarch64-linux-gnu", "{multiarch}")
    return rel


def entries(root: Path) -> dict[str, dict]:
    result = {}
    for p in sorted(root.rglob("*")):
        raw_rel = p.relative_to(root).as_posix()
        rel = canonical_path(raw_rel)
        if rel in result:
            raise RuntimeError(f"canonical path collision: {raw_rel} -> {rel}")
        mode = p.lstat().st_mode & 0o7777
        if p.is_symlink():
            target = os.readlink(p)
            target = target.replace("x86_64-linux-gnu", "{multiarch}").replace(
                "aarch64-linux-gnu", "{multiarch}"
            )
            result[rel] = {"kind": "symlink", "target": target, "mode": mode, "raw_path": raw_rel}
        elif p.is_dir():
            result[rel] = {"kind": "dir", "mode": mode, "raw_path": raw_rel}
        elif p.is_file():
            data = p.read_bytes()[:4]
            if data == b"\x7fELF":
                result[rel] = {"kind": "elf", "mode": mode, "raw_path": raw_rel}
            else:
                result[rel] = {
                    "kind": "file",
                    "sha256": sha256(p),
                    "size": p.stat().st_size,
                    "mode": mode,
                    "raw_path": raw_rel,
                }
        else:
            result[rel] = {"kind": "other", "mode": mode, "raw_path": raw_rel}
    return result


def elf_machine(path: Path) -> str:
    text = run("readelf", "-h", str(path))
    m = re.search(r"^\s*Machine:\s*(.+?)\s*$", text, re.M)
    if not m:
        raise RuntimeError(f"cannot parse ELF machine: {path}")
    return m.group(1)


def needed(path: Path) -> list[str]:
    text = run("readelf", "-dW", str(path))
    return sorted(re.findall(r"\(NEEDED\).*Shared library: \[(.*?)\]", text))


def soname(path: Path) -> str:
    text = run("readelf", "-dW", str(path))
    m = re.search(r"\(SONAME\).*Library soname: \[(.*?)\]", text)
    return m.group(1) if m else ""


def dyn_symbols(path: Path) -> dict[str, list[str]]:
    text = run("readelf", "--dyn-syms", "--wide", str(path))
    imported, exported = set(), set()
    # readelf columns: Num Value Size Type Bind Vis Ndx Name
    for line in text.splitlines():
        m = re.match(
            r"\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$",
            line,
        )
        if not m:
            continue
        typ, bind, vis, ndx, name = m.groups()
        name = name.split()[0]
        if not name or name == "0":
            continue
        # Version suffixes are ABI metadata, so retain them.
        rec = f"{name}|{typ}|{bind}|{vis}"
        if ndx == "UND":
            imported.add(rec)
        elif bind in {"GLOBAL", "WEAK"}:
            exported.add(rec)
    return {"imports": sorted(imported), "exports": sorted(exported)}


def normalize_depends(value: str) -> list[str]:
    return sorted(re.sub(r"\s+", " ", x.strip()) for x in value.split(",") if x.strip())


def find_amd64_deb(artifact: Path) -> Path:
    name = f"{EXPECTED_PACKAGE}_{EXPECTED_VERSION}_amd64.deb"
    candidates = list(artifact.rglob(name))
    if not candidates:
        raise RuntimeError(f"exact AMD64 package not found in authority artifact: {name}")

    def score(p: Path):
        s = p.as_posix()
        # Prefer the downloaded vendor target over the reconstructed build.
        pri = 0
        if "/downloads/" in s:
            pri -= 100
        if "/target" in s:
            pri -= 50
        if "/build-output/" in s:
            pri += 50
        return (pri, len(s), s)

    candidates.sort(key=score)
    return candidates[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--authority-artifact", required=True)
    ap.add_argument("--arm64-deb", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--authority-run-id", required=True)
    ap.add_argument("--authority-artifact-id", required=True)
    ap.add_argument("--authority-artifact-digest", required=True)
    ap.add_argument("--authority-summary-sha256", required=True)
    ap.add_argument("--trigger-sha", required=True)
    ap.add_argument("--bullseye-base-digest", required=True)
    ap.add_argument("--nimf-source-commit", required=True)
    ap.add_argument("--nimf-source-tree", required=True)
    a = ap.parse_args()

    artifact = Path(a.authority_artifact).resolve()
    armdeb = Path(a.arm64_deb).resolve()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    amddeb = find_amd64_deb(artifact)
    arm_ctl = control(armdeb)
    amd_ctl = control(amddeb)

    if arm_ctl["Package"] != EXPECTED_PACKAGE:
        raise SystemExit(f"wrong ARM64 Package: {arm_ctl['Package']}")
    if arm_ctl["Version"] != EXPECTED_VERSION:
        raise SystemExit(f"wrong ARM64 Version: {arm_ctl['Version']}")
    if arm_ctl["Architecture"] != "arm64":
        raise SystemExit(f"wrong ARM64 Architecture: {arm_ctl['Architecture']}")
    if amd_ctl["Package"] != EXPECTED_PACKAGE or amd_ctl["Version"] != EXPECTED_VERSION:
        raise SystemExit("authority AMD64 package has wrong identity")
    if amd_ctl["Architecture"] != "amd64":
        raise SystemExit("authority reference is not amd64")

    semantic_fields = ["Package", "Source", "Version", "Maintainer", "Section", "Priority", "Description"]
    control_diffs = {
        f: {"amd64": amd_ctl[f], "arm64": arm_ctl[f]}
        for f in semantic_fields if amd_ctl[f] != arm_ctl[f]
    }
    depends_equal = normalize_depends(amd_ctl["Depends"]) == normalize_depends(arm_ctl["Depends"])
    control_ok = not control_diffs and depends_equal

    with tempfile.TemporaryDirectory(prefix="han3-native-verify-") as td:
        td = Path(td)
        amdroot, armroot = td / "amd64", td / "arm64"
        amdroot.mkdir()
        armroot.mkdir()
        run("dpkg-deb", "-x", str(amddeb), str(amdroot))
        run("dpkg-deb", "-x", str(armdeb), str(armroot))

        amd_entries = entries(amdroot)
        arm_entries = entries(armroot)
        path_equal = set(amd_entries) == set(arm_entries)

        mismatches = []
        if path_equal:
            for rel in sorted(amd_entries):
                x, y = amd_entries[rel], arm_entries[rel]
                xcmp = {k: val for k, val in x.items() if k != "raw_path"}
                ycmp = {k: val for k, val in y.items() if k != "raw_path"}
                if x["kind"] != y["kind"]:
                    mismatches.append({"path": rel, "reason": "kind", "amd64": x, "arm64": y})
                elif x["kind"] != "elf" and xcmp != ycmp:
                    mismatches.append({"path": rel, "reason": "architecture-neutral-payload", "amd64": x, "arm64": y})
                elif x["kind"] == "elf" and x["mode"] != y["mode"]:
                    mismatches.append({"path": rel, "reason": "elf-mode", "amd64": x, "arm64": y})
        else:
            missing_arm = sorted(set(amd_entries) - set(arm_entries))
            extra_arm = sorted(set(arm_entries) - set(amd_entries))
            mismatches.append({"reason": "path-inventory", "missing_arm64": missing_arm, "extra_arm64": extra_arm})

        amd_elfs = sorted(k for k, v in amd_entries.items() if v["kind"] == "elf")
        arm_elfs = sorted(k for k, v in arm_entries.items() if v["kind"] == "elf")
        elf_paths_equal = amd_elfs == arm_elfs

        elf_records = []
        elf_ok = elf_paths_equal
        x86_count = 0
        if elf_paths_equal:
            for rel in arm_elfs:
                apath = armroot / arm_entries[rel]["raw_path"]
                xpath = amdroot / amd_entries[rel]["raw_path"]
                am = elf_machine(apath)
                xm = elf_machine(xpath)
                if "AArch64" not in am:
                    elf_ok = False
                if "X86-64" in am or "80386" in am or "x86" in am.lower():
                    x86_count += 1
                    elf_ok = False
                if "X86-64" not in xm:
                    elf_ok = False

                an, xn = needed(apath), needed(xpath)
                aso, xso = soname(apath), soname(xpath)
                asym, xsym = dyn_symbols(apath), dyn_symbols(xpath)
                rec_ok = an == xn and aso == xso and asym == xsym
                elf_ok = elf_ok and rec_ok
                elf_records.append({
                    "path": rel,
                    "amd64_machine": xm,
                    "arm64_machine": am,
                    "needed_equal": an == xn,
                    "amd64_needed": xn,
                    "arm64_needed": an,
                    "soname_equal": aso == xso,
                    "amd64_soname": xso,
                    "arm64_soname": aso,
                    "dynamic_symbols_equal": asym == xsym,
                    "amd64_dynamic_symbols": xsym,
                    "arm64_dynamic_symbols": asym,
                    "ok": rec_ok and "AArch64" in am and "X86-64" in xm,
                })

        non_elf_ok = not mismatches
        counts_ok = len(arm_entries) == EXPECTED_ENTRIES and len(arm_elfs) == EXPECTED_ELFS

        summary = {
            "schema": 1,
            "status": "ok" if all([control_ok, path_equal, non_elf_ok, elf_ok, counts_ok, x86_count == 0]) else "failed",
            "package": EXPECTED_PACKAGE,
            "version": EXPECTED_VERSION,
            "architecture": "arm64",
            "arm64_deb": armdeb.name,
            "arm64_deb_sha256": sha256(armdeb),
            "amd64_authority_deb": str(amddeb.relative_to(artifact)),
            "amd64_authority_deb_sha256": sha256(amddeb),
            "entry_count": len(arm_entries),
            "authority_entry_count": len(amd_entries),
            "elf_count": len(arm_elfs),
            "authority_elf_count": len(amd_elfs),
            "x86_elf_count": x86_count,
            "path_inventory_equal": path_equal,
            "non_elf_payload_equal": non_elf_ok,
            "elf_semantics_equal": elf_ok,
            "control_semantics_equal": control_ok,
            "native_arm64_candidate_verified": all([control_ok, path_equal, non_elf_ok, elf_ok, counts_ok, x86_count == 0]),
            "package_promotion_allowed": all([control_ok, path_equal, non_elf_ok, elf_ok, counts_ok, x86_count == 0]),
            "package_promoted": False,
            "iso_assembly_allowed": False,
            "fail_closed": True,
            "provenance": {
                "amd64_authority_run_id": a.authority_run_id,
                "amd64_authority_artifact_id": a.authority_artifact_id,
                "amd64_authority_artifact_digest": a.authority_artifact_digest,
                "amd64_authority_summary_sha256": a.authority_summary_sha256,
                "native_trigger_sha": a.trigger_sha,
                "runner": "ubuntu-24.04-arm",
                "bullseye_base_digest": a.bullseye_base_digest,
                "nimf_source_commit": a.nimf_source_commit,
                "nimf_source_tree": a.nimf_source_tree,
            },
        }

        (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        (out / "control-comparison.json").write_text(json.dumps({
            "ok": control_ok,
            "semantic_field_differences": control_diffs,
            "depends_equal": depends_equal,
            "amd64": amd_ctl,
            "arm64": arm_ctl,
        }, indent=2, sort_keys=True) + "\n")
        (out / "payload-comparison.json").write_text(json.dumps({
            "ok": path_equal and non_elf_ok,
            "path_inventory_equal": path_equal,
            "amd64_entry_count": len(amd_entries),
            "arm64_entry_count": len(arm_entries),
            "mismatches": mismatches,
        }, indent=2, sort_keys=True) + "\n")
        (out / "elf-comparison.json").write_text(json.dumps({
            "ok": elf_ok and x86_count == 0,
            "paths_equal": elf_paths_equal,
            "amd64_elf_paths": amd_elfs,
            "arm64_elf_paths": arm_elfs,
            "records": elf_records,
        }, indent=2, sort_keys=True) + "\n")
        (out / "package-sha256.txt").write_text(f"{sha256(armdeb)}  {armdeb.name}\n")

        print(json.dumps(summary, indent=2, sort_keys=True))
        if summary["status"] != "ok":
            raise SystemExit("native ARM64 candidate verification failed closed")


if __name__ == "__main__":
    main()
