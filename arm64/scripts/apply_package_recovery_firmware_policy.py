#!/usr/bin/env python3
"""Apply the firmware-aware exact-package recovery policy once, fail closed."""

from __future__ import annotations

from pathlib import Path


BASE = Path("arm64/scripts/recover_exact_arm64_package_pool.py")
SUMMARIZER = Path("arm64/scripts/summarize_recovered_package_blockers.py")
WORKFLOW = Path(".github/workflows/arm64-recover-exact-package-pool.yml")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def patch_base() -> None:
    text = BASE.read_text(encoding="utf-8")
    marker = '"embedded_firmware": embedded_firmware'
    if marker in text:
        print(f"already patched: {BASE}")
        return

    text = replace_once(
        text,
        "package under an explicit architecture rule, has an exact source version, uses\n"
        "arm64/all architecture as required, and contains no x86 ELF payload. The script\n"
        "never substitutes a newer/older source and never hides an uncovered package.",
        "package under an explicit architecture rule, has an exact source version, uses\n"
        "arm64/all architecture as required, and contains no x86 host ELF payload. ELF-\n"
        "formatted device firmware under /lib/firmware or /usr/lib/firmware is retained\n"
        "and reported separately. The script never substitutes a newer/older source and\n"
        "never hides an uncovered package.",
        "module policy documentation",
    )
    text = replace_once(
        text,
        "def audit_payload(deb: Path) -> dict[str, Any]:\n"
        "    x86: list[dict[str, Any]] = []\n"
        "    foreign: list[dict[str, Any]] = []\n"
        "    machines: dict[str, int] = {}",
        "def audit_payload(deb: Path) -> dict[str, Any]:\n"
        "    x86: list[dict[str, Any]] = []\n"
        "    foreign: list[dict[str, Any]] = []\n"
        "    embedded_firmware: list[dict[str, Any]] = []\n"
        "    machines: dict[str, int] = {}",
        "payload audit declarations",
    )
    text = replace_once(
        text,
        '                "x86": [],\n'
        '                "foreign": [],\n'
        '                "machines": {},\n'
        '                "passed": False,',
        '                "x86": [],\n'
        '                "foreign": [],\n'
        '                "embedded_firmware": [],\n'
        '                "machines": {},\n'
        '                "passed": False,',
        "payload extraction failure evidence",
    )
    text = replace_once(
        text,
        "                name = ELF_NAMES.get(machine, f\"machine-{machine}\")\n"
        "                machines[name] = machines.get(name, 0) + 1\n"
        "                record = {\n"
        "                    \"path\": str(path.relative_to(root)),\n"
        "                    \"machine\": name,\n"
        "                    \"size\": path.stat().st_size,\n"
        "                }\n"
        "                if machine in {3, 62}:\n"
        "                    x86.append(record)\n"
        "                elif machine not in {0, 183, 247}:\n"
        "                    foreign.append(record)",
        "                name = ELF_NAMES.get(machine, f\"machine-{machine}\")\n"
        "                machines[name] = machines.get(name, 0) + 1\n"
        "                relative = path.relative_to(root).as_posix()\n"
        "                record = {\n"
        "                    \"path\": relative,\n"
        "                    \"machine\": name,\n"
        "                    \"size\": path.stat().st_size,\n"
        "                }\n"
        "                parts = Path(relative).parts\n"
        "                is_embedded_firmware = (\n"
        "                    parts[:2] == (\"lib\", \"firmware\")\n"
        "                    or parts[:3] == (\"usr\", \"lib\", \"firmware\")\n"
        "                )\n"
        "                if is_embedded_firmware:\n"
        "                    embedded_firmware.append(record)\n"
        "                    continue\n"
        "                if machine in {3, 62}:\n"
        "                    x86.append(record)\n"
        "                elif machine not in {0, 183, 247}:\n"
        "                    foreign.append(record)",
        "path-aware firmware classification",
    )
    text = replace_once(
        text,
        '    return {\n'
        '        "x86": x86,\n'
        '        "foreign": foreign,\n'
        '        "machines": dict(sorted(machines.items())),\n'
        '        "passed": not x86 and not foreign,\n'
        '    }',
        '    return {\n'
        '        "x86": x86,\n'
        '        "foreign": foreign,\n'
        '        "embedded_firmware": embedded_firmware,\n'
        '        "machines": dict(sorted(machines.items())),\n'
        '        "passed": not x86 and not foreign,\n'
        '    }',
        "payload audit result",
    )
    text = replace_once(
        text,
        '"policy": "exact-reference-source-version-and-no-x86-elf"',
        '"policy": "exact-reference-source-version-and-no-host-x86-elf-firmware-exempt"',
        "summary policy",
    )
    BASE.write_text(text, encoding="utf-8")
    print(f"patched: {BASE}")


def patch_summarizer() -> None:
    text = SUMMARIZER.read_text(encoding="utf-8")
    marker = '"embedded_firmware_payload_count"'
    if marker in text:
        print(f"already patched: {SUMMARIZER}")
        return

    text = replace_once(
        text,
        '        reference_package = blocker.get("reference_package") or ""\n'
        '        row = {',
        '        reference_package = blocker.get("reference_package") or ""\n'
        '        available_identities = [\n'
        '            {\n'
        '                "filename": item.get("filename") or "",\n'
        '                "version": item.get("version") or "",\n'
        '                "architecture": item.get("architecture") or "",\n'
        '                "source": item.get("source") or "",\n'
        '                "source_version": item.get("source_version") or "",\n'
        '            }\n'
        '            for item in available\n'
        '        ]\n'
        '        row = {',
        "available candidate identity normalization",
    )
    text = replace_once(
        text,
        '            "x86_payload_count": len(payload.get("x86") or []),\n'
        '            "foreign_payload_count": len(payload.get("foreign") or []),\n'
        '            "available_candidate_count": len(available),',
        '            "x86_payload_count": len(payload.get("x86") or []),\n'
        '            "foreign_payload_count": len(payload.get("foreign") or []),\n'
        '            "embedded_firmware_payload_count": len(\n'
        '                payload.get("embedded_firmware") or []\n'
        '            ),\n'
        '            "available_candidate_count": len(available),\n'
        '            "available_candidates": available_identities,',
        "compact blocker evidence fields",
    )
    SUMMARIZER.write_text(text, encoding="utf-8")
    print(f"patched: {SUMMARIZER}")


def patch_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    marker = "Refresh compact blocker authority"
    if marker in text:
        print(f"already patched: {WORKFLOW}")
        return

    text = replace_once(
        text,
        "permissions:\n  contents: write\n  actions: read",
        "permissions:\n  contents: write\n  actions: write",
        "workflow action permission",
    )
    text = replace_once(
        text,
        "      - name: Enforce completeness without inventing missing packages\n",
        "      - name: Refresh compact blocker authority\n"
        "        if: always()\n"
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
        "        shell: bash\n"
        "        run: |\n"
        "          set -euxo pipefail\n"
        "          if [ -f work/recovery/summary.json ] \\\n"
        "             && jq -e '.blocker_count > 0' work/recovery/summary.json >/dev/null; then\n"
        "            gh workflow run arm64-summarize-recovered-package-blockers.yml \\\n"
        "              --repo '${{ github.repository }}' \\\n"
        "              --ref arm64-port\n"
        "          fi\n\n"
        "      - name: Enforce completeness without inventing missing packages\n",
        "compact blocker dispatch step",
    )
    WORKFLOW.write_text(text, encoding="utf-8")
    print(f"patched: {WORKFLOW}")


def main() -> int:
    patch_base()
    patch_summarizer()
    patch_workflow()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
