#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


MATERIALIZER = Path("arm64/scripts/materialize_build_dependency_repo_v2.py")
WORKFLOW = Path(".github/workflows/arm64-build-dependency-repository-v2.yml")
TEST_PATH = Path("arm64/scripts/test_materialize_build_dependency_repo_v2.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new)


def main() -> None:
    text = MATERIALIZER.read_text(encoding="utf-8")
    helper_anchor = '''    return sorted(candidates, key=lambda row: (row["package"], row["version"]))


def download_rebuild_group(
'''
    helper_replacement = '''    return sorted(candidates, key=lambda row: (row["package"], row["version"]))


def package_triplet(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row["package"]),
        str(row["version"]),
        str(row["architecture"]),
    )


def apply_vendor_all_precedence(
    vendor: list[dict[str, Any]],
    rebuilt: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Prefer exact ISO Architecture: all packages over rebuilt duplicates.

    Architecture: all payloads from the original ISO are already native on ARM64
    and remain the byte authority. A rebuilt package with the same Package,
    Version and Architecture is therefore redundant, even when its container
    bytes differ because of build metadata. Ambiguous vendor authority remains a
    hard failure.
    """

    vendor_identities: dict[
        tuple[str, str, str], set[tuple[str, str, int]]
    ] = defaultdict(set)
    for row in vendor:
        if row.get("architecture") != "all":
            raise RuntimeError("vendor precedence received a non-all package")
        vendor_identities[package_triplet(row)].add(
            (str(row["filename"]), str(row["sha256"]), int(row["size"]))
        )

    ambiguous = {
        key: sorted(identities)
        for key, identities in vendor_identities.items()
        if len(identities) != 1
    }
    if ambiguous:
        raise RuntimeError(
            "vendor Architecture: all authority is ambiguous: "
            + json.dumps(ambiguous, ensure_ascii=False, sort_keys=True)
        )

    retained: list[dict[str, Any]] = []
    shadowed: list[dict[str, Any]] = []
    for row in rebuilt:
        key = package_triplet(row)
        identities = vendor_identities.get(key)
        if not identities:
            retained.append(row)
            continue
        filename, digest, size = next(iter(identities))
        shadowed.append(
            {
                **row,
                "shadowed_by": "iso-vendor-binary-lock",
                "vendor_authority": {
                    "filename": filename,
                    "sha256": digest,
                    "size": size,
                },
            }
        )
    return retained, shadowed


def download_rebuild_group(
'''
    text = replace_once(
        text,
        helper_anchor,
        helper_replacement,
        "vendor precedence helper insertion",
    )
    text = replace_once(
        text,
        '''    vendor = vendor_all_candidates(load(args.vendor_lock))
    rebuilt = rebuilt_candidates(load(args.rebuild_packages))
''',
        '''    vendor = vendor_all_candidates(load(args.vendor_lock))
    rebuilt_before_vendor_precedence = rebuilt_candidates(load(args.rebuild_packages))
    rebuilt, shadowed_rebuilt = apply_vendor_all_precedence(
        vendor, rebuilt_before_vendor_precedence
    )
''',
        "vendor precedence application",
    )
    text = replace_once(
        text,
        '''        "vendor_all_candidate_count": len(vendor),
        "rebuilt_candidate_count": len(rebuilt),
''',
        '''        "vendor_all_candidate_count": len(vendor),
        "rebuilt_candidate_count_before_vendor_precedence": len(
            rebuilt_before_vendor_precedence
        ),
        "rebuilt_candidate_count": len(rebuilt),
        "vendor_precedence_shadowed_rebuild_count": len(shadowed_rebuilt),
''',
        "summary precedence accounting",
    )
    text = replace_once(
        text,
        '''        "verified": verified,
        "failures": failures,
''',
        '''        "verified": verified,
        "shadowed_rebuilt": shadowed_rebuilt,
        "failures": failures,
''',
        "manifest precedence evidence",
    )
    MATERIALIZER.write_text(text, encoding="utf-8")

    TEST_PATH.write_text(
        '''#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("materialize_build_dependency_repo_v2.py")
spec = importlib.util.spec_from_file_location("materializer", SCRIPT)
assert spec is not None and spec.loader is not None
materializer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = materializer
spec.loader.exec_module(materializer)


def row(package: str, version: str, architecture: str, digest: str, filename: str):
    return {
        "package": package,
        "version": version,
        "architecture": architecture,
        "sha256": digest,
        "size": 123,
        "filename": filename,
    }


vendor = [row("demo-data", "1.0", "all", "a" * 64, "vendor.deb")]
rebuilt = [
    row("demo-data", "1.0", "all", "b" * 64, "rebuilt.deb"),
    row("demo-runtime", "1.0", "arm64", "c" * 64, "runtime.deb"),
]
retained, shadowed = materializer.apply_vendor_all_precedence(vendor, rebuilt)
assert [item["package"] for item in retained] == ["demo-runtime"]
assert len(shadowed) == 1
assert shadowed[0]["package"] == "demo-data"
assert shadowed[0]["shadowed_by"] == "iso-vendor-binary-lock"
assert shadowed[0]["vendor_authority"] == {
    "filename": "vendor.deb",
    "sha256": "a" * 64,
    "size": 123,
}

retained, shadowed = materializer.apply_vendor_all_precedence(
    vendor,
    [row("demo-data", "2.0", "all", "d" * 64, "new-version.deb")],
)
assert len(retained) == 1 and not shadowed

try:
    materializer.apply_vendor_all_precedence(
        [
            row("demo-data", "1.0", "all", "a" * 64, "one.deb"),
            row("demo-data", "1.0", "all", "b" * 64, "two.deb"),
        ],
        rebuilt,
    )
except RuntimeError as error:
    assert "vendor Architecture: all authority is ambiguous" in str(error)
else:
    raise AssertionError("ambiguous vendor authority must fail closed")

print("materialize_build_dependency_repo_v2 precedence tests: OK")
''',
        encoding="utf-8",
    )

    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    workflow_text = replace_once(
        workflow_text,
        "      - 'arm64/scripts/test_resolve_rebuild_artifact_names.py'\n",
        "      - 'arm64/scripts/test_resolve_rebuild_artifact_names.py'\n"
        "      - 'arm64/scripts/test_materialize_build_dependency_repo_v2.py'\n",
        "workflow test trigger",
    )
    workflow_text = replace_once(
        workflow_text,
        '''            arm64/scripts/resolve_rebuild_artifact_names.py \\
            arm64/scripts/test_resolve_rebuild_artifact_names.py
          python3 arm64/scripts/test_resolve_rebuild_artifact_names.py
''',
        '''            arm64/scripts/resolve_rebuild_artifact_names.py \\
            arm64/scripts/test_resolve_rebuild_artifact_names.py \\
            arm64/scripts/test_materialize_build_dependency_repo_v2.py
          python3 arm64/scripts/test_resolve_rebuild_artifact_names.py
          python3 arm64/scripts/test_materialize_build_dependency_repo_v2.py
''',
        "workflow test execution",
    )
    workflow_text = replace_once(
        workflow_text,
        '''          jq -e '.repository_ready == true and .failure_count == 0 and .ambiguous_count == 0' \\
            work/build-dependency-evidence/summary.json
''',
        '''          jq -e '
            .repository_ready == true
            and .failure_count == 0
            and .ambiguous_count == 0
            and .vendor_precedence_shadowed_rebuild_count >= 2
            and (
              .rebuilt_candidate_count_before_vendor_precedence
              == (.rebuilt_candidate_count + .vendor_precedence_shadowed_rebuild_count)
            )
          ' work/build-dependency-evidence/summary.json
''',
        "workflow precedence gate",
    )
    WORKFLOW.write_text(workflow_text, encoding="utf-8")


if __name__ == "__main__":
    main()
