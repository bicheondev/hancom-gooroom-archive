#!/usr/bin/env python3
"""Regenerate the self-contained exact Git ARM64 builder v2.

The repository once carried a working native ARM64 builder as the Git blob
identified by the repair workflow. Later consolidation accidentally retained a
small wrapper while deleting its base script. This tool deterministically
upgrades the verified historical builder into the current self-contained v2:

* only Architecture: amd64 reference binaries are mandatory native outputs;
* mk-build-deps output naming is handled across devscripts variants;
* an optional hash-verified local dependency APT repository is injected;
* the build lock records the exact dependency-repository identity.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def transform(text: str) -> str:
    bootstrap = (
        'BOOTSTRAP_IMAGE="${HANCOM_GOOROOM_BOOTSTRAP_IMAGE:-'
        'arm64v8/debian:bullseye-slim@sha256:'
        '4ec855d0417cdc9cab49cdebad00afed0466edc3a17bb616a02be18e9ae66f8e}"\n'
    )
    text = replace_once(
        text,
        bootstrap,
        bootstrap
        + 'REFERENCE_JSON="${HANCOM_GOOROOM_REFERENCE_JSON:-'
        'arm64/locks/reference/amd64-reference.json}"\n'
        + 'DEPENDENCY_REPOSITORY="${HANCOM_GOOROOM_DEPENDENCY_REPOSITORY:-}"\n',
        "environment",
    )

    expected = 'EXPECTED_PACKAGES="$(jq -r \'[PLACEHOLDER]\' <<<"$entry")"\n'
    expected = expected.replace("'[PLACEHOLDER]'", "'.binary_packages | join(\" \")'")
    expected_new = r'''if [ -n "${HANCOM_GOOROOM_REQUIRED_PACKAGES:-}" ]; then
  EXPECTED_PACKAGES="$HANCOM_GOOROOM_REQUIRED_PACKAGES"
elif [ -f "$REFERENCE_JSON" ]; then
  EXPECTED_PACKAGES="$(jq -r \
    --arg source "$SOURCE_NAME" \
    --arg version "$SOURCE_VERSION" '
      [.packages[]
       | select(.source == $source
                and .source_version == $version
                and .architecture == "amd64")
       | .package]
      | unique | join(" ")
    ' "$REFERENCE_JSON")"
else
  EXPECTED_PACKAGES="$(jq -r '.binary_packages | join(" ")' <<<"$entry")"
fi
EXPECTED_PACKAGES_JSON="$(
  if [ -n "$EXPECTED_PACKAGES" ]; then
    printf '%s\n' $EXPECTED_PACKAGES | jq -Rsc 'split("\n")[:-1] | unique | sort'
  else
    printf '[]\n'
  fi
)"
'''
    text = replace_once(text, expected, expected_new, "native package selection")

    work = "WORK_DIR=\"$(mktemp -d)\"\ntrap 'rm -rf \"$WORK_DIR\"' EXIT\n"
    work_new = work + r'''DEPENDENCY_REPOSITORY_COPY="$WORK_DIR/dependency-repository"
mkdir -p "$DEPENDENCY_REPOSITORY_COPY"
DEPENDENCY_REPOSITORY_PACKAGES_SHA256=""
if [ -n "$DEPENDENCY_REPOSITORY" ]; then
  [ -d "$DEPENDENCY_REPOSITORY" ] || {
    echo "dependency repository does not exist: $DEPENDENCY_REPOSITORY" >&2
    exit 69
  }
  for required in Packages Packages.gz Release; do
    [ -f "$DEPENDENCY_REPOSITORY/$required" ] || {
      echo "dependency repository is missing $required" >&2
      exit 69
    }
  done
  if [ -f "$DEPENDENCY_REPOSITORY/SHA256SUMS" ]; then
    (cd "$DEPENDENCY_REPOSITORY" && sha256sum --check SHA256SUMS)
  fi
  cp -a "$DEPENDENCY_REPOSITORY/." "$DEPENDENCY_REPOSITORY_COPY/"
  DEPENDENCY_REPOSITORY_PACKAGES_SHA256="$(
    sha256sum "$DEPENDENCY_REPOSITORY_COPY/Packages" | awk '{print $1}'
  )"
fi
'''
    text = replace_once(text, work, work_new, "dependency repository staging")

    resolv = r'''cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"

mkdir -p "$ROOT/build/source" "$ROOT/build/output"
'''
    resolv_new = r'''cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"

if [ -f /dependency-repository/Packages ]; then
  mkdir -p "$ROOT/opt/hancom-gooroom-dependency-repository"
  cp -a /dependency-repository/. \
    "$ROOT/opt/hancom-gooroom-dependency-repository/"
  cat > "$ROOT/etc/apt/sources.list.d/98hancom-gooroom-dependencies.list" <<'EOF'
deb [trusted=yes] file:/opt/hancom-gooroom-dependency-repository ./
EOF
  cat > "$ROOT/etc/apt/preferences.d/98hancom-gooroom-dependencies" <<'EOF'
Package: *
Pin: release o=Hancom Gooroom ARM64
Pin-Priority: 1001
EOF
fi

mkdir -p "$ROOT/build/source" "$ROOT/build/output"
'''
    text = replace_once(
        text,
        resolv,
        resolv_new,
        "dependency repository chroot injection",
    )

    dummy = r'''rm -f ./*-build-deps_*.deb
mk-build-deps --build-dep debian/control
DUMMY_PACKAGE="$(find . -maxdepth 1 -type f -name '*-build-deps_*.deb' -print -quit)"
[ -n "$DUMMY_PACKAGE" ]
'''
    dummy_new = r'''rm -f ./*-build-deps*.deb
mk-build-deps --build-dep debian/control
DUMMY_PACKAGE="$(find . -maxdepth 1 -type f -name '*-build-deps*.deb' -print -quit)"
if [ -z "$DUMMY_PACKAGE" ]; then
  echo "mk-build-deps did not produce a dependency metapackage" >&2
  find . -maxdepth 1 -type f -printf '%f\n' | sort >&2
  exit 21
fi
'''
    text = replace_once(text, dummy, dummy_new, "mk-build-deps output discovery")

    mount = r'''  --volume "$SOURCE_ROOT:/src:ro" \
  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \
'''
    mount_new = r'''  --volume "$SOURCE_ROOT:/src:ro" \
  --volume "$DEPENDENCY_REPOSITORY_COPY:/dependency-repository:ro" \
  --volume "$WORK_DIR/build-inside.sh:/build-inside.sh:ro" \
'''
    text = replace_once(text, mount, mount_new, "dependency repository mount")

    text = replace_once(text, '  "schema": 3,\n', '  "schema": 5,\n', "schema")
    expected_json = (
        '  "expected_binary_packages": '
        '$(jq -c \'.binary_packages\' <<<"$entry"),\n'
    )
    expected_json_new = r'''  "expected_binary_packages": $EXPECTED_PACKAGES_JSON,
  "dependency_repository_packages_sha256": $(jq -Rn --arg v "$DEPENDENCY_REPOSITORY_PACKAGES_SHA256" '$v'),
'''
    text = replace_once(
        text,
        expected_json,
        expected_json_new,
        "build lock package identity",
    )

    produced = (
        '  "produced_binary_packages": '
        '$(printf \'%s\\n\' "${produced_packages[@]}" '
        "| jq -Rsc 'split(\"\\n\")[:-1]')\n"
    )
    produced_new = (
        '  "produced_binary_packages": '
        '$(printf \'%s\\n\' "${produced_packages[@]}" '
        "| jq -Rsc 'split(\"\\n\")[:-1] | unique | sort')\n"
    )
    text = replace_once(
        text,
        produced,
        produced_new,
        "produced package normalization",
    )
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    transformed = transform(args.base.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(transformed, encoding="utf-8")
    print(f"wrote {args.output} ({len(transformed)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
