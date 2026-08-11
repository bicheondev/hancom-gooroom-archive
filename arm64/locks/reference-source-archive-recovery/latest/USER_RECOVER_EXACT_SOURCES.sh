#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:-hancom-gooroom-exact-source-handoff}"
mkdir -p "$OUT"

fetch_locked() {
  local url="$1" name="$2" size="$3" sha="$4"
  local path="$OUT/$name"
  echo "==> $name"
  if ! curl --fail --location --retry 5 --retry-all-errors --connect-timeout 20 --output "$path.part" "$url"; then
    rm -f "$path.part"
    echo "MANUAL_BROWSER_REQUIRED $url" >&2
    return 0
  fi
  test "$(wc -c < "$path.part" | tr -d " ")" = "$size"
  printf "%s  %s\n" "$sha" "$path.part" | sha256sum --check --strict
  mv "$path.part" "$path"
}

fetch_locked http://update.hancomgooroom.com/gooroom/dists/gooroom-3.0/main/source/Sources.gz gooroom-Sources.gz 51094 09e1abccac1bcd86a430318caab0f0c68224f42a567b8cee7bcf308ed7f4a166
fetch_locked http://update.hancomgooroom.com/hancom/dists/hancom-3.0/main/source/Sources.gz hancom-Sources.gz 7142 5898f493b7ae9c750dbd11c80325bde5a3778357500d9acda24cc6e4e41c6a58

(cd "$OUT" && find . -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
(cd "$OUT" && find . -maxdepth 1 -type f -printf "%f\t%s\n" | sort > SIZES.tsv)
echo "Return the complete $OUT directory or its ZIP archive."
