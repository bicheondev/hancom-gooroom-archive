test "$(dpkg-deb -f "$base/downloads/candidate.deb" Architecture)" = amd64
sudo rm -rf "$rootfs"

python3 "$ANALYZER" compare \
  --target-deb "$WORK/downloads/target.deb" \
  --candidate-deb "$WORK/downloads/candidate.deb" \
  --output "$WORK/comparison" \
  --version "$VERSION" \
  --candidate-label han3u3-dwarf-v5 \
  --candidate-commit "$CANDIDATE_COMMIT"

exact="$(jq -r '
  (.different_resource_count == 0)
  and (.different_dynamic_function_count == 0)
  and (.different_allocated_section_count == 0)
  and (.non_elf_difference_count == 0)
' "$WORK/comparison/summary.json")"
jq -n \
  --slurpfile comparison "$WORK/comparison/summary.json" \
  --argjson exact "$exact" '
  {
    schema: 2,
    source: "gooroom-integration-applet",
    version: "0.3.1+grm3u1+han3u3",
    reconstruction_generation: "v5",
    candidate_commit_sha: $comparison[0].candidate_commit_sha,
    comparison_rank: $comparison[0].comparison_rank,
    different_resource_count: $comparison[0].different_resource_count,
    different_dynamic_function_count: $comparison[0].different_dynamic_function_count,
    different_allocated_section_count: $comparison[0].different_allocated_section_count,
    non_elf_difference_count: $comparison[0].non_elf_difference_count,
    main_elf: $comparison[0].main_elf,
    nimf_elf: $comparison[0].nimf_elf,
    amd64_payload_equivalence_verified: $exact,
    native_arm64_build_allowed: $exact,
    package_layer_promotion_allowed: false,
    iso_assembly_allowed: false,
    fail_closed: true,
    next_action: (if $exact then "build reconstructed source natively on ARM64 and verify package payloads" else "inspect remaining resource, function, and allocated-section differences" end)
  }
' > "$WORK/aggregate/summary.json"
cp "$WORK/comparison/different-functions.tsv" "$WORK/aggregate/"
cp "$WORK/comparison/summary.json" "$WORK/aggregate/comparison-summary.json"
cp "$WORK/source-authority/base-reconstruction-report.json" "$WORK/aggregate/"
cp "$WORK/source-authority/han3u3-patch-report.json" "$WORK/aggregate/"
cp "$WORK/source-authority/source-lock.json" "$WORK/aggregate/"
cp "$WORK/source-authority/reconstruction.patch" "$WORK/aggregate/"
find "$WORK/aggregate" -type f -printf '%P\t%s\n' | LC_ALL=C sort > "$WORK/aggregate/FILE-INVENTORY.tsv"
(
  cd "$WORK/aggregate"
  find . -type f ! -name LOCKSUMS.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
  sha256sum --check --strict LOCKSUMS.sha256
)

cp -a "$WORK/source-authority" "$WORK/artifact/"
cp -a "$WORK/comparison" "$WORK/artifact/"
cp -a "$WORK/aggregate" "$WORK/artifact/"
cp "$WORK/downloads/target.deb" "$WORK/artifact/"
cp "$WORK/downloads/candidate.deb" "$WORK/artifact/"
cp "$WORK/build/build.log" "$WORK/artifact/"
cp "$WORK/build/debootstrap.log" "$WORK/artifact/"
find "$WORK/artifact" -type f -printf '%P\t%s\n' | LC_ALL=C sort > "$WORK/artifact/FILE-INVENTORY.tsv"
(
  cd "$WORK/artifact"
  find . -type f ! -name LOCKSUMS.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
  sha256sum --check --strict LOCKSUMS.sha256
)
jq '.' "$WORK/aggregate/summary.json"
