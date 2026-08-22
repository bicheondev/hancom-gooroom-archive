# Runbook

1. Merge the workflow and discovery script into `arm64-port`.
2. Let the push-triggered workflow discover at most twelve unique public source trees.
3. Build each candidate in the locked Bullseye/Nimf environment.
4. Rank exact vendor-visible payload, resource, function, and allocated-section differences.
5. Inspect the committed `latest/summary.json` before opening any later gate.
