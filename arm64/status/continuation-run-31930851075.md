# Hancom Gooroom 3.3 ARM64 continuation gate

- Generated: `2026-08-16T07:56:12+00:00`
- Target run: `31930851075`
- Target status: `completed`
- Target conclusion: `failure`
- Target head SHA: `f24dc7f2a771e68b2c2084615ad9a7d73bd1c32e`
- Exact-source state: `positive`
- Explicit unresolved zero: `false`
- Remaining explicit labels: `gooroom-dockbarx-applet`, `gooroom-guide`, `gooroom-integration-applet`, `gooroom-session-manager`, `linux`, `qtbase-opensource-src`

## Routing

- Category: `failure-debug`
- Candidate category: `failure-debug`
- Reason: target run concluded with 'failure'
- Dispatch result: `dispatched`
- Selected workflow: `.github/workflows/arm64-debug-gnome-flashback-han3u4.yml`
- Selected run: `31935156157`

## Failed target steps

- `Reconstruct and verify the exact AMD64 source relationship` / `(job)`: `failure`
- `Reconstruct and verify the exact AMD64 source relationship` / `Enforce exact controls, payloads, and normalized AMD64 ELF bytes`: `failure`

## Gate policy

- Missing evidence never opens the ISO gate.
- At most one follow-up workflow is dispatched.
- Active follow-up runs suppress duplicate dispatch.
