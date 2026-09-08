# TROE agent guidance

## Documentation gate before commits and pull requests

- Outside ADRs and `AGENTS.md`, repository documentation must describe only the
  current implementation, current contracts, and current verification process.
  Do not retain historical snapshots, previous limits, superseded behavior,
  landed-work narratives, or archival evaluations in current documentation;
  Git history already preserves them. Planned or incomplete work belongs in
  live GitHub issues, not in repository documentation.
- Before removing roadmap, design-direction, deferred-work, or other potentially
  useful future guidance from repository documentation, verify that each still-
  relevant outcome is represented by a live GitHub issue or milestone. Move
  missing direction there first (creating or changing GitHub items only when
  authorized), then remove the duplicate repository prose. Obsolete historical
  measurements and already-landed narratives need no issue because Git retains
  them.
- Before committing changes or opening/updating a pull request, review the
  complete code diff for documentation impact. Do not assume documentation is
  current merely because the changed-file test plan passes.
- Compare changed behavior and limits against current-behavior sources,
  including `README.md`, `CORE-SPEC.md`, `SECURITY.md`, `docs/architecture.md`,
  format specifications, ADR status/supersession notes, testing guidance, SDK
  documentation, man pages, and relevant live issues or milestones.
- Search for older statements made stale by the change, including claims about
  unsupported features, fixed limits, version numbers, image sizes, command
  lists, security boundaries, and roadmap status. Review documents not touched
  by the implementation when their claims may still be affected.
- Update every affected document in the same change before committing or
  opening/updating the pull request. ADRs may preserve historical rationale,
  but add or correct status and supersession guidance when readers could
  mistake an ADR for the current contract.
- In the final pre-PR verification, explicitly report which documentation was
  updated or state that a documentation-drift review found no required changes.

## QEMU verification on macOS

- Prefer the hosted gate. `.github/workflows/gate.yml` runs the same gates on
  GitHub Actions, one runner per platform, with the work selected from the
  changed paths. It avoids the sandbox problem below entirely, and it avoids
  the acceptance-port collision that two overlapping local runs produce. Run
  the gate locally when iterating on a failure that reproduces on this machine,
  or when producing release evidence, which requires pinned local tools.
- QEMU acceptance requires process-control operations that the default Codex
  workspace sandbox denies on macOS. Running it in the sandbox can complete all
  earlier build and test stages before failing with
  `QEMU acceptance failed: [Errno 1] Operation not permitted`.
- Avoid that duplicate full run. Use
  `python3 scripts/test_changed.py --dry-run --explain` in the sandbox first.
  If the selected plan includes QEMU acceptance, run the actual verification
  outside the sandbox from the outset with the narrowest appropriate approval.
- Apply the same rule to direct `scripts/test.py`, `scripts/test-qemu.py`, or
  `scripts/run-qemu.py` invocations that will launch QEMU. Checks that do not
  launch QEMU should remain sandboxed.
- Do not classify other QEMU failures as sandbox failures. The known sandbox
  signature is the macOS `Operation not permitted` error while creating or
  controlling the QEMU process; investigate different errors normally.
