# TROE agent guidance

## QEMU verification on macOS

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
