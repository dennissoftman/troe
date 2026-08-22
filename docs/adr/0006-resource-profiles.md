# ADR 0006: three resource profiles

Status: accepted, 2026-08-22.

Define exactly three build-time resource profiles: `micro`, `tiny`, and `full`.
`micro` targets MCU-class machines, assumes neither an MMU nor page-backed
allocation, and defaults to fixed capacities with no cache. `tiny` targets
constrained systems and may use page-backed mechanisms behind firm limits.
`full` targets larger systems and enables the complete supported service set
while retaining absolute ceilings and accounting.

An intermediate `balanced` profile was rejected because it adds another policy
surface without changing system semantics. Runtime memory detection may refine
budgets within a selected profile, but it must not silently change profiles.

Revisit the numeric defaults through measurement on named supported machines;
do not add another profile unless it represents a materially different machine
model rather than another RAM-size interval.
