"""Shared identifiers for granular QEMU acceptance scenario groups."""

SCENARIO_IDS = (
    "boot",
    "network",
    "shell-terminal",
    "filesystem",
    "lua",
    "quota-memory",
    "persistence",
    "fault-isolation",
    "framebuffer-keyboard",
)
DEFAULT_SCENARIOS = frozenset(SCENARIO_IDS)
