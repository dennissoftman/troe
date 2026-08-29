"""Shared identifiers for granular QEMU acceptance scenario groups."""

SCENARIO_IDS = (
    "boot",
    "network",
    "shell-terminal",
    "filesystem",
    "lua",
    "cpython",
    "quota-memory",
    "persistence",
    "fault-isolation",
    "framebuffer-keyboard",
)
# CPython acceptance consumes the separately built, authenticated interpreter
# package. Selecting it by default would make every acceptance run depend on
# that build, so changed-path selection and explicit --scenario request it.
OPTIONAL_SCENARIOS = frozenset({"cpython", "lua"})
DEFAULT_SCENARIOS = frozenset(SCENARIO_IDS) - OPTIONAL_SCENARIOS
