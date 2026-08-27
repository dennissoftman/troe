"""Hosted unit tests for TROE's actual freestanding Lua runtime."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LUA_ROOT = REPO_ROOT / "apps" / "lua"
RESULT_PATTERN = re.compile(
    rb"TROE_TEST_RESULT result=(\d+) requested=(\d+) status=(\d+) close=(\d+)"
)


class LuaRuntimeTests(unittest.TestCase):
    """Exercise the embedded interpreter without booting a guest."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="troe-lua-unit-")
        cls.runner = Path(cls.temporary.name) / "lua-host-runner"
        compiler = os.environ.get("CC", "clang")
        command = (
            compiler,
            "-std=c11",
            "-O2",
            "-DTROE_LUA=1",
            "-DTROE_LUA_HOST_TEST=1",
            "-DLUA_USE_C89=1",
            "-Wall",
            "-Wextra",
            "-I",
            str(LUA_ROOT / "vendor" / "lua-5.5.1" / "src"),
            str(LUA_ROOT / "c" / "lua_runtime.c"),
            str(LUA_ROOT / "tests" / "host_runner.c"),
            "-lm",
            "-o",
            str(cls.runner),
        )
        subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def run_lua(
        self, source: str, *arguments: str
    ) -> tuple[subprocess.CompletedProcess[bytes], tuple[int, int, int, int]]:
        completed = subprocess.run(
            (self.runner, source, *arguments),
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            timeout=10,
        )
        match = RESULT_PATTERN.search(completed.stderr)
        self.assertIsNotNone(match, completed.stderr.decode(errors="replace"))
        assert match is not None
        return completed, tuple(int(value) for value in match.groups())

    def test_selected_language_libraries_work_together(self) -> None:
        source = r"""
local ok, message = pcall(function() error("protected") end)
assert(not ok and message:match("protected"))
local values = {3, 1, 2}; table.sort(values)
assert(table.concat(values, ",") == "1,2,3")
local packed = string.pack("<i2I2", -123, 456)
local signed, unsigned = string.unpack("<i2I2", packed)
assert(signed == -123 and unsigned == 456)
assert(math.floor(math.sqrt(81)) == 9)
assert(utf8.len("λ") == 1 and utf8.codepoint("λ") == 0x03bb)
local thread = coroutine.create(function() coroutine.yield(42); return 7 end)
local resumed, value = coroutine.resume(thread)
assert(resumed and value == 42)
resumed, value = coroutine.resume(thread)
assert(resumed and value == 7 and coroutine.status(thread) == "dead")
print("lua-feature-unit", _VERSION)
"""
        completed, metadata = self.run_lua(source)
        self.assertEqual(metadata[0], 0)
        self.assertIn(b"lua-feature-unit\tLua 5.5", completed.stdout)

    def test_sandbox_and_capability_aware_os_surface(self) -> None:
        source = r"""
assert(package == nil and io == nil and debug == nil)
assert(type(load) == "function" and loadfile == nil and dofile == nil)
assert(load("return 6 * 7", "=(unit)", "t")() == 42)
assert(os.difftime(7, 2) == 5)
local before = os.clock()
for index = 1, 10000 do end
assert(os.clock() >= before)
local ok, message = pcall(os.time)
assert(not ok and message:match("os%.time is unavailable in TROE"))
print("lua-sandbox-unit")
"""
        completed, metadata = self.run_lua(source)
        self.assertEqual(metadata[0], 0)
        self.assertEqual(completed.stdout, b"lua-sandbox-unit\n")

    def test_arguments_and_controlled_exit_are_exact(self) -> None:
        completed, metadata = self.run_lua(
            'assert(arg[0] == "lua" and arg[1] == "hello"); os.exit(37, true)',
            "hello",
        )
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(metadata[0], 5)
        self.assertEqual(metadata[1:], (1, 37, 1))

    def test_allocation_heavy_workload_completes(self) -> None:
        source = r"""
local values = {}
local total = 0
for index = 1, 6144 do
    local value = string.rep("x", 1024)
    values[index] = value
    total = total + #value
end
print("lua-allocation-unit", #values, total)
"""
        completed, metadata = self.run_lua(source)
        self.assertEqual(metadata[0], 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stdout, b"lua-allocation-unit\t6144\t6291456\n")

    def test_clock_benchmark_completes_without_interpreter_scheduling_hooks(self) -> None:
        source = r"""
local function target()
    local x = 0
    for i = 1, 100 do x = x + i end
end
local n = 100000
local start = os.clock()
for i = 1, n do end
local overhead = os.clock() - start
start = os.clock()
for i = 1, n do target() end
local total = os.clock() - start - overhead
print("lua-clock-benchmark", type(total), total >= 0)
"""
        completed, metadata = self.run_lua(source)
        self.assertEqual(metadata[0], 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stdout, b"lua-clock-benchmark\tnumber\ttrue\n")


if __name__ == "__main__":
    unittest.main()
