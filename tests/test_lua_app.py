"""Hosted unit tests for TROE's actual freestanding Lua runtime."""

from __future__ import annotations

import json
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
        cls.printf_runner = Path(cls.temporary.name) / "lua-printf-runner"
        cls.module_path = Path(cls.temporary.name) / "lua_module.lua"
        cls.module_path.write_text(
            "local module = {}\n"
            "function module.answer() return 42 end\n"
            "return module\n",
            encoding="utf-8",
        )
        compiler = os.environ.get("CC", "clang")
        command = (
            compiler,
            "-std=c11",
            "-O2",
            "-DTROE_LUA=1",
            "-DTROE_LUA_HOST_TEST=1",
            "-DLUA_USE_POSIX=1",
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
        printf_command = (
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-I",
            str(REPO_ROOT / "sdk" / "c" / "troe-kex-runtime"),
            str(LUA_ROOT / "tests" / "printf_runner.c"),
            "-o",
            str(cls.printf_runner),
        )
        subprocess.run(printf_command, cwd=REPO_ROOT, check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def run_lua(
        self,
        source: str,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], tuple[int, int, int, int]]:
        process_environment = os.environ.copy()
        if environment is not None:
            process_environment.update(environment)
        completed = subprocess.run(
            (self.runner, source, *arguments),
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            timeout=10,
            env=process_environment,
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

    def test_local_time_follows_the_launch_timezone(self) -> None:
        # `os.date` without `!` is local time, so the launch `TZ` decides it.
        # United States Eastern in 2026 enters daylight time at
        # 2026-03-08T07:00:00Z and leaves it at 2026-11-01T06:00:00Z.
        source = r"""
assert(os.getenv("TZ") == "EST5EDT,M3.2.0,M11.1.0")
assert(os.date("!%Y-%m-%d %H:%M:%S %Z", 1784116800) == "2026-07-15 12:00:00 UTC")
assert(os.date("%Y-%m-%d %H:%M:%S %Z %z", 1784116800)
    == "2026-07-15 08:00:00 EDT -0400")
assert(os.date("%Y-%m-%d %H:%M:%S %Z %z", 1768478400)
    == "2026-01-15 07:00:00 EST -0500")
-- The exact transition second and the one before it.
assert(os.date("%H:%M:%S %Z", 1772953199) == "01:59:59 EST")
assert(os.date("%H:%M:%S %Z", 1772953200) == "03:00:00 EDT")
local summer = os.date("*t", 1784116800)
assert(summer.hour == 8 and summer.isdst == true)
local winter = os.date("*t", 1768478400)
assert(winter.hour == 7 and winter.isdst == false)
-- `os.time` reads a table as local wall time, which is what mktime means.
assert(os.time{year=2026, month=7, day=15, hour=8, min=0, sec=0} == 1784116800)
assert(os.time{year=2026, month=1, day=15, hour=7, min=0, sec=0} == 1768478400)
print("lua-timezone", os.date("%Z", 1784116800))
"""
        completed, metadata = self.run_lua(
            source,
            environment={"TROE_TEST_ENV_TZ": "EST5EDT,M3.2.0,M11.1.0"},
        )
        self.assertEqual(metadata[0], 0)
        self.assertIn(b"lua-timezone\tEDT", completed.stdout)

    def test_a_southern_zone_wraps_the_year_in_lua(self) -> None:
        # Australian Eastern runs daylight time October through April, so a
        # January instant is inside the period rather than outside it.
        source = r"""
assert(os.date("%Y-%m-%d %H:%M %Z %z", 1768478400) == "2026-01-15 23:00 AEDT +1100")
assert(os.date("%Y-%m-%d %H:%M %Z %z", 1784116800) == "2026-07-15 22:00 AEST +1000")
assert(os.date("*t", 1768478400).isdst == true)
assert(os.date("*t", 1784116800).isdst == false)
print("lua-southern", os.date("%Z", 1768478400))
"""
        completed, metadata = self.run_lua(
            source,
            environment={"TROE_TEST_ENV_TZ": "AEST-10AEDT,M10.1.0,M4.1.0/3"},
        )
        self.assertEqual(metadata[0], 0)
        self.assertIn(b"lua-southern\tAEDT", completed.stdout)

    def test_freestanding_binary64_formatter_matches_host_libc(self) -> None:
        completed = subprocess.run(
            (self.printf_runner,),
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(completed.stdout, b"troe-printf-double ok\n")

    def test_standard_libraries_and_utc_os_surface(self) -> None:
        source = r"""
assert(type(package) == "table" and type(require) == "function")
assert(type(io) == "table" and type(debug) == "table")
assert(type(load) == "function" and type(loadfile) == "function")
assert(type(dofile) == "function")
assert(load("return 6 * 7", "=(unit)", "t")() == 42)
assert(os.difftime(7, 2) == 5)
local before = os.clock()
for index = 1, 10000 do end
assert(os.clock() > before)
local wall_before = os.time()
assert(type(wall_before) == "number" and os.time() > wall_before)
local date = {year=2024, month=2, day=29, hour=1, min=2, sec=3}
local seconds = os.time(date)
assert(seconds == 1709168523)
assert(os.date("!%Y-%m-%d %H:%M:%S %a %j", seconds) == "2024-02-29 01:02:03 Thu 060")
assert(date.wday == 5 and date.yday == 60 and date.isdst == false)
local broken = {year=2023, month=13, day=1}
assert(os.date("!%Y-%m-%d %H:%M:%S", os.time(broken)) == "2024-01-01 12:00:00")
local previous = {year=2024, month=3, day=0}
assert(os.date("!%Y-%m-%d", os.time(previous)) == "2024-02-29")
assert(previous.year == 2024 and previous.month == 2 and previous.day == 29)
assert(os.setlocale() == "C" and os.setlocale("C", "time") == "C")
assert(os.setlocale("uk_UA.UTF-8") == nil)
assert(os.getenv("HOME") == "/" and os.getenv("PWD") == "/")
assert(os.getenv("PATH") == "/bin" and os.getenv("MISSING") == nil)
local ok, kind, status = os.execute("true")
assert(ok == true and kind == "exit" and status == 0 and os.execute() == true)
ok, kind, status = os.execute("false")
assert(ok == nil and kind == "exit" and status == 1)
local process = assert(io.popen("printf lua-popen", "r"))
assert(process:read("a") == "lua-popen")
ok, kind, status = process:close()
assert(ok == true and kind == "exit" and status == 0)
assert(type(os.tmpname()) == "string")
assert(collectgarbage("incremental") == "generational")
assert(type(debug.getinfo(1, "nS")) == "table")
print("lua-standard-unit")
"""
        completed, metadata = self.run_lua(source)
        self.assertEqual(metadata[0], 0)
        self.assertEqual(completed.stdout, b"lua-standard-unit\n")

    def test_loadfile_require_and_io_use_upstream_semantics(self) -> None:
        module_path = json.dumps(str(self.module_path))
        module_pattern = json.dumps(str(self.module_path.parent / "?.lua"))
        source = f"""
package.path = {module_pattern} .. ";" .. package.path
local module, loader = require("lua_module")
assert(module.answer() == 42 and loader:match("lua_module%.lua$"))
assert(require("lua_module") == module)
local chunk = assert(loadfile({module_path}, "t"))
assert(chunk().answer() == 42)
assert(dofile({module_path}).answer() == 42)
local file = assert(io.open({module_path}, "r"))
local contents = assert(file:read("a"))
assert(contents:match("return module"))
assert(file:seek("set", 0) == 0)
assert(file:read(5) == "local")
assert(file:close())
local temporary = assert(io.tmpfile())
assert(temporary:write("hello"))
assert(temporary:seek("set", 0) == 0 and temporary:read("a") == "hello")
assert(temporary:close())
print("lua-files-unit")
"""
        completed, metadata = self.run_lua(source)
        self.assertEqual(metadata[0], 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stdout, b"lua-files-unit\n")

    def test_warning_handler_matches_stock_lua(self) -> None:
        completed, metadata = self.run_lua('warn("@on"); warn("visible-warning")')
        self.assertEqual(metadata[0], 0)
        self.assertIn(b"Lua warning: visible-warning", completed.stderr)

    def test_versioned_environment_initialization_runs_before_source(self) -> None:
        completed, metadata = self.run_lua(
            'assert(initialized_by_lua_init == 42); print("lua-init-unit")',
            environment={"TROE_TEST_ENV_LUA_INIT_5_5": "initialized_by_lua_init = 42"},
        )
        self.assertEqual(metadata[0], 0)
        self.assertEqual(completed.stdout, b"lua-init-unit\n")

    def test_unversioned_initialization_is_the_fallback_only(self) -> None:
        completed, metadata = self.run_lua(
            'assert(chosen == "plain"); print("lua-init-fallback")',
            environment={"TROE_TEST_ENV_LUA_INIT": 'chosen = "plain"'},
        )
        self.assertEqual(metadata[0], 0)
        self.assertEqual(completed.stdout, b"lua-init-fallback\n")

        # With both present the versioned name wins and the fallback is unread.
        completed, metadata = self.run_lua(
            'assert(chosen == "versioned"); print("lua-init-precedence")',
            environment={
                "TROE_TEST_ENV_LUA_INIT_5_5": 'chosen = "versioned"',
                "TROE_TEST_ENV_LUA_INIT": 'chosen = "plain"',
            },
        )
        self.assertEqual(metadata[0], 0)
        self.assertEqual(completed.stdout, b"lua-init-precedence\n")

    def test_ignore_environment_suppresses_initialization_but_not_getenv(self) -> None:
        # Module-path suppression is covered by QEMU acceptance instead: the
        # host build links the real libc, so upstream setpath reads the host
        # process environment rather than the injected guest environment.
        completed, metadata = self.run_lua(
            'assert(initialized_by_lua_init == nil); print("lua-ignore-env")',
            environment={
                "TROE_TEST_LUA_IGNORE_ENV": "1",
                "TROE_TEST_ENV_LUA_INIT_5_5": "initialized_by_lua_init = 42",
                "TROE_TEST_ENV_LUA_INIT": "initialized_by_lua_init = 7",
            },
        )
        self.assertEqual(metadata[0], 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stdout, b"lua-ignore-env\n")

        # It must not change ordinary os.getenv, which is not Lua configuration.
        completed, metadata = self.run_lua(
            'assert(os.getenv("HOME") == "/" and os.getenv("LUA_INIT_5_5") ~= nil); '
            'print("lua-getenv-unaffected")',
            environment={
                "TROE_TEST_LUA_IGNORE_ENV": "1",
                "TROE_TEST_ENV_LUA_INIT_5_5": "initialized_by_lua_init = 42",
            },
        )
        self.assertEqual(metadata[0], 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stdout, b"lua-getenv-unaffected\n")

    def test_absent_names_have_no_ambient_value(self) -> None:
        completed, metadata = self.run_lua(
            'assert(os.getenv("LUA_INIT_5_5") == nil '
            'and os.getenv("LUA_INIT") == nil); '
            'assert(os.getenv("TOTALLY_ABSENT") == nil); print("lua-absent-env")'
        )
        self.assertEqual(metadata[0], 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stdout, b"lua-absent-env\n")

    def test_arguments_and_controlled_exit_are_exact(self) -> None:
        completed, metadata = self.run_lua(
            "local first, second = ...; "
            'assert(arg[-1] == "lua" and arg[0] == "host.lua"); '
            'assert(arg[1] == "hello" and arg[2] == "world"); '
            'assert(select("#", ...) == 2 and first == "hello" and second == "world"); '
            "os.exit(37, true)",
            "hello",
            "world",
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

    def test_clock_benchmark_completes_without_interpreter_scheduling_hooks(
        self,
    ) -> None:
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

    def test_portable_benchmark_smoke(self) -> None:
        benchmark = REPO_ROOT / "rootfs" / "share" / "lua" / "benchmark.lua"
        completed, metadata = self.run_lua(
            benchmark.read_text(encoding="utf-8"), "1", "1", "host-smoke"
        )
        output = completed.stdout.decode()
        self.assertEqual(metadata[0], 0, completed.stderr.decode(errors="replace"))
        self.assertIn("BENCHMARK version=1 label=host-smoke", output)
        for phase in (
            "integer_mix",
            "floating_arithmetic",
            "retained_records",
            "allocation_churn",
        ):
            self.assertIn(f"RESULT label=host-smoke name={phase}", output)
        self.assertIn("END label=host-smoke", output)


if __name__ == "__main__":
    unittest.main()
