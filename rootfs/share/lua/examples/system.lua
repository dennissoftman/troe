-- Lua integration with TROE filesystems, modules, processes, and environment.

local data_path = "/tmp/lua-system-data.txt"
local renamed_path = "/tmp/lua-system-data-renamed.txt"
local module_path = "/tmp/lua-system-module.lua"
local tree_path = "/tmp/lua-system-tree"
local renamed_tree_path = "/tmp/lua-system-renamed-tree"

os.remove(data_path)
os.remove(renamed_path)
os.remove(module_path)

local file = assert(io.open(data_path, "w+"))
assert(file:write("alpha\nbeta\n"))
assert(file:seek("set", 0) == 0)
assert(file:read("l") == "alpha")
assert(file:close())

file = assert(io.open(data_path, "a"))
assert(file:write("gamma\n"))
assert(file:close())

file = assert(io.open(data_path, "r"))
local lines = {}
for line in file:lines() do
  lines[#lines + 1] = line
end
assert(file:close())

assert(os.rename(data_path, renamed_path))
file = assert(io.open(renamed_path, "r"))
assert(file:read("a") == "alpha\nbeta\ngamma\n")
assert(file:close())

file = assert(io.open(module_path, "w"))
assert(file:write("return { answer = 6 * 7 }\n"))
assert(file:close())
package.path = "/tmp/?.lua;" .. package.path
local module, loaded_from = require("lua-system-module")
assert(module.answer == 42)

local temporary = assert(io.tmpfile())
assert(temporary:write(string.pack("<I4", 0x54524f45)))
assert(temporary:seek("set", 0) == 0)
local marker = string.unpack("<I4", temporary:read("a"))
assert(temporary:close())

local dumped = string.dump(function(value) return value * value end)
assert(load(dumped, "=(dumped)", "b")(9) == 81)
local info = debug.getinfo(1, "S")
local leap_day = os.time { year = 2024, month = 2, day = 29, hour = 12 }

local ok, kind, status = os.execute([[echo "lua execute"]])
assert(ok and kind == "exit" and status == 0)
local process = assert(io.popen("printf lua-popen", "r"))
local captured = assert(process:read("a"))
ok, kind, status = process:close()
assert(ok and kind == "exit" and status == 0)

assert(os.execute("cp -r /vol/root/nested " .. tree_path))
assert(os.rename(tree_path, renamed_tree_path))
local removed, remove_message, remove_errno = os.remove(renamed_tree_path)
assert(removed == nil and remove_errno == 39)
assert(remove_message:match("directory not empty"))
local check = assert(io.open(renamed_tree_path .. "/state.txt", "r"))
assert(check:read("l") == "read-only activation complete")
assert(check:close())
assert(os.remove(renamed_tree_path .. "/state.txt"))
assert(os.remove(renamed_tree_path))

assert(os.execute("ln -s hello.txt /vol/root/lua-system-link"))
assert(os.rename("/vol/root/lua-system-link", "/vol/root/lua-system-renamed-link"))
assert(os.remove("/vol/root/lua-system-renamed-link"))
check = assert(io.open("/vol/root/hello.txt", "r"))
assert(check:read("l") == "native ext4 mount")
assert(check:close())

file = assert(io.open("/tmp/lua-system-cross-device.txt", "w"))
assert(file:write("source preserved\n"))
assert(file:close())
local moved, move_message, move_errno = os.rename(
  "/tmp/lua-system-cross-device.txt",
  "/vol/root/lua-system-cross-device.txt"
)
assert(moved == nil and move_errno == 18)
assert(move_message:match("cross%-device operation"))
check = assert(io.open("/tmp/lua-system-cross-device.txt", "r"))
assert(check:read("a") == "source preserved\n")
assert(check:close())
assert(os.remove("/tmp/lua-system-cross-device.txt"))

local read_only, read_only_message, read_only_errno = io.open("/recovery/motd", "w")
assert(read_only == nil and read_only_errno == 30)
assert(read_only_message:match("read%-only filesystem"))

-- The session is the trusted top-level composer. An application reads the
-- values it was given; nothing is synthesized from state inside the program.
assert(os.getenv("PWD") == "/" and os.getenv("HOME") == "/")
assert(os.getenv("PATH") == "/bin" and os.getenv("MISSING") == nil)
assert(os.getenv("SHELL") == "/bin/sh" and os.getenv("TMPDIR") == "/tmp")
assert(os.getenv("USER") == "root" and os.getenv("LOGNAME") == "root")
-- Names the launcher did not supply have no value at all.
assert(os.getenv("LUA_PATH_5_5") == nil and os.getenv("LUA_PATH") == nil)
assert(os.getenv("LUA_INIT_5_5") == nil and os.getenv("LUA_INIT") == nil)
-- A direct child inherits those values, with PWD narrowed to its own directory.
-- The interpreter is an optional shared-media runtime, so re-invoke it through
-- the exact path this process was launched with rather than a bare name.
local interpreter = arg[-1]
assert(os.execute(
  interpreter .. [[ -e 'assert(os.getenv("PWD") == "/")']]))
assert(os.execute(
  interpreter ..
  [[ -e 'assert(os.getenv("HOME") == "/" and os.getenv("USER") == "root")']]))
local inherited = assert(io.popen(
  interpreter .. [[ -e 'io.write(os.getenv("PATH"), " ", os.getenv("PWD"))']],
  "r"))
local inherited_values = assert(inherited:read("a"))
assert(inherited:close())

print("lua-system libraries", type(package), type(io), type(debug))
print("lua-system date", os.date("!%Y-%m-%d %A", leap_day))
print("lua-system file", table.concat(lines, ","))
print("lua-system module", module.answer, loaded_from)
print("lua-system bytecode", marker, info.what)
print("lua-system process", captured)
print("lua-system environment", inherited_values)

assert(os.remove(renamed_path))
assert(os.remove(module_path))
print("lua-system cleanup", io.open(renamed_path, "r") == nil,
      io.open(module_path, "r") == nil)
