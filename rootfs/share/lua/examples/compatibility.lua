-- Exercise the standard-library features that connect Lua to TROE services.
local data_path = "/tmp/lua55-showcase.txt"
local renamed_path = "/tmp/lua55-showcase-renamed.txt"
local module_path = "/tmp/lua55-showcase-module.lua"

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
local module, loaded_from = require("lua55-showcase-module")
assert(module.answer == 42)

local temporary = assert(io.tmpfile())
assert(temporary:write(string.pack("<I4", 0x54524f45)))
assert(temporary:seek("set", 0) == 0)
local marker = string.unpack("<I4", temporary:read("a"))
assert(temporary:close())

local dumped = string.dump(function(value) return value * value end)
assert(load(dumped, "=(dumped)", "b")(9) == 81)
local info = debug.getinfo(1, "S")
local leap_day = os.time {year = 2024, month = 2, day = 29, hour = 12}

print("lua-compat libraries", type(package), type(io), type(debug))
print("lua-compat date", os.date("!%Y-%m-%d %A", leap_day))
print("lua-compat file", table.concat(lines, ","))
print("lua-compat module", module.answer, loaded_from)
print("lua-compat bytecode", marker, info.what)

assert(os.remove(renamed_path))
assert(os.remove(module_path))
print("lua-compat cleanup", io.open(renamed_path, "r") == nil,
      io.open(module_path, "r") == nil)
