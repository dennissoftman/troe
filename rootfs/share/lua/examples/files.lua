-- Create, update, rename, read, and remove a file in TROE's writable /tmp.
local path = "/tmp/lua-files-example.txt"
local renamed = "/tmp/lua-files-example-renamed.txt"

os.remove(path)
os.remove(renamed)

local file = assert(io.open(path, "w"))
assert(file:write("created by Lua 5.5\n"))
assert(file:close())

file = assert(io.open(path, "a+"))
assert(file:write("appended on TROE\n"))
assert(file:seek("set", 0) == 0)
local contents = assert(file:read("a"))
assert(file:close())

assert(os.rename(path, renamed))
local check = assert(io.open(renamed, "r"))
assert(check:read("a") == contents)
assert(check:close())
assert(os.remove(renamed))

print("lua-files wrote", #contents, "bytes")
print("lua-files cleanup", io.open(path, "r") == nil,
      io.open(renamed, "r") == nil)
