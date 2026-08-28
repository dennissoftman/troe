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

-- The KEX filesystem primitives also provide exact-path directory and symlink
-- renames. Recursive copying remains a command-level operation.
assert(os.execute("cp -r /vol/root/nested /tmp/lua-files-tree"))
assert(os.rename("/tmp/lua-files-tree", "/tmp/lua-files-renamed-tree"))
local removed, remove_message, remove_errno =
    os.remove("/tmp/lua-files-renamed-tree")
assert(removed == nil and remove_errno == 39)
assert(remove_message:match("directory not empty"))
check = assert(io.open("/tmp/lua-files-renamed-tree/state.txt", "r"))
assert(check:read("l") == "read-only activation complete")
assert(check:close())
assert(os.remove("/tmp/lua-files-renamed-tree/state.txt"))
assert(os.remove("/tmp/lua-files-renamed-tree"))

assert(os.execute("ln -s hello.txt /vol/root/lua-files-link"))
assert(os.rename("/vol/root/lua-files-link",
                 "/vol/root/lua-files-renamed-link"))
assert(os.remove("/vol/root/lua-files-renamed-link"))
check = assert(io.open("/vol/root/hello.txt", "r"))
assert(check:read("l") == "native ext4 mount")
assert(check:close())

file = assert(io.open("/tmp/lua-files-cross-device.txt", "w"))
assert(file:write("source preserved\n"))
assert(file:close())
local moved, move_message, move_errno =
    os.rename("/tmp/lua-files-cross-device.txt",
              "/vol/root/lua-files-cross-device.txt")
assert(moved == nil and move_errno == 18)
assert(move_message:match("cross%-device operation"))
check = assert(io.open("/tmp/lua-files-cross-device.txt", "r"))
assert(check:read("a") == "source preserved\n")
assert(check:close())
assert(os.remove("/tmp/lua-files-cross-device.txt"))

local read_only, read_only_message, read_only_errno =
    io.open("/recovery/motd", "w")
assert(read_only == nil and read_only_errno == 30)
assert(read_only_message:match("read%-only filesystem"))

assert(os.getenv("PWD") == "/" and os.getenv("HOME") == "/")
assert(os.getenv("PATH") == "/bin" and os.getenv("MISSING") == nil)
assert(os.execute([[lua -e 'assert(os.getenv("PWD") == "/")']]))

print("lua-files wrote", #contents, "bytes")
print("lua-files cleanup", io.open(path, "r") == nil,
      io.open(renamed, "r") == nil)
