local ok, message = pcall(function()
  error("protected jump")
end)
assert(not ok and message:match("protected jump"))

local values = {}
for index = 1, 4096 do
  values[index] = string.rep("x", index % 127)
end
for index = 1, #values, 2 do
  values[index] = nil
end
collectgarbage()

local sum = 0
for index = 1, 50000 do
  sum = sum + index
end

local encoded = string.pack("<i4I4", -7, 42)
local signed, unsigned = string.unpack("<i4I4", encoded)
assert(signed == -7 and unsigned == 42)

print(string.format(
  "lua-file:%s sum=%d sqrt=%.0f pow=%.0f",
  arg[1], sum, math.sqrt(81), 2 ^ 10
))
