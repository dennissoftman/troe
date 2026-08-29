-- Core Lua strings, tables, metatables, and cooperative coroutines.

local template = "hello, ${name}!"
local rendered = template:gsub("%${(%w+)}", { name = "TROE" })
local first, last = rendered:find("TROE", 1, true)

print(rendered)
print(string.format("match=%d..%d upper=%s", first, last, rendered:upper()))

local packed = string.pack("<i2I2", -123, 456)
local signed, unsigned = string.unpack("<i2I2", packed)
print(string.format("packed=%d bytes values=%d,%d", #packed, signed, unsigned))

local symbol = "λ"
print(string.format(
  "utf8=%d codepoint, %d bytes, U+%04X",
  utf8.len(symbol),
  #symbol,
  utf8.codepoint(symbol)
))

local tasks = {
  { name = "render", priority = 2 },
  { name = "network", priority = 3 },
  { name = "cleanup", priority = 1 },
}

table.sort(tasks, function(left, right)
  return left.priority > right.priority
end)

for index, task in ipairs(tasks) do
  print(string.format("task %d: %s (priority %d)", index, task.name, task.priority))
end

local vector = {}
vector.__index = vector

function vector.new(x, y)
  return setmetatable({ x = x, y = y }, vector)
end

function vector.__add(left, right)
  return vector.new(left.x + right.x, left.y + right.y)
end

function vector.__tostring(value)
  return string.format("(%d, %d)", value.x, value.y)
end

print("vector sum: " .. tostring(vector.new(2, 3) + vector.new(5, 7)))

local squares = coroutine.create(function(limit)
  for value = 1, limit do
    coroutine.yield(value, value * value)
  end
end)

while coroutine.status(squares) ~= "dead" do
  local ok, value, square = coroutine.resume(squares, 4)
  assert(ok, value)
  if value ~= nil then
    print(string.format("square(%d)=%d", value, square))
  end
end
