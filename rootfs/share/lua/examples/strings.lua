-- String patterns, formatting, binary packing, and UTF-8 helpers.

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
