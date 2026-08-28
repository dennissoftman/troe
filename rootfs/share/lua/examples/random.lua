-- Standard Lua random sampling, automatically seeded from TROE's CSPRNG.
--
-- math.random is appropriate for games, simulations, shuffling, and sampling.
-- It is not a cryptographic byte generator; security-sensitive applications
-- should use a native runtime API backed directly by the random capability.

local dice = {}
for index = 1, 6 do
  dice[index] = math.random(1, 6)
  assert(dice[index] >= 1 and dice[index] <= 6)
end

local choices = { "red", "green", "blue", "gold" }
local choice = choices[math.random(#choices)]
assert(choice ~= nil)

local deck = { "A", "B", "C", "D", "E" }
for index = #deck, 2, -1 do
  local selected = math.random(index)
  deck[index], deck[selected] = deck[selected], deck[index]
end

local unit = math.random()
assert(unit >= 0 and unit < 1)

print("lua-random dice", table.concat(dice, ","))
print("lua-random choice", choice)
print("lua-random shuffle", table.concat(deck, ""))
print("lua-random checks", "ok", #deck, unit >= 0 and unit < 1)
