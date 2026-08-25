-- Floating-point math, integer arithmetic, and a small statistics example.

for _, degrees in ipairs({ 0, 30, 45, 60, 90 }) do
  local radians = math.rad(degrees)
  print(string.format(
    "%3d degrees: sin=% .6f cos=% .6f",
    degrees,
    math.sin(radians),
    math.cos(radians)
  ))
end

local samples = { 2, 4, 4, 4, 5, 5, 7, 9 }
local total = 0
for _, value in ipairs(samples) do
  total = total + value
end

local mean = total / #samples
local squared_error = 0
for _, value in ipairs(samples) do
  squared_error = squared_error + (value - mean) ^ 2
end

local function gcd(left, right)
  while right ~= 0 do
    left, right = right, left % right
  end
  return left
end

print(string.format(
  "mean=%.2f standard-deviation=%.2f",
  mean,
  math.sqrt(squared_error / #samples)
))
print(string.format(
  "2^10=%.0f log2(1024)=%.0f gcd(84,30)=%d",
  2 ^ 10,
  math.log(1024, 2),
  gcd(84, 30)
))
