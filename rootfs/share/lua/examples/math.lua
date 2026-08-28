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

-- TROE seeds Lua's standard generator from the kernel CSPRNG at launch. A
-- numerical distribution summary can expose obvious range or bias bugs, but
-- no finite statistical test can prove randomness or make math.random
-- cryptographic.
local random_samples = 60000
local buckets = { 0, 0, 0, 0, 0, 0 }
local sample_minimum = math.huge
local sample_maximum = -math.huge
local sample_sum = 0
local sample_squared_sum = 0
for _ = 1, random_samples do
  local face = math.random(6)
  buckets[face] = buckets[face] + 1
  sample_minimum = math.min(sample_minimum, face)
  sample_maximum = math.max(sample_maximum, face)
  sample_sum = sample_sum + face
  sample_squared_sum = sample_squared_sum + face * face
end

local expected = random_samples / #buckets
local chi_square = 0
local maximum_deviation = 0
local minimum_bucket = math.huge
local maximum_bucket = 0
for _, count in ipairs(buckets) do
  local deviation = math.abs(count - expected)
  maximum_deviation = math.max(maximum_deviation, deviation)
  chi_square = chi_square + deviation * deviation / expected
  minimum_bucket = math.min(minimum_bucket, count)
  maximum_bucket = math.max(maximum_bucket, count)
end

local sample_mean = sample_sum / random_samples
local sample_variance = sample_squared_sum / random_samples - sample_mean ^ 2
local sample_standard_deviation = math.sqrt(sample_variance)
local maximum_deviation_percent = maximum_deviation * 100 / expected
local uniformity_sanity = sample_minimum == 1 and sample_maximum == 6 and
  math.abs(sample_mean - 3.5) < 0.1 and
  maximum_deviation_percent < 10 and chi_square < 50
print(string.format(
  "random distribution\tsamples=%d min=%d max=%d average/mean=%.4f " ..
    "expected-mean=3.5000 standard-deviation=%.4f",
  random_samples,
  sample_minimum,
  sample_maximum,
  sample_mean,
  sample_standard_deviation
))
print(string.format(
  "random bucket range\tmin=%d max=%d expected=%.0f " ..
    "max-deviation=%.2f%% chi-square=%.3f",
  minimum_bucket,
  maximum_bucket,
  expected,
  maximum_deviation_percent,
  chi_square
))
print(string.format(
  "random uniformity\t%s\tsamples=%d",
  uniformity_sanity and "pass" or "suspicious",
  random_samples
))
print("random source", "kernel CSPRNG seed -> Lua math PRNG")
print("random caveat", "uniformity is evidence, not proof or cryptographic safety")
