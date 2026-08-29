-- Portable Lua 5.5 compute and allocation benchmark for TROE and Alpine.
--
-- Usage: lua benchmark.lua [SCALE [SAMPLES [LABEL]]]
--
-- Run the same file, scale, and sample count in both guests. LABEL is included
-- in every output record and may contain ASCII letters, digits, '.', '_', '-'.

local function fail(message)
  io.stderr:write("lua-benchmark: ", message, "\n")
  io.stderr:write("usage: lua benchmark.lua [SCALE [SAMPLES [LABEL]]]\n")
  os.exit(2)
end

local function bounded_integer(value, default, minimum, maximum, name)
  if value == nil then
    return default
  end
  local number = tonumber(value)
  if number == nil or math.type(number) ~= "integer" or
      number < minimum or number > maximum then
    fail(string.format("%s must be an integer from %d through %d", name, minimum, maximum))
  end
  return number
end

local scale = bounded_integer(arg[1], 1, 1, 4, "scale")
local sample_count = bounded_integer(arg[2], 5, 1, 9, "samples")
local label = arg[3] or "unlabeled"
if not label:match("^[%w._-]+$") then
  fail("label contains unsupported characters")
end

local function sorted_copy(values)
  local copy = {}
  for index, value in ipairs(values) do
    copy[index] = value
  end
  table.sort(copy)
  return copy
end

local function median(values)
  local copy = sorted_copy(values)
  local middle = (#copy + 1) // 2
  if #copy % 2 == 1 then
    return copy[middle]
  end
  return (copy[middle] + copy[middle + 1]) / 2
end

local function minimum(values)
  local result = math.huge
  for _, value in ipairs(values) do
    result = math.min(result, value)
  end
  return result
end

local function maximum(values)
  local result = -math.huge
  for _, value in ipairs(values) do
    result = math.max(result, value)
  end
  return result
end

local function safe_rate(units, seconds)
  if seconds <= 0 then
    return 0
  end
  return units / seconds
end

local sink = 0

local function integer_mix(iterations)
  local value = 2463534242
  local checksum = 0
  for index = 1, iterations do
    value = value ~ (value << 13)
    value = value ~ (value >> 17)
    value = value ~ (value << 5)
    value = value & 0x7fffffff
    checksum = (checksum + value + index) & 0x7fffffff
  end
  return checksum
end

local function floating_arithmetic(iterations)
  local value = 0.5
  local increment = 0.000001
  local checksum = 0.0
  for _ = 1, iterations do
    value = value * 1.0000001192092896 + increment
    increment = increment + 0.000001
    if increment > 0.000097 then
      increment = 0.000001
    end
    if value > 2.0 then
      value = value - 1.5
    end
    checksum = checksum + value
  end
  return math.floor(checksum * 1000.0) & 0x7fffffff
end

local function retained_records(records)
  local rows = {}
  for index = 1, records do
    rows[index] = {
      index,
      index + 1,
      index + 2,
      index + 3,
      "record-" .. index,
    }
  end
  local last = rows[records]
  local checksum = (#rows + last[1] + last[4] + #last[5]) & 0x7fffffff
  return checksum, rows
end

local function allocation_churn(records)
  local batch_size = 2000
  local completed = 0
  local checksum = 0
  local baseline_kib = collectgarbage("count")
  local peak_kib = baseline_kib
  while completed < records do
    local count = math.min(batch_size, records - completed)
    local batch = {}
    for offset = 1, count do
      local value = completed + offset
      batch[offset] = { value, value + 1, "churn-" .. value }
    end
    checksum = (checksum + batch[count][1] + #batch[count][3]) & 0x7fffffff
    peak_kib = math.max(peak_kib, collectgarbage("count"))
    batch = nil
    collectgarbage("collect")
    completed = completed + count
  end
  return checksum, nil, peak_kib - baseline_kib
end

local function run_phase(name, kind, units, operation)
  collectgarbage("collect")
  local warmup_units = math.max(1, units // 20)
  local _, warmup_retained = operation(warmup_units)
  warmup_retained = nil
  collectgarbage("collect")

  local elapsed_samples = {}
  local live_samples = {}
  local reclaimed_samples = {}
  local peak_samples = {}
  local expected_checksum = nil

  for sample = 1, sample_count do
    collectgarbage("collect")
    local baseline_kib = collectgarbage("count")
    local started = os.clock()
    local checksum, retained, reported_peak_kib = operation(units)
    local elapsed = os.clock() - started
    local live_kib = math.max(0, collectgarbage("count") - baseline_kib)

    if expected_checksum == nil then
      expected_checksum = checksum
    elseif checksum ~= expected_checksum then
      fail(string.format("%s checksum changed in sample %d", name, sample))
    end

    elapsed_samples[sample] = elapsed
    live_samples[sample] = live_kib
    peak_samples[sample] = reported_peak_kib or live_kib
    sink = (sink ~ checksum) & 0x7fffffff

    retained = nil
    collectgarbage("collect")
    reclaimed_samples[sample] = math.max(
      0,
      live_kib - math.max(0, collectgarbage("count") - baseline_kib)
    )
  end

  local median_seconds = median(elapsed_samples)
  local median_live_kib = median(live_samples)
  local median_peak_kib = median(peak_samples)
  local median_reclaimed_kib = median(reclaimed_samples)
  local rate = safe_rate(units, median_seconds)

  if kind == "compute" then
    print(string.format(
      "RESULT label=%s name=%s kind=%s units=%d samples=%d " ..
        "median_s=%.6f min_s=%.6f max_s=%.6f units_per_s=%.0f checksum=%d",
      label,
      name,
      kind,
      units,
      sample_count,
      median_seconds,
      minimum(elapsed_samples),
      maximum(elapsed_samples),
      rate,
      expected_checksum
    ))
  else
    print(string.format(
      "RESULT label=%s name=%s kind=%s records=%d samples=%d " ..
        "median_s=%.6f min_s=%.6f max_s=%.6f records_per_s=%.0f " ..
        "live_kib=%.1f peak_kib=%.1f reclaimed_kib=%.1f " ..
        "live_mib_per_s=%.2f checksum=%d",
      label,
      name,
      kind,
      units,
      sample_count,
      median_seconds,
      minimum(elapsed_samples),
      maximum(elapsed_samples),
      rate,
      median_live_kib,
      median_peak_kib,
      median_reclaimed_kib,
      safe_rate(median_live_kib / 1024, median_seconds),
      expected_checksum
    ))
  end
end

local previous_gc_mode = collectgarbage("incremental", 120, 200, 13)
collectgarbage("collect")
local baseline_kib = collectgarbage("count")
local lua_version = _VERSION:gsub(" ", "_")

print(string.format(
  "BENCHMARK version=1 label=%s lua=%s scale=%d samples=%d " ..
    "timer=os.clock gc=incremental previous_gc=%s baseline_kib=%.1f",
  label,
  lua_version,
  scale,
  sample_count,
  previous_gc_mode,
  baseline_kib
))

run_phase("integer_mix", "compute", 2000000 * scale, integer_mix)
run_phase("floating_arithmetic", "compute", 1500000 * scale, floating_arithmetic)
run_phase("retained_records", "allocation", 30000 * scale, retained_records)
run_phase("allocation_churn", "allocation_gc", 80000 * scale, allocation_churn)

collectgarbage("collect")
print(string.format(
  "END label=%s sink=%d final_kib=%.1f",
  label,
  sink,
  collectgarbage("count")
))
