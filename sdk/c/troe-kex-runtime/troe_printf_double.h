#ifndef TROE_PRINTF_DOUBLE_H
#define TROE_PRINTF_DOUBLE_H

/* Exact, allocation-free binary64 formatting for the freestanding printf
 * facade. The working decimal is the finite value's exact integer numerator,
 * represented in base 1e9 after eliminating its power-of-two denominator. */

#define TROE_DECIMAL_BASE 1000000000u
#define TROE_DECIMAL_LIMBS 128
#define TROE_DOUBLE_TEXT_BYTES 512

typedef struct TroeDecimalInteger {
  uint32_t limbs[TROE_DECIMAL_LIMBS];
  size_t count;
} TroeDecimalInteger;

typedef union TroePrintfDoubleBits {
  double value;
  uint64_t bits;
} TroePrintfDoubleBits;

static int troe_decimal_multiply(TroeDecimalInteger *value,
                                 uint32_t factor) {
  uint64_t carry = 0;
  for (size_t index = 0; index < value->count; ++index) {
    uint64_t product = (uint64_t)value->limbs[index] * factor + carry;
    value->limbs[index] = (uint32_t)(product % TROE_DECIMAL_BASE);
    carry = product / TROE_DECIMAL_BASE;
  }
  if (carry != 0) {
    if (value->count == TROE_DECIMAL_LIMBS)
      return -1;
    value->limbs[value->count++] = (uint32_t)carry;
  }
  return 0;
}

static size_t troe_decimal_u32(char *destination, uint32_t value,
                               int padded) {
  char reversed[10];
  size_t count = 0;
  do {
    reversed[count++] = (char)('0' + value % 10);
    value /= 10;
  } while (value != 0);
  while (padded && count < 9)
    reversed[count++] = '0';
  for (size_t index = 0; index < count; ++index)
    destination[index] = reversed[count - index - 1];
  return count;
}

static int troe_exact_decimal(double number, char *digits, size_t *length,
                              int *decimal_position) {
  TroePrintfDoubleBits converted = {.value = number};
  uint64_t exponent = (converted.bits >> 52) & 0x7ffu;
  uint64_t mantissa = converted.bits & UINT64_C(0x000fffffffffffff);
  int binary_exponent;
  TroeDecimalInteger integer = {{0}, 0};
  size_t output = 0;
  if (exponent == 0) {
    if (mantissa == 0) {
      digits[0] = '0';
      *length = 1;
      *decimal_position = 1;
      return 0;
    }
    binary_exponent = -1074;
  } else {
    mantissa |= UINT64_C(1) << 52;
    binary_exponent = (int)exponent - 1023 - 52;
  }
  integer.limbs[0] = (uint32_t)(mantissa % TROE_DECIMAL_BASE);
  integer.limbs[1] = (uint32_t)(mantissa / TROE_DECIMAL_BASE);
  integer.count = integer.limbs[1] == 0 ? 1 : 2;
  if (binary_exponent >= 0) {
    for (int shift = 0; shift < binary_exponent; ++shift) {
      if (troe_decimal_multiply(&integer, 2) != 0)
        return -1;
    }
  } else {
    for (int shift = 0; shift < -binary_exponent; ++shift) {
      if (troe_decimal_multiply(&integer, 5) != 0)
        return -1;
    }
  }
  for (size_t index = integer.count; index != 0; --index) {
    output += troe_decimal_u32(digits + output, integer.limbs[index - 1],
                               index != integer.count);
  }
  *length = output;
  *decimal_position =
      binary_exponent >= 0 ? (int)output : (int)output + binary_exponent;
  return 0;
}

static int troe_nonzero_tail(const char *digits, size_t start,
                             size_t length) {
  for (size_t index = start; index < length; ++index) {
    if (digits[index] != '0')
      return 1;
  }
  return 0;
}

static int troe_should_round(char next, int sticky, char last) {
  return next > '5' ||
         (next == '5' && (sticky || ((last - '0') & 1) != 0));
}

static int troe_increment_digits(char *digits, size_t length) {
  while (length != 0) {
    --length;
    if (digits[length] != '9') {
      ++digits[length];
      return 0;
    }
    digits[length] = '0';
  }
  return 1;
}

static char troe_exact_digit(const char *digits, size_t length, int index) {
  return index >= 0 && (size_t)index < length ? digits[index] : '0';
}

static int troe_format_fixed(const char *exact, size_t exact_length,
                             int decimal_position, int precision, int alternate,
                             char *destination) {
  int integer_digits = decimal_position > 0 ? decimal_position : 1;
  size_t raw_length = (size_t)integer_digits + (size_t)precision;
  char raw[TROE_DOUBLE_TEXT_BYTES];
  int cutoff;
  char next;
  int sticky;
  if (raw_length + 2 > sizeof(raw))
    return -1;
  for (int index = 0; index < integer_digits; ++index) {
    int exponent = integer_digits - index - 1;
    raw[index] = troe_exact_digit(exact, exact_length,
                                  decimal_position - exponent - 1);
  }
  for (int index = 0; index < precision; ++index)
    raw[integer_digits + index] =
        troe_exact_digit(exact, exact_length, decimal_position + index);
  cutoff = decimal_position + precision;
  next = troe_exact_digit(exact, exact_length, cutoff);
  sticky = cutoff < 0
               ? troe_nonzero_tail(exact, 0, exact_length)
               : troe_nonzero_tail(exact, (size_t)cutoff + 1, exact_length);
  if (troe_should_round(next, sticky, raw[raw_length - 1]) &&
      troe_increment_digits(raw, raw_length)) {
    for (size_t index = raw_length; index != 0; --index)
      raw[index] = raw[index - 1];
    raw[0] = '1';
    ++raw_length;
    ++integer_digits;
  }
  memcpy(destination, raw, (size_t)integer_digits);
  size_t output = (size_t)integer_digits;
  if (precision != 0 || alternate)
    destination[output++] = '.';
  if (precision != 0) {
    memcpy(destination + output, raw + integer_digits, (size_t)precision);
    output += (size_t)precision;
  }
  return (int)output;
}

static int troe_rounded_exponent(const char *exact, size_t exact_length,
                                 int decimal_position, int significant) {
  char kept[100];
  int exponent = decimal_position - 1;
  for (int index = 0; index < significant; ++index)
    kept[index] = troe_exact_digit(exact, exact_length, index);
  if (troe_should_round(troe_exact_digit(exact, exact_length, significant),
                        troe_nonzero_tail(exact, (size_t)significant + 1,
                                          exact_length),
                        kept[significant - 1]) &&
      troe_increment_digits(kept, (size_t)significant))
    ++exponent;
  return exponent;
}

static int troe_format_scientific(const char *exact, size_t exact_length,
                                  int decimal_position, int precision,
                                  int alternate, int uppercase,
                                  char *destination) {
  int significant = precision + 1;
  int exponent = decimal_position - 1;
  char kept[100];
  size_t output = 0;
  if (significant > (int)sizeof(kept))
    return -1;
  for (int index = 0; index < significant; ++index)
    kept[index] = troe_exact_digit(exact, exact_length, index);
  if (troe_should_round(troe_exact_digit(exact, exact_length, significant),
                        troe_nonzero_tail(exact, (size_t)significant + 1,
                                          exact_length),
                        kept[significant - 1]) &&
      troe_increment_digits(kept, (size_t)significant)) {
    kept[0] = '1';
    for (int index = 1; index < significant; ++index)
      kept[index] = '0';
    ++exponent;
  }
  destination[output++] = kept[0];
  if (precision != 0 || alternate)
    destination[output++] = '.';
  if (precision != 0) {
    memcpy(destination + output, kept + 1, (size_t)precision);
    output += (size_t)precision;
  }
  destination[output++] = uppercase ? 'E' : 'e';
  destination[output++] = exponent < 0 ? '-' : '+';
  unsigned magnitude = (unsigned)(exponent < 0 ? -exponent : exponent);
  char reversed[8];
  size_t count = 0;
  do {
    reversed[count++] = (char)('0' + magnitude % 10);
    magnitude /= 10;
  } while (magnitude != 0);
  while (count < 2)
    reversed[count++] = '0';
  while (count != 0)
    destination[output++] = reversed[--count];
  return (int)output;
}

static int troe_trim_general(char *text, int length) {
  int exponent = length;
  int point = -1;
  for (int index = 0; index < length; ++index) {
    if (text[index] == '.')
      point = index;
    else if (text[index] == 'e' || text[index] == 'E') {
      exponent = index;
      break;
    }
  }
  if (point < 0)
    return length;
  int end = exponent;
  while (end > point + 1 && text[end - 1] == '0')
    --end;
  if (end == point + 1)
    --end;
  if (exponent != length) {
    memmove(text + end, text + exponent, (size_t)(length - exponent));
    end += length - exponent;
  }
  return end;
}

static int troe_format_double_payload(char *destination, double number,
                                      char conversion, int precision,
                                      int alternate) {
  TroePrintfDoubleBits converted = {.value = number};
  uint64_t exponent = (converted.bits >> 52) & 0x7ffu;
  uint64_t fraction = converted.bits & UINT64_C(0x000fffffffffffff);
  int uppercase = conversion >= 'A' && conversion <= 'Z';
  char exact[1100];
  size_t exact_length;
  int decimal_position;
  int length;
  if (exponent == 0x7ffu) {
    const char *word = fraction == 0 ? (uppercase ? "INF" : "inf")
                                     : (uppercase ? "NAN" : "nan");
    memcpy(destination, word, 3);
    return 3;
  }
  converted.bits &= ~(UINT64_C(1) << 63);
  if (troe_exact_decimal(converted.value, exact, &exact_length,
                         &decimal_position) != 0)
    return -1;
  if (conversion == 'f' || conversion == 'F')
    return troe_format_fixed(exact, exact_length, decimal_position, precision,
                             alternate, destination);
  if (conversion == 'e' || conversion == 'E')
    return troe_format_scientific(exact, exact_length, decimal_position,
                                  precision, alternate, uppercase, destination);
  if (precision == 0)
    precision = 1;
  int rounded_exponent = troe_rounded_exponent(
      exact, exact_length, decimal_position, precision);
  if (rounded_exponent < -4 || rounded_exponent >= precision) {
    length = troe_format_scientific(exact, exact_length, decimal_position,
                                    precision - 1, alternate, uppercase,
                                    destination);
  } else {
    length = troe_format_fixed(exact, exact_length, decimal_position,
                               precision - rounded_exponent - 1, alternate,
                               destination);
  }
  return alternate || length < 0 ? length
                                 : troe_trim_general(destination, length);
}

typedef struct TroePrintfWriter {
  char *destination;
  size_t capacity;
  size_t count;
} TroePrintfWriter;

static void troe_printf_byte(TroePrintfWriter *writer, char byte) {
  if (writer->count + 1 < writer->capacity)
    writer->destination[writer->count] = byte;
  ++writer->count;
}

static void troe_printf_bytes(TroePrintfWriter *writer, const char *bytes,
                              size_t length) {
  for (size_t index = 0; index < length; ++index)
    troe_printf_byte(writer, bytes[index]);
}

static int troe_vsnprintf_double(char *buffer, size_t size, const char *format,
                                 va_list arguments, int *handled) {
  const char *percent = strchr(format, '%');
  const char *cursor;
  int left = 0, plus = 0, space = 0, alternate = 0, zero = 0;
  int width = 0, precision = 6, explicit_precision = 0;
  int long_double = 0;
  char conversion;
  char payload[TROE_DOUBLE_TEXT_BYTES];
  int payload_length;
  TroePrintfDoubleBits value;
  TroePrintfWriter writer = {buffer, size, 0};
  *handled = 0;
  if (percent == NULL || percent[1] == '%')
    return 0;
  cursor = percent + 1;
  for (;;) {
    if (*cursor == '-') left = 1;
    else if (*cursor == '+') plus = 1;
    else if (*cursor == ' ') space = 1;
    else if (*cursor == '#') alternate = 1;
    else if (*cursor == '0') zero = 1;
    else break;
    ++cursor;
  }
  while (*cursor >= '0' && *cursor <= '9') {
    if (width > 1000000)
      return 0;
    width = width * 10 + *cursor++ - '0';
  }
  if (*cursor == '.') {
    explicit_precision = 1;
    precision = 0;
    ++cursor;
    while (*cursor >= '0' && *cursor <= '9') {
      if (precision > 1000000)
        return 0;
      precision = precision * 10 + *cursor++ - '0';
    }
  }
  if (*cursor == 'l')
    ++cursor;
  else if (*cursor == 'L') {
    long_double = 1;
    ++cursor;
  }
  conversion = *cursor++;
  if (conversion != 'f' && conversion != 'F' && conversion != 'e' &&
      conversion != 'E' && conversion != 'g' && conversion != 'G')
    return 0;
  if (strchr(cursor, '%') != NULL || precision > 99)
    return 0;
  (void)explicit_precision;
  value.value = long_double ? (double)va_arg(arguments, long double)
                            : va_arg(arguments, double);
  if (((value.bits >> 52) & 0x7ffu) == 0x7ffu)
    zero = 0;
  payload_length = troe_format_double_payload(payload, value.value, conversion,
                                              precision, alternate);
  if (payload_length < 0)
    return 0;
  *handled = 1;
  troe_printf_bytes(&writer, format, (size_t)(percent - format));
  char sign = (value.bits >> 63) != 0 ? '-' : (plus ? '+' : (space ? ' ' : 0));
  int padding = width - payload_length - (sign != 0);
  if (padding < 0)
    padding = 0;
  if (!left && !zero)
    while (padding-- != 0) troe_printf_byte(&writer, ' ');
  if (sign != 0)
    troe_printf_byte(&writer, sign);
  if (!left && zero)
    while (padding-- != 0) troe_printf_byte(&writer, '0');
  troe_printf_bytes(&writer, payload, (size_t)payload_length);
  if (left)
    while (padding-- != 0) troe_printf_byte(&writer, ' ');
  troe_printf_bytes(&writer, cursor, strlen(cursor));
  if (size != 0) {
    size_t terminator = writer.count < size ? writer.count : size - 1;
    buffer[terminator] = '\0';
  }
  return writer.count > (size_t)INT_MAX ? -1 : (int)writer.count;
}

#endif
