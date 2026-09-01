#include <stddef.h>
#include <stdint.h>

int isalnum(int value) { return value; }
int isalpha(int value) { return value; }
int isdigit(int value) { return value; }
int islower(int value) { return value; }
int isspace(int value) { return value; }
int isupper(int value) { return value; }
int tolower(int value) { return value; }
int toupper(int value) { return value; }

uint64_t troe_parse_decimal(const char *text, size_t length, int *status) {
  (void)text;
  (void)length;
  if (status != NULL)
    *status = 0;
  return 0;
}

#define TROE_MATH_UNARY(name)                                                 \
  uint64_t name(uint64_t value) { return value; }
#define TROE_MATH_BINARY(name)                                                \
  uint64_t name(uint64_t left, uint64_t right) {                             \
    (void)right;                                                              \
    return left;                                                              \
  }
TROE_MATH_UNARY(troe_math_acos_bits)
TROE_MATH_UNARY(troe_math_asin_bits)
TROE_MATH_UNARY(troe_math_atan_bits)
TROE_MATH_BINARY(troe_math_atan2_bits)
TROE_MATH_UNARY(troe_math_ceil_bits)
TROE_MATH_UNARY(troe_math_cos_bits)
TROE_MATH_UNARY(troe_math_exp_bits)
TROE_MATH_UNARY(troe_math_fabs_bits)
TROE_MATH_UNARY(troe_math_floor_bits)
TROE_MATH_BINARY(troe_math_fmod_bits)
TROE_MATH_BINARY(troe_math_frexp_bits)
TROE_MATH_BINARY(troe_math_ldexp_bits)
TROE_MATH_UNARY(troe_math_log_bits)
TROE_MATH_UNARY(troe_math_log10_bits)
TROE_MATH_BINARY(troe_math_pow_bits)
TROE_MATH_UNARY(troe_math_sin_bits)
TROE_MATH_UNARY(troe_math_sqrt_bits)
TROE_MATH_UNARY(troe_math_tan_bits)

double acosh(double value) { return value; }
double asinh(double value) { return value; }
double atanh(double value) { return value; }
double erf(double value) { return value; }
double erfc(double value) { return value; }
double expm1(double value) { return value; }
double log1p(double value) { return value; }
double log2(double value) { return value; }

/* Timezone rule evaluation the C sysroot's `tzset`, `localtime_r` and `mktime`
 * obtain from the Rust KEX runtime, which configure never links. As with the
 * math stubs above, only the symbol has to resolve: these never execute, and a
 * fourth copy of the calendar layout would be one more mirror to keep in step
 * for no gain. The final KEX links the real implementations. See ADR 0067. */
void troe_runtime_zone_summary(void) {}
void troe_runtime_local_calendar_from_seconds(void) {}
void troe_runtime_normalize_local_calendar(void) {}

/* Compiler runtime conversions pulled in by the C sysroot's long-double
 * formatting paths on aarch64. The configure links never execute. The final
 * KEX obtains the real implementations from Rust's compiler_builtins. */
double __trunctfdf2(long double value) { (void)value; return 0.0; }
long double __extenddftf2(double value) { (void)value; return 0.0L; }
