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

/* Compiler runtime conversions pulled in by the C sysroot's long-double
 * formatting paths on aarch64. The configure links never execute. The final
 * KEX obtains the real implementations from Rust's compiler_builtins. */
double __trunctfdf2(long double value) { (void)value; return 0.0; }
long double __extenddftf2(double value) { (void)value; return 0.0L; }
