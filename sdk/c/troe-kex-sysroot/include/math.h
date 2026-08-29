#ifndef TROE_MATH_H
#define TROE_MATH_H

#define HUGE_VAL (__builtin_huge_val())
#define INFINITY (__builtin_inff())
#define NAN (__builtin_nanf(""))
#define M_PI 3.14159265358979323846
#define isfinite(value) __builtin_isfinite(value)
#define isinf(value) __builtin_isinf(value)
#define isnan(value) __builtin_isnan(value)
#define signbit(value) __builtin_signbit(value)

double acos(double value);
double asin(double value);
double atan(double value);
double atan2(double left, double right);
double ceil(double value);
double cos(double value);
double exp(double value);
double fabs(double value);
double floor(double value);
double fmod(double left, double right);
double frexp(double value, int *exponent);
double ldexp(double value, int exponent);
double log(double value);
double log10(double value);
double pow(double left, double right);
double sin(double value);
double sqrt(double value);
double tan(double value);

#endif
