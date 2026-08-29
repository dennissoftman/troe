#ifndef TROE_CPYTHON_MATH_OVERLAY_H
#define TROE_CPYTHON_MATH_OVERLAY_H
#include_next <math.h>
double acosh(double value);
double asinh(double value);
double atanh(double value);
double cbrt(double value);
double copysign(double magnitude, double sign);
double cosh(double value);
double erf(double value);
double erfc(double value);
double exp2(double value);
double expm1(double value);
double fma(double left, double right, double addend);
double hypot(double left, double right);
double log1p(double value);
double log2(double value);
double modf(double value, double *integer_part);
double nextafter(double value, double direction);
double round(double value);
double sinh(double value);
double tanh(double value);
double trunc(double value);
#endif
