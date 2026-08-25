#ifndef TROE_MATH_H
#define TROE_MATH_H

#define HUGE_VAL (__builtin_huge_val())

double acos(double value);
double asin(double value);
double atan(double value);
double atan2(double y, double x);
double ceil(double value);
double cos(double value);
double exp(double value);
double fabs(double value);
double floor(double value);
double fmod(double x, double y);
double frexp(double value, int *exponent);
double ldexp(double value, int exponent);
double log(double value);
double log10(double value);
double pow(double x, double y);
double sin(double value);
double sqrt(double value);
double tan(double value);

#endif
