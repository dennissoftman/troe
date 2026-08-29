#ifndef TROE_ASSERT_H
#define TROE_ASSERT_H

#ifdef NDEBUG
#define assert(expression) ((void)0)
#else
void troe_assert_fail(const char *expression, const char *file, int line,
                      const char *function) __attribute__((noreturn));
#define assert(expression) \
  ((expression) ? (void)0 : troe_assert_fail(#expression, __FILE__, __LINE__, __func__))
#endif

#endif
