static _Thread_local unsigned long long marker = 0x1122334455667788ULL;
static _Thread_local unsigned long long count;

int troe_native_canary(int advance) {
  if (advance) {
    if (marker != 0x1122334455667788ULL || count != 0) return 1;
    marker += 0x22;
    ++count;
    return 0;
  }
  return marker != 0x11223344556677aaULL || count != 1;
}
