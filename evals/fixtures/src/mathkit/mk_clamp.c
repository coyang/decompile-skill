int mk_sub(int a, int b);

int mk_clamp(int v, int lo, int hi) {
  int span = mk_sub(hi, lo);
  if (span <= 0) {
    return lo;
  }
  if (v < lo) {
    return lo;
  }
  if (v > hi) {
    return hi;
  }
  return v;
}
