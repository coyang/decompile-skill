int mk_mul(int a, int b) {
  int acc = 0;
  for (int i = 0; i < b; ++i) {
    acc += a;
  }
  return acc;
}
