#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long accumulate(const char *const *argv, int n) {
  long acc = 0;
  for (int i = 0; i < n; ++i) {
    acc += strtol(argv[i], NULL, 10);
  }
  return acc;
}

static int apply_op(char op, int a, int b) {
  switch (op) {
    case '+':
      return a + b;
    case '-':
      return a > b ? a - b : 0;
    case '*':
      return a * b;
    default:
      return -1;
  }
}

static void usage(const char *prog) {
  printf("usage: %s [+|-|*] a b\n", prog);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--sum") == 0) {
    printf("%ld\n", accumulate(argv + 2, argc - 2));
    return 0;
  }
  if (argc != 4) {
    usage(argv[0]);
    fprintf(stderr, "calc: expected 3 arguments\n");
    return 1;
  }
  int a = atoi(argv[2]);
  int b = atoi(argv[3]);
  int r = apply_op(argv[1][0], a, b);
  if (r < 0) {
    fprintf(stderr, "calc: unknown operator '%s'\n", argv[1]);
    return 1;
  }
  printf("%d\n", r);
  return 0;
}
