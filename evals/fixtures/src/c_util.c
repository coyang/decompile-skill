#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  uint32_t magic;
  char name[32];
  int flags;
} AppConfig;

enum LoadMode { LOAD_RDONLY = 1, LOAD_WRONLY = 2, LOAD_RDWR = 3 };

typedef struct Node {
  int value;
  struct Node *next;
} Node;

AppConfig default_config = { 0x41424344u, "default", 0 };

static int node_depth(const Node *n) {
  int d = 0;
  while (n != NULL) {
    d++;
    n = n->next;
  }
  return d;
}

static uint32_t fold_magic(uint32_t m) {
  return (m ^ (m >> 16)) * 2654435761u;
}

void config_init(AppConfig *cfg, const char *name, int flags) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->magic = fold_magic(0x12345678u);
  if (name != NULL) {
    strncpy(cfg->name, name, sizeof(cfg->name) - 1);
  }
  cfg->flags = flags;
}

const char *mode_name(int mode) {
  switch (mode) {
    case LOAD_RDONLY:
      return "read-only";
    case LOAD_WRONLY:
      return "write-only";
    case LOAD_RDWR:
      return "read-write";
    default:
      return "unknown";
  }
}

int mode_combine(int a, int b) {
  int m = a | b;
  if (m > LOAD_RDWR) {
    return -1;
  }
  return m;
}

uint32_t config_magic(const AppConfig *cfg) {
  return fold_magic(cfg->magic);
}

int node_count(const Node *head) {
  if (head == NULL) {
    fprintf(stderr, "node_count: null head\n");
    return -1;
  }
  return node_depth(head);
}

int node_sum(const Node *head) {
  if (head == NULL) {
    return 0;
  }
  return head->value + node_sum(head->next);
}

void node_link(Node *a, Node *b) {
  a->next = b;
}

int config_load(AppConfig *cfg, const char *name, int mode) {
  if (cfg == NULL) {
    fprintf(stderr, "config_load: null cfg\n");
    return -1;
  }
  config_init(cfg, name, mode);
  if (mode < LOAD_RDONLY || mode > LOAD_RDWR) {
    fprintf(stderr, "config_load: bad mode %d\n", mode);
    return -1;
  }
  return 0;
}
