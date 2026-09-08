#ifndef C_UTIL_H
#define C_UTIL_H

#include <stdint.h>

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

extern AppConfig default_config;

void config_init(AppConfig *cfg, const char *name, int flags);
const char *mode_name(int mode);
int mode_combine(int a, int b);
uint32_t config_magic(const AppConfig *cfg);
int node_count(const Node *head);
int node_sum(const Node *head);
void node_link(Node *a, Node *b);
int config_load(AppConfig *cfg, const char *name, int mode);

#endif  /* C_UTIL_H */
