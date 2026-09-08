#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "c_util.h"

/* src:@0x101149 */  /* (G) whole body in fn_00101149_node_depth.c */
static int node_depth(const Node *n) {
  int d = 0;
  while (n != NULL) {
    d++;
    n = n->next;
  }
  return d;
}

/* src:@0x101176 */  /* (G) whole body in fn_00101176_fold_magic.c */
static uint32_t fold_magic(uint32_t m) {
  return (m ^ (m >> 16)) * 2654435761u;
}

/* src:@0x10118e */  /* (G) whole body in fn_0010118e_config_init.c */
void config_init(AppConfig *cfg, const char *name, int flags) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->magic = fold_magic(0x12345678u);
  if (name != NULL) {
    strncpy(cfg->name, name, sizeof(cfg->name) - 1);
  }
  cfg->flags = flags;
}

/* src:@0x1011f7 */  /* (G) switch arms and literals in fn_001011f7_mode_name.c */
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

/* src:@0x10123c */  /* (G) whole body in fn_0010123c_mode_combine.c */
int mode_combine(int a, int b) {
  return a | b;
}

/* src:@0x101261 */  /* (G) whole body in fn_00101261_config_magic.c */
uint32_t config_magic(const AppConfig *cfg) {
  return fold_magic(cfg->magic);
}

/* src:@0x10127c */  /* (G) whole body in fn_0010127c_node_count.c */
int node_count(const Node *head) {
  if (head == NULL) {
    fprintf(stderr, "node_count: null head\n");
    return -1;
  }
  return node_depth(head);
}

/* src:@0x1012ca */  /* (G) whole body in fn_001012ca_node_sum.c */
int node_sum(const Node *head) {
  if (head == NULL) {
    return 0;
  }
  return head->value + node_sum(head->next);
}

/* src:@0x101303 */  /* (G) whole body in fn_00101303_node_link.c */
void node_link(Node *a, Node *b) {
  a->next = b;
}

/* src:@0x10131e */  /* (G) whole body in fn_0010131e_config_load.c */
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

/* (I) initializer read from raw bytes, not from the decompiler — see NOTES.md */
AppConfig default_config = { 0x41424344u, "default", 0 };
