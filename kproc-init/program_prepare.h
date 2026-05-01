#ifndef KPROC_INIT_PROGRAM_PREPARE_H
#define KPROC_INIT_PROGRAM_PREPARE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/param.h>

struct kproc_prepared_program {
  char path[MAXPATHLEN];
  char bundle_path[MAXPATHLEN];
  bool is_bundle_copy;
};

int kproc_prepare_program(const char *program,
                          bool use_path_search,
                          const char *const envp[],
                          struct kproc_prepared_program *prepared);

#endif
