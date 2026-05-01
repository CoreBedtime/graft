#ifndef KPROC_INIT_SPAWN_REQUEST_H
#define KPROC_INIT_SPAWN_REQUEST_H

#include <spawn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xpc/xpc.h>

#include "spawn_blob.h"

struct kproc_spawn_request {
  const struct kproc_spawn_blob *blob;
  const char *program;
  const char *cwd;
  const char *stdin_path;
  const char *stdout_path;
  const char *stderr_path;
  const char *username;
  const char *groupname;
  uid_t uid;
  gid_t gid;
  bool has_identity;
  bool use_path_search;
  bool set_umask;
  mode_t umask_value;
  uint32_t flags;
  uint32_t process_type;
  uint32_t qos_class;
  const char **argv;
  size_t argc;
  const char **envp;
  size_t envc;
};

bool kproc_spawn_request_decode(const struct kproc_spawn_blob *blob, struct kproc_spawn_request *request);
void kproc_spawn_request_destroy(struct kproc_spawn_request *request);
int kproc_spawn_request_execute(const struct kproc_spawn_request *request, xpc_object_t ports, xpc_object_t fds);

#endif
