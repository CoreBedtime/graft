#include "spawn_request.h"

#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <mach/mach.h>
#include <pthread/spawn.h>
#include <pthread/qos.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diagnostics.h"
#include "program_prepare.h"

extern char **environ;

typedef mach_port_t (*xpc_mach_send_get_right_fn)(xpc_object_t object);

enum {
  OFF_PROGRAM = 4,
  OFF_CONSTRAINT_DATA = 8,
  OFF_CONSTRAINT_SIZE = 12,
  OFF_ARGC = 16,
  OFF_ARGV = 20,
  OFF_ENVC = 24,
  OFF_ENVP = 28,
  OFF_BINPREF_COUNT = 32,
  OFF_BINPREFS = 36,
  OFF_USERNAME = 40,
  OFF_GROUPNAME = 44,
  OFF_UID = 48,
  OFF_UMASK = 52,
  OFF_CWD = 64,
  OFF_STDIN = 68,
  OFF_STDOUT = 72,
  OFF_STDERR = 76,
  OFF_SUBSYSTEM_ROOT = 88,
  OFF_PROCESS_TYPE = 112,
  OFF_QOS_CLASS = 200,
  OFF_RLIMIT_COUNT = 204,
  OFF_RLIMITS = 208,
  OFF_SPECIAL_PORTS = 216,
  OFF_SPECIAL_PORT_COUNT = 220,
  OFF_CPU_MONITOR_PERCENT = 228,
  OFF_DATALESS_IOPOLICY = 229,
  OFF_FLAGS = 236,
  OFF_FLAG_BYTE_237 = 237,
};

enum {
  SPAWN_FLAG_USE_PATH = 0x800,
  SPAWN_FLAG_USE_UID = 0x80000,
  SPAWN_FLAG_SKIP_IDENTITY = 0x100,
  SPAWN_FLAG_HIDE_SETUP_EVENTS = 0x80,
  SPAWN_FLAG_CPU_MONITOR_DEFAULT = 0x2,
};

static bool
checked_calloc(void **out, size_t count, size_t size)
{
  if (count != 0 && size > SIZE_MAX / count) {
    return false;
  }

  *out = calloc(count, size);
  return *out != NULL;
}

static const char **
copy_environ(size_t *count)
{
  size_t envc = 0;
  const char **copy;

  while (environ[envc] != NULL) {
    envc++;
  }

  if (!checked_calloc((void **) &copy, envc + 1, sizeof(char *))) {
    return NULL;
  }

  for (size_t i = 0; i != envc; i++) {
    copy[i] = environ[i];
  }
  copy[envc] = NULL;
  *count = envc;
  return copy;
}

static bool
decode_identity(const struct kproc_spawn_blob *blob, struct kproc_spawn_request *request)
{
  uint32_t username_offset = kproc_spawn_blob_u32(blob, OFF_USERNAME);
  uint32_t group_offset = kproc_spawn_blob_u32(blob, OFF_GROUPNAME);

  if ((request->flags & SPAWN_FLAG_SKIP_IDENTITY) != 0) {
    return true;
  }

  if ((request->flags & SPAWN_FLAG_USE_UID) != 0 && username_offset == 0) {
    struct passwd *pw;

    request->uid = kproc_spawn_blob_u32(blob, OFF_UID);
    errno = 0;
    pw = getpwuid(request->uid);
    if (pw == NULL) {
      return errno == 0 ? false : false;
    }

    request->gid = pw->pw_gid;
    request->username = pw->pw_name;
    request->has_identity = true;
    return true;
  }

  if (username_offset != 0) {
    request->username = kproc_spawn_blob_string(blob, username_offset);
    if (request->username == NULL) {
      return false;
    }
  }

  if (group_offset != 0) {
    request->groupname = kproc_spawn_blob_string(blob, group_offset);
    if (request->groupname == NULL) {
      return false;
    }
  }

  if (request->username == NULL && request->groupname != NULL) {
    request->username = "root";
  }

  if (request->username != NULL) {
    struct passwd *pw = getpwnam(request->username);
    if (pw == NULL) {
      return false;
    }

    request->uid = pw->pw_uid;
    request->gid = pw->pw_gid;
    request->has_identity = true;
  }

  if (request->groupname != NULL) {
    struct group *gr = getgrnam(request->groupname);
    if (gr == NULL) {
      return false;
    }

    request->gid = gr->gr_gid;
    request->has_identity = true;
  }

  return true;
}

bool
kproc_spawn_request_decode(const struct kproc_spawn_blob *blob, struct kproc_spawn_request *request)
{
  uint32_t program_offset;
  uint32_t argc;
  uint32_t argv_offset;
  uint32_t envc;
  uint32_t envp_offset;
  uint32_t cwd_offset;
  uint8_t flag_byte_237;

  memset(request, 0, sizeof(*request));
  request->blob = blob;

  program_offset = kproc_spawn_blob_u32(blob, OFF_PROGRAM);
  request->program = kproc_spawn_blob_string(blob, program_offset);
  if (request->program == NULL) {
    return false;
  }

  request->flags = kproc_spawn_blob_u32(blob, OFF_FLAGS);
  request->use_path_search = (request->flags & SPAWN_FLAG_USE_PATH) != 0;
  request->process_type = kproc_spawn_blob_u32(blob, OFF_PROCESS_TYPE);
  request->qos_class = kproc_spawn_blob_u32(blob, OFF_QOS_CLASS);

  flag_byte_237 = kproc_spawn_blob_u8(blob, OFF_FLAG_BYTE_237);
  request->set_umask = (flag_byte_237 & 0x20) != 0;
  request->umask_value = kproc_spawn_blob_u16(blob, OFF_UMASK);

  argc = kproc_spawn_blob_u32(blob, OFF_ARGC);
  argv_offset = kproc_spawn_blob_u32(blob, OFF_ARGV);
  if (!checked_calloc((void **) &request->argv, (argc != 0 ? argc : 1) + 1, sizeof(char *))) {
    return false;
  }
  if (argc != 0) {
    if (!kproc_spawn_blob_strings(blob, argv_offset, request->argv, argc)) {
      return false;
    }
    request->argc = argc;
  } else {
    request->argv[0] = request->program;
    request->argc = 1;
  }

  envc = kproc_spawn_blob_u32(blob, OFF_ENVC);
  envp_offset = kproc_spawn_blob_u32(blob, OFF_ENVP);
  if (envc != 0) {
    if (!checked_calloc((void **) &request->envp, envc + 1, sizeof(char *))) {
      return false;
    }
    if (!kproc_spawn_blob_strings(blob, envp_offset, request->envp, envc)) {
      return false;
    }
    request->envc = envc;
  } else {
    request->envp = copy_environ(&request->envc);
    if (request->envp == NULL) {
      return false;
    }
  }

  cwd_offset = kproc_spawn_blob_u32(blob, OFF_CWD);
  request->cwd = cwd_offset != 0 ? kproc_spawn_blob_string(blob, cwd_offset) : "/";
  if (request->cwd == NULL) {
    return false;
  }

  request->stdin_path = kproc_spawn_blob_string(blob, kproc_spawn_blob_u32(blob, OFF_STDIN));
  request->stdout_path = kproc_spawn_blob_string(blob, kproc_spawn_blob_u32(blob, OFF_STDOUT));
  request->stderr_path = kproc_spawn_blob_string(blob, kproc_spawn_blob_u32(blob, OFF_STDERR));

  if (!decode_identity(blob, request)) {
    return false;
  }

  return true;
}

void
kproc_spawn_request_destroy(struct kproc_spawn_request *request)
{
  free((void *) request->argv);
  free((void *) request->envp);
  memset(request, 0, sizeof(*request));
}

static int
mkparent(const char *path)
{
  char scratch[PATH_MAX];
  char *slash;

  if (strlcpy(scratch, path, sizeof(scratch)) >= sizeof(scratch)) {
    return ENAMETOOLONG;
  }

  slash = strrchr(scratch, '/');
  if (slash == NULL) {
    return EINVAL;
  }
  if (slash == scratch) {
    return 0;
  }

  *slash = '\0';
  int result = mkpath_np(scratch, 0755);
  return result == EEXIST ? 0 : result;
}

static bool
resolve_relative_path(const char *cwd, const char *path, char *buffer, size_t buffer_size, const char **resolved)
{
  if (path == NULL || path[0] == '\0') {
    *resolved = NULL;
    return true;
  }

  if (path[0] == '/') {
    *resolved = path;
    return true;
  }

  if (snprintf(buffer, buffer_size, "%s/%s", cwd, path) >= (int) buffer_size) {
    return false;
  }

  *resolved = buffer;
  return true;
}

static int
add_stdio_action(posix_spawn_file_actions_t *actions, int fd, const char *cwd, const char *path)
{
  char path_buffer[PATH_MAX];
  const char *resolved;
  int oflag;
  int error;

  if (!resolve_relative_path(cwd, path, path_buffer, sizeof(path_buffer), &resolved)) {
    return ENAMETOOLONG;
  }

  if (resolved == NULL) {
    resolved = "/dev/null";
    oflag = fd == STDIN_FILENO ? O_RDONLY : O_WRONLY;
  } else if (fd == STDIN_FILENO) {
    oflag = O_RDONLY | O_CREAT;
  } else {
    oflag = O_WRONLY | O_CREAT | O_APPEND;
  }

  error = mkparent(resolved);
  if (error != 0) {
    return error;
  }

  return posix_spawn_file_actions_addopen(actions, fd, resolved, oflag, 0666);
}

static int
apply_rlimits(const struct kproc_spawn_request *request)
{
  const struct kproc_spawn_blob *blob = request->blob;
  uint32_t count = kproc_spawn_blob_u32(blob, OFF_RLIMIT_COUNT);
  uint32_t offset = kproc_spawn_blob_u32(blob, OFF_RLIMITS);
  const uint8_t *entries = kproc_spawn_blob_payload(blob, offset, (size_t) count * 20);

  if (count == 0) {
    return 0;
  }
  if (entries == NULL) {
    return EINVAL;
  }

  for (uint32_t i = 0; i != count; i++) {
    const uint8_t *entry = entries + (i * 20);
    struct rlimit limit;
    uint64_t soft;
    uint64_t hard;
    uint16_t resource;
    uint8_t set_hard;
    uint8_t set_soft;

    memcpy(&soft, entry, sizeof(soft));
    memcpy(&hard, entry + 8, sizeof(hard));
    memcpy(&resource, entry + 16, sizeof(resource));
    set_hard = entry[18];
    set_soft = entry[19];

    if (getrlimit(resource, &limit) == -1) {
      return errno;
    }
    if (set_soft) {
      limit.rlim_cur = (rlim_t) soft;
    }
    if (set_hard) {
      limit.rlim_max = (rlim_t) hard;
    }
    if (setrlimit(resource, &limit) == -1) {
      return errno;
    }
  }

  return 0;
}

static int
apply_binprefs(const struct kproc_spawn_request *request, posix_spawnattr_t *attr)
{
  const struct kproc_spawn_blob *blob = request->blob;
  uint32_t count = kproc_spawn_blob_u32(blob, OFF_BINPREF_COUNT);
  uint32_t offset = kproc_spawn_blob_u32(blob, OFF_BINPREFS);
  const uint8_t *entries;
  cpu_type_t cpu_types[8];
  cpu_subtype_t cpu_subtypes[8];

  if (count == 0) {
    return 0;
  }
  if (count > 8) {
    return EINVAL;
  }

  entries = kproc_spawn_blob_payload(blob, offset, (size_t) count * 8);
  if (entries == NULL) {
    return EINVAL;
  }

  for (uint32_t i = 0; i != count; i++) {
    memcpy(&cpu_types[i], entries + (i * 8), sizeof(cpu_types[i]));
    memcpy(&cpu_subtypes[i], entries + (i * 8) + 4, sizeof(cpu_subtypes[i]));
  }

  return posix_spawnattr_setarchpref_np(attr, count, cpu_types, cpu_subtypes, NULL);
}

static int
apply_special_ports(const struct kproc_spawn_request *request, posix_spawnattr_t *attr, xpc_object_t ports)
{
  xpc_mach_send_get_right_fn get_right;
  const struct kproc_spawn_blob *blob = request->blob;
  uint32_t count = kproc_spawn_blob_u32(blob, OFF_SPECIAL_PORT_COUNT);
  uint32_t offset = kproc_spawn_blob_u32(blob, OFF_SPECIAL_PORTS);
  const uint8_t *port_names;

  if (count == 0 || ports == NULL) {
    return 0;
  }
  if (xpc_get_type(ports) != XPC_TYPE_ARRAY || xpc_array_get_count(ports) < count) {
    return EINVAL;
  }

  port_names = kproc_spawn_blob_payload(blob, offset, (size_t) count * sizeof(uint32_t));
  if (port_names == NULL) {
    return EINVAL;
  }

  get_right = (xpc_mach_send_get_right_fn) dlsym(RTLD_DEFAULT, "_xpc_mach_send_get_right");
  if (get_right == NULL) {
    get_right = (xpc_mach_send_get_right_fn) dlsym(RTLD_DEFAULT, "__xpc_mach_send_get_right");
  }
  if (get_right == NULL) {
    return 0;
  }

  for (uint32_t i = 0; i != count; i++) {
    uint32_t which;
    mach_port_t right;
    xpc_object_t port = xpc_array_get_value(ports, i);

    memcpy(&which, port_names + (i * sizeof(which)), sizeof(which));
    right = get_right(port);
    if (right == MACH_PORT_NULL || right == MACH_PORT_DEAD) {
      return EINVAL;
    }
    if (which >= 128 && which <= 130) {
      continue;
    }
    int error = posix_spawnattr_setspecialport_np(attr, right, (int) which);
    if (error != 0) {
      return error;
    }
  }

  return 0;
}

static int
apply_fd_actions(posix_spawn_file_actions_t *actions, xpc_object_t fds, int **owned_fds, size_t *owned_fd_count)
{
  size_t count;
  int *local_fds;
  size_t local_count = 0;

  *owned_fds = NULL;
  *owned_fd_count = 0;

  if (fds == NULL) {
    return 0;
  }
  if (xpc_get_type(fds) != XPC_TYPE_ARRAY) {
    return EINVAL;
  }

  count = xpc_array_get_count(fds);
  if ((count % 2) != 0) {
    return EINVAL;
  }

  if (!checked_calloc((void **) &local_fds, count / 2, sizeof(int))) {
    return ENOMEM;
  }

  for (size_t i = 0; i != count; i += 2) {
    xpc_object_t fd_object = xpc_array_get_value(fds, i);
    xpc_object_t dest_object = xpc_array_get_value(fds, i + 1);
    int local_fd;
    int dest_fd;
    int error;

    if (xpc_get_type(dest_object) != XPC_TYPE_INT64) {
      free(local_fds);
      return EINVAL;
    }

    local_fd = xpc_fd_dup(fd_object);
    if (local_fd == -1) {
      error = errno;
      free(local_fds);
      return error;
    }

    dest_fd = (int) xpc_int64_get_value(dest_object);
    error = posix_spawn_file_actions_adddup2(actions, local_fd, dest_fd);
    if (error != 0) {
      close(local_fd);
      free(local_fds);
      return error;
    }

    local_fds[local_count++] = local_fd;
  }

  *owned_fds = local_fds;
  *owned_fd_count = local_count;
  return 0;
}

static int
apply_identity(const struct kproc_spawn_request *request)
{
  if (!request->has_identity) {
    return 0;
  }

  if (setgid(request->gid) == -1) {
    return errno;
  }
  if (request->username != NULL && initgroups(request->username, request->gid) == -1) {
    return errno;
  }
  if (setuid(request->uid) == -1) {
    return errno;
  }

  return 0;
}

int
kproc_spawn_request_execute(const struct kproc_spawn_request *request, xpc_object_t ports, xpc_object_t fds)
{
  posix_spawnattr_t attr;
  posix_spawn_file_actions_t actions;
  short flags = POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT;
  int error;
  int *owned_fds = NULL;
  size_t owned_fd_count = 0;
  pid_t pid = 0;
  struct kproc_prepared_program prepared_program;
  const char *program_path = request->program;
  char **spawn_argv = NULL;

  error = posix_spawnattr_init(&attr);
  if (error != 0) {
    return error;
  }
  error = posix_spawn_file_actions_init(&actions);
  if (error != 0) {
    posix_spawnattr_destroy(&attr);
    return error;
  }

  error = posix_spawnattr_setflags(&attr, flags);
  if (error == 0 && request->qos_class != 0) {
    error = posix_spawnattr_set_qos_class_np(&attr, (qos_class_t) request->qos_class);
  }
  if (error == 0) {
    error = apply_binprefs(request, &attr);
  }
  if (error == 0) {
    error = apply_special_ports(request, &attr, ports);
  }
  if (error == 0) {
    error = add_stdio_action(&actions, STDIN_FILENO, request->cwd, request->stdin_path);
  }
  if (error == 0) {
    error = add_stdio_action(&actions, STDOUT_FILENO, request->cwd, request->stdout_path);
  }
  if (error == 0) {
    error = add_stdio_action(&actions, STDERR_FILENO, request->cwd, request->stderr_path);
  }
  if (error == 0) {
    error = apply_fd_actions(&actions, fds, &owned_fds, &owned_fd_count);
  }
  if (error == 0 && request->set_umask) {
    (void) umask(request->umask_value);
  }
  if (error == 0) {
    error = apply_rlimits(request);
  }
  if (error == 0 && request->cwd != NULL) {
    if (chdir(request->cwd) == -1) {
      error = errno;
    }
  }
  if (error == 0) {
    error = kproc_prepare_program(request->program, request->use_path_search, request->envp, &prepared_program);
    if (error == 0) {
      program_path = prepared_program.path;
      if (!checked_calloc((void **) &spawn_argv, request->argc + 1, sizeof(char *))) {
        error = ENOMEM;
      } else {
        for (size_t i = 0; i != request->argc; i++) {
          spawn_argv[i] = (char *) request->argv[i];
        }
        if (request->argc != 0) {
          spawn_argv[0] = (char *) program_path;
        }
      }
    }
  }
  if (error == 0) {
    error = apply_identity(request);
  }
  if (error == 0) {
    error = posix_spawn(&pid, program_path, &actions, &attr, spawn_argv, (char *const *) request->envp);
  }

  free(spawn_argv);
  for (size_t i = 0; i != owned_fd_count; i++) {
    close(owned_fds[i]);
  }
  free(owned_fds);

  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attr);
  return error;
}
