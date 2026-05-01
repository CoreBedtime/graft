#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xpc/xpc.h>

#include "diagnostics.h"
#include "launchd.h"
#include "runtime.h"
#include "spawn_blob.h"
#include "spawn_request.h"

enum {
  KDEBUG_XPCPROXY_START = 570425372,
  KDEBUG_XPCPROXY_SPAWN = 570425376,
  KDEBUG_XPCPROXY_DONE = 570425380,
};

static bool
allow_direct_execution(void)
{
  const char *value = getenv("KPROC_INIT_ALLOW_DIRECT");
  return value != NULL && strcmp(value, "0") != 0;
}

static xpc_object_t
required_dictionary_value(xpc_object_t dictionary, const char *key)
{
  xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
  return value;
}

int
main(int argc, char **argv)
{
  xpc_object_t reply;
  const void *blob_data;
  size_t blob_length = 0;
  struct kproc_spawn_blob blob;
  struct kproc_spawn_request request;
  xpc_object_t ports;
  xpc_object_t fds;
  int error;

  (void) argc;

  if (setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1) == -1) {
    kproc_fail(errno, 0, __LINE__, "setenv(PATH) failed: %s", strerror(errno));
  }

  kproc_runtime_prepare(false);
  if (!kproc_parent_is_launchd() && !allow_direct_execution()) {
    fprintf(stdout, "%s cannot be run directly.\n", argv[0]);
    return 78;
  }

  if (!kproc_launchd_bootstrap()) {
    kproc_fail(ENOSYS, 0, __LINE__, "launchd service routine is unavailable");
  }

  kproc_kdebug_trace(KDEBUG_XPCPROXY_START);
  reply = kproc_launchd_copy_self_request();
  if (reply == NULL) {
    kproc_fail(EINVAL, 0, __LINE__, "launchd did not provide a spawn request");
  }
  if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
    kproc_fail(EINVAL, 0, __LINE__, "launchd returned an XPC error");
  }

  blob_data = xpc_dictionary_get_data(reply, "blob", &blob_length);
  if (!kproc_spawn_blob_init(&blob, blob_data, blob_length)) {
    kproc_fail(EINVAL, 0, __LINE__, "missing or invalid spawn attribute blob");
  }

  if (!kproc_spawn_request_decode(&blob, &request)) {
    kproc_fail(EINVAL, 0, __LINE__, "unable to decode spawn attribute blob");
  }

  ports = required_dictionary_value(reply, "ports");
  fds = required_dictionary_value(reply, "fds");
  if (ports != NULL && xpc_get_type(ports) != XPC_TYPE_ARRAY) {
    kproc_fail(EINVAL, 0, __LINE__, "special ports entry is not an array");
  }
  if (fds != NULL && xpc_get_type(fds) != XPC_TYPE_ARRAY) {
    kproc_fail(EINVAL, 0, __LINE__, "file descriptors entry is not an array");
  }

  kproc_kdebug_trace(KDEBUG_XPCPROXY_SPAWN);
  error = kproc_spawn_request_execute(&request, ports, fds);
  if (error != 0) {
    kproc_fail(error, 0, __LINE__, "posix_spawn(%s) failed: %s", request.program, strerror(error));
  }

  kproc_kdebug_trace(KDEBUG_XPCPROXY_DONE);
  kproc_spawn_request_destroy(&request);
  xpc_release(reply);
  return 0;
}
