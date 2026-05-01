#include "launchd.h"

#include <dlfcn.h>
#include <stdint.h>

#include "diagnostics.h"

typedef int (*xpc_service_routine_fn)(int routine, xpc_object_t request, xpc_object_t *reply);

enum {
  KPROC_LAUNCHD_ROUTINE_SPAWN_SELF = 700,
  KPROC_LAUNCHD_ROUTINE_SPAWN_FAILURE = 701,
};

static xpc_service_routine_fn g_service_routine;

static xpc_service_routine_fn
resolve_service_routine(void)
{
  if (g_service_routine != NULL) {
    return g_service_routine;
  }

  g_service_routine = (xpc_service_routine_fn) dlsym(RTLD_DEFAULT, "_xpc_service_routine");
  if (g_service_routine == NULL) {
    g_service_routine = (xpc_service_routine_fn) dlsym(RTLD_DEFAULT, "__xpc_service_routine");
  }

  return g_service_routine;
}

bool
kproc_launchd_bootstrap(void)
{
  if (resolve_service_routine() == NULL) {
    return false;
  }

  kproc_set_reporter(kproc_launchd_report_failure);
  return true;
}

xpc_object_t
kproc_launchd_copy_self_request(void)
{
  xpc_service_routine_fn routine = resolve_service_routine();
  if (routine == NULL) {
    return NULL;
  }

  xpc_object_t request = xpc_dictionary_create_empty();
  xpc_dictionary_set_bool(request, "self", true);

  xpc_object_t reply = NULL;
  int error = routine(KPROC_LAUNCHD_ROUTINE_SPAWN_SELF, request, &reply);
  xpc_release(request);

  if (error != 0) {
    if (reply != NULL) {
      xpc_release(reply);
    }
    return NULL;
  }

  return reply;
}

void
kproc_launchd_report_failure(int code, int subcode, unsigned line, const char *message)
{
  xpc_service_routine_fn routine = resolve_service_routine();
  if (routine == NULL) {
    return;
  }

  xpc_object_t event = xpc_dictionary_create_empty();
  xpc_dictionary_set_bool(event, "self", true);
  xpc_dictionary_set_int64(event, "code", code);
  xpc_dictionary_set_int64(event, "subcode", subcode);
  xpc_dictionary_set_uint64(event, "line", line);
  xpc_dictionary_set_bool(event, "setup-event", false);
  if (message != NULL) {
    xpc_dictionary_set_string(event, "string", message);
  }

  xpc_object_t reply = NULL;
  (void) routine(KPROC_LAUNCHD_ROUTINE_SPAWN_FAILURE, event, &reply);
  if (reply != NULL) {
    xpc_release(reply);
  }
  xpc_release(event);
}
