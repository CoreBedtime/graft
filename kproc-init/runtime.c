#include "runtime.h"

#include <dlfcn.h>
#include <notify.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef uint64_t (*kdebug_trace_fn)(uint32_t code, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);
typedef uint32_t (*notify_set_options_fn)(uint32_t options);
typedef void (*si_search_module_set_flags_fn)(const char *module, uint64_t flags);
typedef void (*os_trace_set_mode_fn)(uint32_t mode);

void
kproc_runtime_prepare(bool preflight_only)
{
  notify_set_options_fn notify_options;
  si_search_module_set_flags_fn set_search_flags;
  os_trace_set_mode_fn set_trace_mode;

  if (preflight_only) {
    (void) dlopen("/usr/lib/system/libsystem_notify.dylib", RTLD_LAZY);
    (void) dlopen("/usr/lib/system/libsystem_info.dylib", RTLD_LAZY);
    (void) dlopen("/usr/lib/system/libsystem_trace.dylib", RTLD_LAZY);
  }

  notify_options = (notify_set_options_fn) dlsym(RTLD_DEFAULT, "notify_set_options");
  if (notify_options != NULL) {
    (void) notify_options(0);
  }

  set_search_flags = (si_search_module_set_flags_fn) dlsym(RTLD_DEFAULT, "si_search_module_set_flags");
  if (set_search_flags != NULL) {
    set_search_flags("user", 0);
    set_search_flags("group", 0);
  }

  set_trace_mode = (os_trace_set_mode_fn) dlsym(RTLD_DEFAULT, "_os_trace_set_mode");
  if (set_trace_mode != NULL) {
    set_trace_mode(0x100);
  }
}

bool
kproc_parent_is_launchd(void)
{
  return getppid() == 1;
}

void
kproc_kdebug_trace(unsigned code)
{
  kdebug_trace_fn trace = (kdebug_trace_fn) dlsym(RTLD_DEFAULT, "kdebug_trace");
  if (trace != NULL) {
    (void) trace(code, (uintptr_t) getpid(), 0, 0, 0);
  }
}
