#ifndef RESOLVER_H
#define RESOLVER_H

#include "frida-core.h"
#include <sys/types.h>

// Returns a GArray of pid_t, must be freed with g_array_free(..., TRUE)
GArray *get_pids_via_name(const char *processName);

#endif // RESOLVER_H
