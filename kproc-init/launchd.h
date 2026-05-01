#ifndef KPROC_INIT_LAUNCHD_H
#define KPROC_INIT_LAUNCHD_H

#include <stdbool.h>

#include <xpc/xpc.h>

bool kproc_launchd_bootstrap(void);
xpc_object_t kproc_launchd_copy_self_request(void);
void kproc_launchd_report_failure(int code, int subcode, unsigned line, const char *message);

#endif
