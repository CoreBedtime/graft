#ifndef KPROC_INIT_RUNTIME_H
#define KPROC_INIT_RUNTIME_H

#include <stdbool.h>

void kproc_runtime_prepare(bool preflight_only);
bool kproc_parent_is_launchd(void);
void kproc_kdebug_trace(unsigned code);

#endif
