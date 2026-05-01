#ifndef KPROC_INIT_DIAGNOSTICS_H
#define KPROC_INIT_DIAGNOSTICS_H

#include <stdarg.h>

#include <xpc/xpc.h>

void kproc_set_reporter(void (*reporter)(int code, int subcode, unsigned line, const char *message));
void kproc_fail(int code, int subcode, unsigned line, const char *format, ...)
    __attribute__((noreturn, format(printf, 4, 5)));
void kproc_failv(int code, int subcode, unsigned line, const char *format, va_list ap)
    __attribute__((noreturn, format(printf, 4, 0)));
void kproc_report_launchd_failure(int code, int subcode, unsigned line, const char *message);

#endif
