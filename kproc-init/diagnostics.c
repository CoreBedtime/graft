#include "diagnostics.h"

#include <stdio.h>
#include <stdlib.h>

static void (*g_reporter)(int code, int subcode, unsigned line, const char *message);

void
kproc_set_reporter(void (*reporter)(int code, int subcode, unsigned line, const char *message))
{
  g_reporter = reporter;
}

void
kproc_report_launchd_failure(int code, int subcode, unsigned line, const char *message)
{
  if (g_reporter != NULL) {
    g_reporter(code, subcode, line, message);
  }
}

void
kproc_failv(int code, int subcode, unsigned line, const char *format, va_list ap)
{
  char *message = NULL;
  if (vasprintf(&message, format, ap) == -1) {
    message = NULL;
  }

  if (message != NULL) {
    kproc_report_launchd_failure(code, subcode, line, message);
    fprintf(stderr, "kproc-init: %s\n", message);
    free(message);
  } else {
    kproc_report_launchd_failure(code, subcode, line, "fatal error");
    fprintf(stderr, "kproc-init: fatal error\n");
  }

  exit(78);
}

void
kproc_fail(int code, int subcode, unsigned line, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  kproc_failv(code, subcode, line, format, ap);
}
