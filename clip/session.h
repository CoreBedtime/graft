#ifndef SESSION_H
#define SESSION_H

#include "frida-core.h"

typedef struct _SessionManager SessionManager;

SessionManager *session_manager_new(FridaDevice *device, const gchar *bundle);
void session_manager_free(SessionManager *manager);

// Check if a PID is currently managed
gboolean session_manager_has_pid(SessionManager *manager, pid_t pid);

// Attempt to attach and load script to a specific PID
gboolean session_manager_attach(SessionManager *manager, pid_t pid);

#endif // SESSION_H
