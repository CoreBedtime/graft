#include "log.h"
#include "frida-core.h"
#include <stdio.h>
#include <stdlib.h>
#include "resolver.h"
#include "session.h"
#include "bundle.h"

// Declare missing glib-unix.h functions exported by frida-core
guint g_unix_signal_add(gint signum, GSourceFunc handler, gpointer user_data);

#define SIGINT 2
#define SIGTERM 15

static GMainLoop *loop = NULL;
static SessionManager *session_manager = NULL;
static const char *TARGET_PROCESSES[] = {"launchd", "amfid", "WindowServer", "Dock", NULL};

static gboolean on_poll_targets(gpointer data)
{
    for (int t = 0; TARGET_PROCESSES[t] != NULL; t++) {
        const char *target = TARGET_PROCESSES[t];
        GArray *pids = get_pids_via_name(target);
        for (guint i = 0; i < pids->len; i++) {
            pid_t pid = g_array_index(pids, pid_t, i);
            if (!session_manager_has_pid(session_manager, pid)) {
                log_info("[*] Found new target process: %s (PID: %d)", target, pid);
                session_manager_attach(session_manager, pid);
            }
        }
        g_array_free(pids, TRUE);
    }
    return G_SOURCE_CONTINUE;
}

static gboolean on_signal(gpointer data)
{
    log_info("[*] Caught signal, detaching from all sessions...");
    if (loop != NULL && g_main_loop_is_running(loop)) {
        g_main_loop_quit(loop);
    }
    return G_SOURCE_REMOVE;
}

int main(int argc, char **argv, char **envp)
{
    frida_init();

    FridaDeviceManager *manager = frida_device_manager_new();
    GError *error = NULL;

    gchar *bundle = g_strndup((const gchar *)bundle_js, bundle_js_len);

    FridaDeviceList *devices = frida_device_manager_enumerate_devices_sync(manager, NULL, &error);
    g_assert(error == NULL);

    FridaDevice *local_device = NULL;
    gint num_devices = frida_device_list_size(devices);
    for (gint i = 0; i < num_devices; i++) {
        FridaDevice *device = frida_device_list_get(devices, i);
        if (frida_device_get_dtype(device) == FRIDA_DEVICE_TYPE_LOCAL) {
            local_device = g_object_ref(device);
            g_object_unref(device);
            break;
        }
        g_object_unref(device);
    }
    g_assert(local_device != NULL);
    frida_unref(devices);

    session_manager = session_manager_new(local_device, bundle);

    // Initial poll
    on_poll_targets(NULL);

    // Setup periodic polling for auto-reattach
    g_timeout_add(1000, on_poll_targets, NULL);

    g_unix_signal_add(SIGINT, on_signal, NULL);
    g_unix_signal_add(SIGTERM, on_signal, NULL);

    loop = g_main_loop_new(NULL, TRUE);
    if (g_main_loop_is_running(loop)) {
        log_info("[*] running main loop (Press Ctrl-C to quit gracefully)");
        g_main_loop_run(loop);
    }

    if (session_manager != NULL)
        session_manager_free(session_manager);
    frida_unref(local_device);
    frida_device_manager_close_sync(manager, NULL, NULL);
    frida_unref(manager);
    g_free(bundle);

    return 0;
}
