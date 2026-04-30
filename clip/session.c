#include "log.h"
#include "session.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    pid_t pid;
    FridaSession *session;
    FridaScript *script;
    gboolean teardown_initiated;
    gboolean dispose_acked;
} TargetSession;

struct _SessionManager {
    FridaDevice *device;
    gchar *bundle;
    GHashTable *sessions; // pid_t -> TargetSession*
};

static void on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data)
{
    TargetSession *ts = (TargetSession *)user_data;

    if (strstr(message, "\"disposed\"")) {
        ts->dispose_acked = TRUE;
        return;
    }

    log_info("[%d] %s", ts->pid, message);
}

static void free_target_session(TargetSession *ts)
{
    if (ts->script) {
        frida_unref(ts->script);
        ts->script = NULL;
    }
    if (ts->session) {
        frida_unref(ts->session);
        ts->session = NULL;
    }
    g_free(ts);
}

static void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data)
{
    TargetSession *ts = (TargetSession *)user_data;
    log_info("[%d] Session detached (reason=%d)", ts->pid, reason);
    // ts is always freed here — it is the only place we free it.
    free_target_session(ts);
}

SessionManager *session_manager_new(FridaDevice *device, const gchar *bundle)
{
    SessionManager *manager = g_new0(SessionManager, 1);
    manager->device = g_object_ref(device);
    manager->bundle = g_strdup(bundle);
    // No destroy notifier — on_detached owns all ts lifetime.
    manager->sessions = g_hash_table_new(g_direct_hash, g_direct_equal);
    return manager;
}

void session_manager_free(SessionManager *manager)
{
    GHashTableIter iter;
    gpointer key, value;

    // Post dispose to every script and wait for the ack before detaching.
    g_hash_table_iter_init(&iter, manager->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        TargetSession *ts = (TargetSession *)value;
        ts->teardown_initiated = TRUE;
        if (ts->script) {
            frida_script_post(ts->script, "{\"type\":\"dispose\"}", NULL);

            // Pump the frida main context until the JS dispose ack arrives
            // or we time out (500 ms).
            GMainContext *ctx = frida_get_main_context();
            gint64 deadline = g_get_monotonic_time() + 500 * G_TIME_SPAN_MILLISECOND;
            while (!ts->dispose_acked && g_get_monotonic_time() < deadline)
                g_main_context_iteration(ctx, FALSE);

            if (ts->dispose_acked)
                log_info("[%d] JS dispose ack received", ts->pid);
            else
                log_warn("[%d] JS dispose timed out", ts->pid);
        }
        frida_session_detach(ts->session, NULL, NULL, NULL);
    }

    g_hash_table_destroy(manager->sessions);
    g_free(manager->bundle);
    frida_unref(manager->device);
    g_free(manager);
}

gboolean session_manager_has_pid(SessionManager *manager, pid_t pid)
{
    return g_hash_table_contains(manager->sessions, GINT_TO_POINTER(pid));
}

gboolean session_manager_attach(SessionManager *manager, pid_t pid)
{
    if (session_manager_has_pid(manager, pid)) return TRUE;

    GError *error = NULL;
    FridaSession *session = frida_device_attach_sync(manager->device, pid, (FridaSessionOptions *)FRIDA_REALM_NATIVE, NULL, &error);
    if (error != NULL) {
        log_error("[%d] Failed to attach: %s", pid, error->message);
        g_error_free(error);
        if (session) frida_unref(session);
        return FALSE;
    }

    if (frida_session_is_detached(session)) {
        log_error("[%d] Session detached prematurely", pid);
        frida_unref(session);
        return FALSE;
    }

    TargetSession *ts = g_new0(TargetSession, 1);
    ts->pid = pid;
    ts->session = session;
    ts->teardown_initiated = FALSE;

    // on_detached is the sole owner of ts lifetime from here on.
    g_signal_connect(session, "detached", G_CALLBACK(on_detached), ts);

    FridaScriptOptions *options = frida_script_options_new();
    frida_script_options_set_name(options, "/clip/loader.entry.js");
    frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS);

    FridaScript *script = frida_session_create_script_sync(session, manager->bundle, options, NULL, &error);
    g_clear_object(&options);

    if (error != NULL) {
        log_error("[%d] Failed to create script: %s", pid, error->message);
        g_error_free(error);
        // Detach will trigger on_detached which frees ts.
        frida_session_detach(session, NULL, NULL, NULL);
        return FALSE;
    }

    ts->script = script;
    g_signal_connect(script, "message", G_CALLBACK(on_message), ts);

    frida_script_load_sync(script, NULL, &error);
    if (error != NULL) {
        log_error("[%d] Failed to load script: %s", pid, error->message);
        g_error_free(error);
        frida_session_detach(session, NULL, NULL, NULL);
        return FALSE;
    }

    g_hash_table_insert(manager->sessions, GINT_TO_POINTER(pid), ts);
    log_info("[%d] Attached and script loaded successfully", pid);

    return TRUE;
}
