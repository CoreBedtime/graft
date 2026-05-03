#include "log.h"
#include "session.h"
#include "process.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/mach.h>
#include <sys/signal.h>
#include <unistd.h>

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

static const gchar *skip_json_ws(const gchar *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static gchar *decode_json_string(const gchar *p)
{
    GString *out;

    if (*p != '"') return NULL;
    p++;

    out = g_string_new(NULL);
    while (*p && *p != '"') {
        if (*p != '\\') {
            g_string_append_c(out, *p++);
            continue;
        }

        p++;
        switch (*p) {
            case '"': g_string_append_c(out, '"'); p++; break;
            case '\\': g_string_append_c(out, '\\'); p++; break;
            case '/': g_string_append_c(out, '/'); p++; break;
            case 'b': g_string_append_c(out, '\b'); p++; break;
            case 'f': g_string_append_c(out, '\f'); p++; break;
            case 'n': g_string_append_c(out, '\n'); p++; break;
            case 'r': g_string_append_c(out, '\r'); p++; break;
            case 't': g_string_append_c(out, '\t'); p++; break;
            case 'u': {
                gunichar ch = 0;
                gchar utf8[6];
                gint len;

                p++;
                for (int i = 0; i < 4; i++) {
                    gint digit = g_ascii_xdigit_value(p[i]);
                    if (digit < 0) {
                        g_string_free(out, TRUE);
                        return NULL;
                    }
                    ch = (ch << 4) | digit;
                }
                p += 4;

                len = g_unichar_to_utf8(ch, utf8);
                g_string_append_len(out, utf8, len);
                break;
            }
            case '\0':
                g_string_free(out, TRUE);
                return NULL;
            default:
                g_string_append_c(out, *p++);
                break;
        }
    }

    if (*p != '"') {
        g_string_free(out, TRUE);
        return NULL;
    }

    return g_string_free(out, FALSE);
}

static gchar *json_string_property(const gchar *json, const gchar *name)
{
    gchar *pattern = g_strdup_printf("\"%s\"", name);
    const gchar *p = json;

    while ((p = strstr(p, pattern)) != NULL) {
        const gchar *value = skip_json_ws(p + strlen(pattern));
        if (*value == ':') {
            g_free(pattern);
            return decode_json_string(skip_json_ws(value + 1));
        }
        p += strlen(pattern);
    }

    g_free(pattern);
    return NULL;
}


static void log_script_console_message(pid_t pid, const gchar *level, const gchar *payload)
{
    const gchar *console_level = level != NULL ? level : "log";

    if (g_strcmp0(console_level, "error") == 0) {
        log_error("[%d] console.%s: %s", pid, console_level, payload);
    } else if (g_strcmp0(console_level, "warning") == 0 || g_strcmp0(console_level, "warn") == 0) {
        log_warn("[%d] console.%s: %s", pid, console_level, payload);
    } else {
        log_info("[%d] console.%s: %s", pid, console_level, payload);
    }
}

static void on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data)
{
    TargetSession *ts = (TargetSession *)user_data;
    gchar *type;

    (void)script;
    (void)data;

    if (strstr(message, "\"disposed\"")) {
        ts->dispose_acked = TRUE;
        return;
    }

    type = json_string_property(message, "type");
    if (g_strcmp0(type, "log") == 0) {
        gchar *level = json_string_property(message, "level");
        gchar *payload = json_string_property(message, "payload");

        if (payload != NULL) {
            log_script_console_message(ts->pid, level, payload);
        } else {
            log_info("[%d] console.%s", ts->pid, level != NULL ? level : "log");
        }

        g_free(payload);
        g_free(level);
    } else if (g_strcmp0(type, "error") == 0) {
        gchar *description = json_string_property(message, "description");
        gchar *stack = json_string_property(message, "stack");

        log_error("[%d] script error: %s", ts->pid, description != NULL ? description : message);
        if (stack != NULL && *stack != '\0') log_error("[%d] %s", ts->pid, stack);

        g_free(stack);
        g_free(description);
    } else if (g_strcmp0(type, "send") == 0) {
        JsonParser *parser = json_parser_new();
        if (json_parser_load_from_data(parser, message, -1, NULL)) {
            JsonNode *root = json_parser_get_root(parser);
            if (JSON_NODE_HOLDS_OBJECT(root)) {
                JsonObject *obj = json_node_get_object(root);
                if (json_object_has_member(obj, "payload")) {
                    JsonNode *payload_node = json_object_get_member(obj, "payload");
                    if (JSON_NODE_HOLDS_OBJECT(payload_node)) {
                        JsonObject *payload = json_node_get_object(payload_node);
                        if (g_strcmp0(json_object_get_string_member_with_default(payload, "type", ""), "launch_request") == 0) {
                            const gchar *path = json_object_get_string_member_with_default(payload, "path", NULL);
                            getready_process(path);
                        }
                    } else {
                        log_info("[%d] %s", ts->pid, message);
                    }
                } else {
                    log_info("[%d] %s", ts->pid, message);
                }
            } else {
                log_info("[%d] %s", ts->pid, message);
            }
        } else {
            log_info("[%d] %s", ts->pid, message);
        }
        g_object_unref(parser);
    } else {
        log_info("[%d] %s", ts->pid, message);
    }

    g_free(type);
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
