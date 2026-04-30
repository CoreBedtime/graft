#include "log.h"
#include "resolver.h"
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

GArray *get_pids_via_name(const char *processName)
{
    GArray *pids = g_array_new(FALSE, FALSE, sizeof(pid_t));
    size_t size = 0;

    if (sysctlbyname("kern.proc.all", NULL, &size, NULL, 0) == -1) {
        perror("sysctlbyname");
        return pids;
    }

    struct kinfo_proc* procs = (struct kinfo_proc*)malloc(size);

    if (sysctlbyname("kern.proc.all", procs, &size, NULL, 0) == -1) {
        perror("sysctlbyname");
        free(procs);
        return pids;
    }

    int count = size / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        if (procs[i].kp_proc.p_comm[0] == '\0') {
            continue;
        }

        if (strcmp(procs[i].kp_proc.p_comm, processName) == 0) {
            pid_t pid = procs[i].kp_proc.p_pid;
            g_array_append_val(pids, pid);
        }
    }

    free(procs);
    return pids;
}
