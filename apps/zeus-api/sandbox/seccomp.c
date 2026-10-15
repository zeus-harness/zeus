/* Export a native-architecture filter; bubblewrap installs it after setup. */
#include <seccomp.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return 1;
    const char *deny[] = {"mount", "umount2", "pivot_root", "chroot", "setns", "unshare",
        "ptrace", "process_vm_readv", "process_vm_writev", "bpf", "perf_event_open",
        "keyctl", "add_key", "request_key", "init_module", "finit_module", "delete_module",
        "kexec_load", "kexec_file_load", "reboot", "swapon", "swapoff", "userfaultfd",
        "open_by_handle_at", "name_to_handle_at", "fsopen", "fsmount", "move_mount",
        "fsconfig", "open_tree", "mount_setattr", "io_uring_setup"};
    for (unsigned i=0; i<sizeof(deny)/sizeof(deny[0]); i++) {
        int nr = seccomp_syscall_resolve_name(deny[i]);
        if (nr != __NR_SCMP_ERROR && seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0)) return 2;
    }
    int clone3 = seccomp_syscall_resolve_name("clone3");
    if (clone3 != __NR_SCMP_ERROR && seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), clone3, 0)) return 3;
    /* Allow threads, but prohibit clone() creating additional namespaces. */
    const unsigned long flags[] = {0x80,0x20000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000};
    int clone = seccomp_syscall_resolve_name("clone");
    for (unsigned i=0; i<sizeof(flags)/sizeof(flags[0]); i++)
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), clone, 1,
            SCMP_A0(SCMP_CMP_MASKED_EQ, flags[i], flags[i]))) return 4;
    int result = seccomp_export_bpf(ctx, STDOUT_FILENO);
    seccomp_release(ctx);
    return result != 0;
}
