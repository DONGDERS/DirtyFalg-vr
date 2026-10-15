/* Persistent kernel-log follower.
 *
 * Spawned by the dfroot UMH shell at ko-init time (root, SELinux
 * permissive). Reads /dev/kmsg message-by-message and appends each one to
 * the public Download dir with a per-message fsync: whatever the kernel
 * prints reaches the disk within milliseconds and survives even a watchdog
 * hard reset, which takes the whole page cache (and pstore) with it.
 *
 * pstore is structurally absent on this device, so this daemon is the only
 * witness of the lead-up to a wedge/panic. The final panic() print itself
 * lands after userspace is frozen and is intentionally out of scope - the
 * last fsynced line marks the entry point of the hang.
 *
 * Mutex /dev/dfkmsg (tmpfs, dies with the boot): one follower per boot,
 * across any number of runs. */
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define KMSG    "/dev/kmsg"
#define MUTEX   "/dev/dfkmsg"
#define OUT_DIR "/data/media/0/Download/DirtyFrag"
#define OUT     OUT_DIR "/dmesg_live.txt"

int main(void)
{
    int mfd = open(MUTEX, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (mfd < 0) return 0;          /* a follower is already running */
    write(mfd, "1", 1);
    close(mfd);

    mkdir(OUT_DIR, 0755);           /* UMH shell normally did this already */

    int k = open(KMSG, O_RDONLY | O_NONBLOCK);
    if (k < 0) return 0;
    /* Start at the END of the ring: only what happens from now on. */
    lseek(k, 0, SEEK_END);

    int o = open(OUT, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (o < 0) return 0;

    char buf[2048];
    struct pollfd p = { .fd = k, .events = POLLIN };
    for (;;) {
        int r = poll(&p, 1, 50);    /* 50ms idle sleep, ms-level wakeups */
        if (r <= 0) continue;
        for (;;) {
            ssize_t n = read(k, buf, sizeof(buf));
            if (n > 0) {
                if (buf[n - 1] != '\n') { buf[n] = '\n'; n++; }
                ssize_t w = write(o, buf, n);
                (void)w;
                fsync(o);           /* per message: survives hard reset */
                continue;
            }
            break;                  /* EAGAIN - drained */
        }
    }
}
