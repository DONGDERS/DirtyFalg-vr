package df.root;

import android.content.pm.ApplicationInfo;

import java.io.File;
import java.io.RandomAccessFile;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Locates the ksud CLI inside an SU manager's native library dir.
 *
 * <p>Upstream managers ship it as {@code libksud.so}. Newer SukiSU builds rename
 * the library at packaging time (e.g. {@code liblaapkjdiji.so}) so a fixed
 * filename check no longer finds them, and a "contains ksud" string test is not
 * enough - small helper stubs carry that string too. Two cheap discriminators
 * identify the CLI instead: it is a real PIE executable, so its ELF carries a
 * PT_INTERP program header (a plain .so does not), and its command table
 * contains the {@code late-load} subcommand.</p>
 *
 * <p>The scan is deliberately IO-frugal. A phone with a few hundred apps holds
 * several gigabytes of native libraries, and reading them all froze the UI for
 * minutes; the header check rejects ordinary libraries after a few hundred
 * bytes, and the string search is capped because the command table sits in the
 * leading part of the file (189 KB in SukiSU v3, 303 KB in ReSukiSU).</p>
 */
final class SuManagerBinary {
    /** Smallest plausible size for the ksud CLI; skips stubs without reading. */
    private static final long MIN_SIZE = 300_000L;
    /** Upper bound for the string search: the command table lives up front. */
    private static final long MAX_SCAN = 8L * 1024 * 1024;
    private static final byte[] NEEDLE = "late-load".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] ELF = {0x7f, 'E', 'L', 'F'};
    private static final int CHUNK = 64 * 1024;
    private static final int PT_INTERP = 3;

    /** nativeLibraryDir -> the binary found there. */
    private static final Map<String, File> CACHE = new HashMap<>();
    /** nativeLibraryDir -> dir mtime when it last proved to hold no ksud. */
    private static final Map<String, Long> MISSES = new HashMap<>();

    private SuManagerBinary() {}

    /** @return the ksud binary for this app, or null when it has none. */
    static synchronized File find(ApplicationInfo app) {
        if (app.nativeLibraryDir == null) return null;
        String dir = app.nativeLibraryDir;
        File cached = CACHE.get(dir);
        if (cached != null && cached.isFile()) return cached;

        // A lib dir only changes when the app is installed, updated or removed,
        // so its mtime is enough to trust an earlier "no ksud here".
        File dirFile = new File(dir);
        long stamp = dirFile.lastModified();
        Long missStamp = MISSES.get(dir);
        if (missStamp != null && missStamp == stamp) return null;

        File found = search(dirFile);
        if (found != null) {
            CACHE.put(dir, found);
            MISSES.remove(dir);
        } else {
            CACHE.remove(dir);
            MISSES.put(dir, stamp);
        }
        return found;
    }

    private static File search(File dir) {
        // Conventional name first: every manager except the obfuscated builds
        // ships this, and returning it without reading the file keeps the
        // per-app scan cheap.
        File conventional = new File(dir, "libksud.so");
        if (conventional.isFile()) return conventional;

        File[] files = dir.listFiles((parent, name) -> name.endsWith(".so"));
        if (files == null) return null;
        for (File file : files) {
            if (isKsudCli(file)) return file;
        }
        return null;
    }

    private static boolean isKsudCli(File file) {
        if (!file.isFile() || !file.canRead()) return false;
        if (file.length() < MIN_SIZE) return false;
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            if (!isPieExecutable(raf)) return false;
            long limit = Math.min(file.length(), MAX_SCAN);
            raf.seek(0);
            byte[] buf = new byte[CHUNK + NEEDLE.length - 1];
            int carry = 0;
            long read = 0;
            while (read < limit) {
                int want = (int) Math.min(CHUNK, limit - read);
                int n = raf.read(buf, carry, want);
                if (n <= 0) return false;
                read += n;
                int total = carry + n;
                if (indexOf(buf, total, NEEDLE) >= 0) return true;
                carry = NEEDLE.length - 1;
                System.arraycopy(buf, total - carry, buf, 0, carry);
            }
            return false;
        } catch (IOException | SecurityException e) {
            return false;
        }
    }

    /**
     * True when the file is an ELF executable rather than a shared library,
     * i.e. its program header table has a PT_INTERP entry. Costs one short
     * header read plus the program headers, never the body of the file.
     */
    private static boolean isPieExecutable(RandomAccessFile raf) throws IOException {
        byte[] head = new byte[64];
        raf.seek(0);
        int got = raf.read(head);
        if (got < 52) return false;
        for (int i = 0; i < ELF.length; i++) {
            if (head[i] != ELF[i]) return false;
        }
        boolean is64 = head[4] == 2;
        long phoff = is64 ? readLong(head, 32) : readInt(head, 28);
        int phentsize = is64 ? readShort(head, 54) : readShort(head, 42);
        int phnum = is64 ? readShort(head, 56) : readShort(head, 44);
        if (phoff <= 0 || phentsize < 4 || phnum <= 0) return false;
        // Guard against absurd tables in malformed or hostile files.
        if (phentsize > 256 || phnum > 128 || phoff > raf.length()) return false;

        byte[] ph = new byte[phentsize * phnum];
        raf.seek(phoff);
        int read = 0;
        while (read < ph.length) {
            int n = raf.read(ph, read, ph.length - read);
            if (n <= 0) break;
            read += n;
        }
        for (int i = 0; i < phnum; i++) {
            int off = i * phentsize;
            if (off + 4 > read) break;
            if (readInt(ph, off) == PT_INTERP) return true;
        }
        return false;
    }

    private static int readInt(byte[] b, int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8
                | (b[off + 2] & 0xff) << 16 | (b[off + 3] & 0xff) << 24;
    }

    private static long readLong(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xffL);
        return v;
    }

    private static int readShort(byte[] b, int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8;
    }

    private static int indexOf(byte[] haystack, int length, byte[] needle) {
        outer:
        for (int i = 0; i <= length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}