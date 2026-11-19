package df.root;

import android.content.pm.ApplicationInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Locates the ksud CLI inside an SU manager's native library dir.
 *
 * <p>Upstream managers ship it as {@code libksud.so}. Newer SukiSU builds rename
 * the library at packaging time (e.g. {@code liblaapkjdiji.so}) so a fixed
 * filename check no longer finds them, and a "contains ksud" string test is not
 * enough - small helper stubs carry that string too. The discriminator used here
 * is the {@code late-load} subcommand, which only the ksud CLI's command table
 * carries, plus a real ELF header and the executable bit.</p>
 */
final class SuManagerBinary {
    /** Smallest plausible size for the ksud CLI; skips stub .so files cheaply. */
    private static final long MIN_SIZE = 300_000L;
    private static final byte[] NEEDLE = "late-load".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] ELF = {0x7f, 'E', 'L', 'F'};
    private static final int CHUNK = 64 * 1024;

    private static final Map<String, File> CACHE = new HashMap<>();

    private SuManagerBinary() {}

    /** @return the ksud binary for this app, or null when it has none. */
    static synchronized File find(ApplicationInfo app) {
        if (app.nativeLibraryDir == null) return null;
        File cached = CACHE.get(app.nativeLibraryDir);
        if (cached != null && cached.isFile()) return cached;

        File found = search(new File(app.nativeLibraryDir));
        if (found != null) CACHE.put(app.nativeLibraryDir, found);
        else CACHE.remove(app.nativeLibraryDir);
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
        if (!file.isFile() || !file.canRead() || !file.canExecute()) return false;
        if (file.length() < MIN_SIZE) return false;
        try (InputStream in = new FileInputStream(file)) {
            byte[] head = new byte[ELF.length];
            if (readFully(in, head) != head.length) return false;
            for (int i = 0; i < ELF.length; i++) {
                if (head[i] != ELF[i]) return false;
            }

            byte[] buf = new byte[CHUNK + NEEDLE.length - 1];
            int carry = 0;
            while (true) {
                int n = in.read(buf, carry, CHUNK);
                if (n <= 0) return false;
                int total = carry + n;
                if (indexOf(buf, total, NEEDLE) >= 0) return true;
                carry = NEEDLE.length - 1;
                System.arraycopy(buf, total - carry, buf, 0, carry);
            }
        } catch (IOException | SecurityException e) {
            return false;
        }
    }

    private static int readFully(InputStream in, byte[] out) throws IOException {
        int off = 0;
        while (off < out.length) {
            int n = in.read(out, off, out.length - off);
            if (n < 0) break;
            off += n;
        }
        return off;
    }

    private static int indexOf(byte[] haystack, int length, byte[] needle) {
        outer: for (int i = 0; i <= length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}