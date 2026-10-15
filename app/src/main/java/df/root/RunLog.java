package df.root;

import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.provider.MediaStore;
import android.provider.Settings;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Crash-proof run log. Every report line from BOTH run chains (app-button and
 * boot autorun) lands here, line-synchronous and fsynced, so a kernel panic
 * mid-run cannot eat it.
 *
 * Two channels:
 *  - Device-encrypted private dir (/data/user_de/0/df.root/files/):
 *    last_run.log (current run) and last_run_prev.log (rolled on boot change
 *    or new run - renamed, never deleted). Readable with root, survives
 *    everything, writable even during direct boot.
 *  - Public Downloads via MediaStore (Download/DirtyFrag/dfroot_runlog.txt):
 *    append-only history of every run, no storage permission needed on
 *    Android 12L-15 for the app's own contributions, readable from any file
 *    manager or adb WITHOUT root - which matters because after a panic
 *    reboot root is gone until the next successful run.
 *
 * Direct boot caveat: at LOCKED_BOOT_COMPLETED the external volume is not
 * mounted, so the boot chain writes DE only and marks the mirror pending;
 * the pending DE content is flushed to Downloads on user unlock / next app
 * start. Nothing is dropped either way.
 */
public final class RunLog {
    private static final String TAG = "dfroot";
    private static final String DE_FILE = "last_run.log";
    private static final String PREV_FILE = "last_run_prev.log";
    private static final String EXT_DIR = "Download/DirtyFrag";
    private static final String EXT_NAME = "dfroot_runlog.txt";

    private static boolean inited;
    private static boolean externalPending;
    private static Uri extUri;

    private RunLog() {}

    /** Idempotent. Rolls last_run.log to last_run_prev.log when the boot
     *  count changed (a crash-reboot happened since the last write). */
    public static synchronized void init(Context deCtx) {
        if (inited) return;
        inited = true;
        File f = new File(deCtx.getFilesDir(), DE_FILE);
        int saved = deCtx.getSharedPreferences("dfroot", Context.MODE_PRIVATE)
                .getInt("log_boot_count", -1);
        int boot = bootCount(deCtx);
        if (saved != boot && f.exists()) {
            File prev = new File(deCtx.getFilesDir(), PREV_FILE);
            prev.delete();
            // Rename, never delete: the stale run is the crash evidence.
            if (!f.renameTo(prev)) Log.w(TAG, "runlog: roll " + DE_FILE + " failed");
        }
        deCtx.getSharedPreferences("dfroot", Context.MODE_PRIVATE)
                .edit().putInt("log_boot_count", boot).apply();
    }

    /** The authoritative append. Raw lines, synchronized, fsynced. */
    public static synchronized void append(Context deCtx, String msg) {
        try (FileOutputStream out = new FileOutputStream(
                new File(deCtx.getFilesDir(), DE_FILE), true)) {
            out.write(msg.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.getFD().sync();
        } catch (IOException e) {
            Log.w(TAG, "runlog: DE append failed", e);
        }
        mirrorExternal(deCtx, msg);
    }

    /** Explicit roll (new run started in-app). */
    public static synchronized void roll(Context deCtx) {
        File f = new File(deCtx.getFilesDir(), DE_FILE);
        if (!f.exists()) return;
        File prev = new File(deCtx.getFilesDir(), PREV_FILE);
        prev.delete();
        f.renameTo(prev);
    }

    public static File file(Context deCtx) {
        return new File(deCtx.getFilesDir(), DE_FILE);
    }

    public static File prevFile(Context deCtx) {
        return new File(deCtx.getFilesDir(), PREV_FILE);
    }

    /** Push DE content that missed the mirror (direct-boot window) to
     *  Downloads. Safe to call anytime; cheap no-op when nothing is pending. */
    public static synchronized void flushExternal(Context deCtx) {
        if (!externalPending) return;
        externalPending = false;
        StringBuilder sb = new StringBuilder();
        for (String name : new String[]{PREV_FILE, DE_FILE}) {
            File f = new File(deCtx.getFilesDir(), name);
            if (!f.exists()) continue;
            try (FileInputStream in = new FileInputStream(f)) {
                byte[] b = new byte[(int) f.length()];
                int n = in.read(b);
                if (n > 0) sb.append("=== recovered ").append(name).append(" ===\n")
                        .append(new String(b, 0, n, StandardCharsets.UTF_8));
            } catch (IOException ignored) {
                externalPending = true;
            }
        }
        if (sb.length() > 0) mirrorExternal(deCtx, sb.toString());
        if (externalPending) Log.w(TAG, "runlog: external flush still pending");
    }

    // ------------------------------------------------------------- external

    private static void mirrorExternal(Context deCtx, String msg) {
        if (externalPending) return;
        try {
            // The DE context cannot see external volumes; the application
            // context (CE) is what MediaStore talks to.
            Context app = deCtx.getApplicationContext();
            Uri uri = ensureExternal(app);
            try (OutputStream os = app.getContentResolver()
                    .openOutputStream(uri, "wa")) {
                if (os == null) throw new IOException("null stream");
                os.write(msg.getBytes(StandardCharsets.UTF_8));
                os.write('\n');
                os.flush();
            }
        } catch (Exception e) {
            // Direct boot (volume not mounted) or transient FUSE failure:
            // keep the DE copy and replay it on unlock / next app start.
            externalPending = true;
            Log.w(TAG, "runlog: external mirror deferred - " + e);
        }
    }

    private static Uri ensureExternal(Context app) throws IOException {
        if (extUri != null) return extUri;
        String sel = MediaStore.MediaColumns.RELATIVE_PATH + "=? AND "
                + MediaStore.MediaColumns.DISPLAY_NAME + "=?";
        try (android.database.Cursor c = app.getContentResolver().query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                new String[]{MediaStore.MediaColumns._ID},
                sel, new String[]{EXT_DIR + "/", EXT_NAME}, null)) {
            if (c != null && c.moveToFirst()) {
                extUri = ContentUris.withAppendedId(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI, c.getLong(0));
                return extUri;
            }
        }
        ContentValues cv = new ContentValues();
        cv.put(MediaStore.MediaColumns.DISPLAY_NAME, EXT_NAME);
        cv.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
        cv.put(MediaStore.MediaColumns.RELATIVE_PATH, EXT_DIR);
        Uri pending = app.getContentResolver()
                .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
        if (pending == null) throw new IOException("insert failed");
        // Finalize immediately; later appends open it with "wa".
        app.getContentResolver().openOutputStream(pending).close();
        ContentValues done = new ContentValues();
        done.put(MediaStore.MediaColumns.IS_PENDING, 0);
        app.getContentResolver().update(pending, done, null, null);
        extUri = pending;
        return extUri;
    }

    private static int bootCount(Context deCtx) {
        try {
            return Settings.Global.getInt(deCtx.getContentResolver(),
                    Settings.Global.BOOT_COUNT, -1);
        } catch (Exception e) {
            return -1;
        }
    }
}
