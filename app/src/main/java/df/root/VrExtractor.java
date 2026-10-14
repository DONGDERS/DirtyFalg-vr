package df.root;

/**
 * Java bridge to the vr offset extractor (libvrext.so). The engine is
 * GhostLock's own kernel extractor (tools/extract_rs from Ghostlock-vr),
 * compiled as a cdylib: it takes a boot.img / payload.bin / OTA ZIP (local
 * path or http URL), recovers the embedded kallsyms, disassembles
 * __traceiter_sys_exit and derives the W1c write target
 * (__tracepoint_sys_exit->funcs) as a member offset of struct tracepoint
 * (e.g. 72 on 6.6.89-android15-8).
 *
 * derive() blocks (URL mode downloads only the boot partition via ranged
 * requests); call it from a background thread. Progress is polled via
 * progress(): "phase done total", phase 0 = download bytes, 1 = extraction.
 */
public final class VrExtractor {
    static {
        System.loadLibrary("vrext");
    }

    private VrExtractor() {}

    /** Blocks until done. Returns the JSON result string (ok/member/error). */
    public static native String nativeDerive(String input, String workDir, boolean insecure);

    /** Non-blocking: "phase done total" of the latest progress report. */
    public static native String nativeProgress();
}
