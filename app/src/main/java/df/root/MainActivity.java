package df.root;

import android.content.Context;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.util.Log;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.content.res.ResourcesCompat;

import androidx.appcompat.app.AppCompatActivity;

import df.root.databinding.ActivityMainBinding;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private ActivityMainBinding binding;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private final StringBuilder logBuffer = new StringBuilder();
    private File lastLogFile;
    private boolean running;
    private boolean runArmed;
    private boolean advancedLog;
    private boolean expertMode;
    private boolean vrRefresh;
    private String exploitPhase = "";
    private int cleanupSteps;
    private float seg1;
    private float pillPercent = 0.48f;
    /** SU-manager launcher geometry: a 54dp circle with a 12dp gap to the Run
     *  pill while a run is in flight; once root is verified the circle morphs
     *  into a pill as wide as the shrunken Run pill (setCompactButton +
     *  morphKsuToPill). Matches the share circle's 54dp on the left. */
    private static final float KSU_CIRCLE_DP = 54f;
    private static final float KSU_GAP_DP = 12f;
    private android.animation.ValueAnimator ksuMorph;
    private VersionPillSpan pillSpan;
    private TextView titleView;
    private boolean updateAvailable;
    private boolean moduleRefresh;

    /** Device-protected storage context: bootstrap.c reads its prefs from
     *  /data/user_de/0/df.root/, so every pref the exploit depends on must live
     *  there, not in credential-protected storage. */
    private Context mDeCtx;
    /** Package name of the SU manager whose libksud.so gets staged, or null. */
    private String suManagerPkg;
    private CharSequence suManagerLabel;
    /** A failed run locks the Run button until reboot (page-cache patch). */
    private boolean failedRun;
    /** Raw "***FAILED***: ..." text from the exploit, used for the failure log. */
    private String lastFailReason;

    // ---- Movable card stack (VIS1 - VIS5) -----------------------------------

    /** The card keys as they are written to dfroot_ui, in the shipped order.
     *  "sumanager" is first and is the one card that can never be hidden. */
    private static final String[] CARD_KEYS = {"sumanager", "autorun", "modules", "vr", "log"};
    /** Hide button per card, index-parallel to CARD_KEYS. They live in the root
     *  layout, not inside the cards: MaterialCardView clips its children to the
     *  rounded outline, and the badge has to straddle the card's top-left edge. */
    private final android.widget.ImageButton[] hideButtons =
            new android.widget.ImageButton[CARD_KEYS.length];
    /** Cards the user hid; kept in sync with the prefs so a restart is faithful. */
    private final List<String> hiddenCards = new ArrayList<>();
    /** True while a drag has the scrollable log blacked out (VIS2.1). */
    private boolean logHiddenForDrag;
    /** True while the log is allowed on screen at all: the advanced-log switch
     *  is on, there is a run to show and the advanced-log card is not collapsed.
     *  Composed with {@link #logHiddenForDrag} into one fade (VIS2.1/VIS4). */
    private boolean logAllowed;
    /** How long the log and its gradient take to ease in or away. */
    private static final long LOG_FADE_MS = 180L;
    /** Hide button geometry: a 30dp badge sitting on the card's top edge. */
    private static final float HIDE_BTN_DP = 30f;
    /** Invisible full-screen sheet that turns the next tap into "accept this
     *  layout" while a card is still outlined. It has to be a real view: the
     *  log scroll and the pills eat their own touches, so a listener on the
     *  root layout would never hear the tap. */
    private View acceptOverlay;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        // Forensics first, raw and unfiltered, line-synchronous on disk.
        RunLog.append(createDeviceProtectedStorageContext(), msg.trim());
        mMain.post(() -> {
            // Drive the two-step progress bar from the raw (unfiltered) lines.
            for (String line : msg.split("\n", -1)) {
                driveProgress(line.trim());
            }
            for (String line : msg.split("\n", -1)) {
                String t = line.trim();
                // Skip empty lines to keep the log compact.
                if (t.isEmpty()) {
                    continue;
                }
                // Drop byte-progress counters ("0 ?", "512 ?", ...).
                if (t.matches("\\d+\\s*(\\u2026|\\.{3})?")) {
                    continue;
                }
                // Drop internal patch/hook details and raw result markers: the
                // app renders its own SETUP/EXPLOIT/INIT/CLEANUP headers and
                // synthesizes a single failure line instead of the raw one.
                if (t.contains("hook=") || t.equals("ksud start: SUCCESS")
                        || t.contains("ERROR - ")) {
                    continue;
                }
                // Strip hex file offsets: ".../libc.so+0x6e8b0" -> ".../libc.so"
                t = t.replaceAll("\\+0x[0-9a-fA-F]+$", "");
                t = stripHeader(t);
                t = zhLine(t);
                appendLog(t);
            }
            binding.outputScroll.post(() -> binding.outputScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void appendLog(String line) {
        binding.outputView.append(styleLogLine(line));
        binding.outputView.append("\n");
        logBuffer.append(line).append('\n');
    }

    /** Translates raw native log lines into two-step progress-bar states.
     *  STRICTLY LINEAR: seg 1 (the exploit run) climbs to 100% and only then does seg 2
     *  (verification) start climbing. The two bars never move at the same time.
     *  Seg 1 tracks setup + file patching + the hook firing; seg 2 tracks the bootstrap,
     *  which reports progress by touching /dev/dfm* nodes that exp.c polls for 70 seconds. */
    private void driveProgress(String t) {
        if (t.isEmpty()) return;
        // v4.0 marker table: a failure is reported as "<stage>: ERROR - <reason>".
        int err = t.indexOf("ERROR - ");
        if (err >= 0) {
            lastFailReason = t.substring(err + "ERROR - ".length()).trim();
        }
        switch (t) {
            case "=== setup ===":
                exploitPhase = "setup";
                setSeg1(0.05f);
                break;
            case "=== exploit (patching files) ===":
                exploitPhase = "exploit";
                setSeg1(0.15f);
                break;
            case "=== init  ===":
                // The run bar is nearly done; the verification bar stays EMPTY until the
                // module is actually in and the exploit bar has read 100%.
                exploitPhase = "init";
                setSeg1(0.98f);
                break;
            case "=== cleanup ===":
                exploitPhase = "cleanup";
                cleanupSteps = 0;
                break;
            default:
                break;
        }
        if (exploitPhase.equals("setup") && t.startsWith("found ko_target:")) {
            setSeg1(0.10f);
        }
        if (exploitPhase.equals("exploit")) {
            if (t.startsWith("patch: crash_dump64")) {
                setSeg1(0.30f);
            } else if (t.contains("<- dfroot.ko")) {
                setSeg1(0.50f);
            } else if (t.startsWith("Finding symbol offsets")) {
                setSeg1(0.60f);
            } else if (t.contains("<- shellcode")) {
                setSeg1(0.75f);
            } else if (t.contains("<- trampoline")) {
                setSeg1(0.90f);
            } else if (t.startsWith("Triggering hook")) {
                setSeg1(0.95f);
            }
        }
        // Run bar finishes here - the module is in, nothing left to patch.
        if (t.startsWith("libc++: loading custom module")) {
            setSeg1(1f);
        }
        // Verification bar: one step per bootstrap marker (see exp.c markers[]).
        // v4.0 renamed every marker and dropped the "env adopted" / "partitions set
        // ro" confirmations, so these steps are re-keyed to the new table.
        if (t.startsWith("kernel module: launching bootstrap")) {
            setSeg2(0.14f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: loading app preferences file")) {
            setSeg2(0.28f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: cloning zygote env")
                || t.startsWith("bootstrap: WARNING - clone zygote env failed")) {
            setSeg2(0.42f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: setting partitions ro")
                || t.startsWith("bootstrap: WARNING - set partitions ro failed")) {
            setSeg2(0.57f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: disabling ksu modules")) {
            setSeg2(0.71f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: starting SU daemon")) {
            setSeg2(0.85f, "Verification", 0xFFFFFFFF);
        }
        if (t.equals("ksud start: SUCCESS")) {
            setSeg1(1f);
            setSeg2(1f, "已验证", 0xFFFFFFFF);
        }
        if (exploitPhase.equals("cleanup") && t.startsWith("restoring")) {
            cleanupSteps++;
        }
    }

    private void setSeg1(float p) {
        seg1 = p;
        binding.twoStep.setSeg1(p, Math.round(p * 100) + "%");
    }

    private void setSeg2(float p, String label, int color) {
        binding.twoStep.setSeg2(p, label, color);
    }

    /** VIS4: the room the stack keeps under the advanced-log card, which is also
     *  exactly how tall the log panel and its fade are - one number in
     *  @dimen/log_window_height, so the window and the box can never disagree. */
    private int logWindowPx() {
        return getResources().getDimensionPixelSize(R.dimen.log_window_height);
    }

    /** Turn the advanced log on or off from anywhere - the switch, a card being
     *  lifted, the saved setting at startup.
     *  OneUiSwitch is drawn from scratch and only reports a change when a finger
     *  clicks it: quietly calling setChecked() moves the thumb and tells nobody,
     *  which left the pill showing off while the log went on behaving as if it
     *  were still on. Everything therefore comes through here. */
    private void setAdvancedLog(boolean on) {
        advancedLog = on;
        binding.switchAdvancedLog.setChecked(on);
        createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("advanced_log", on).apply();
        updateLogVisibility();
    }

    /** Visibility of log / share button / progress bar, composed from the
     *  advanced-log setting and whether any run data exists. The log block
     *  needs the switch; the share circle does not - a finished run can always
     *  be saved. */
    private void updateLogVisibility() {
        boolean hasRun = logBuffer.length() > 0
                || (lastLogFile != null && lastLogFile.exists());
        // The log lives under its own card, so a collapsed card takes the log
        // with it - "重置卡片布局" brings both back.
        logAllowed = advancedLog && hasRun && !hiddenCards.contains("log");
        // VIS4: the log hangs off the advanced-log card, so the window the stack
        // keeps for it follows the log. The stack then does the placing - the
        // panel and its fade are handed over in setupCardStack().
        // The window is cut before the log fades up, so the panel and its
        // gradient are already lying in the right place when they appear: show
        // the log first and slide the gradient in behind it, and the log reads
        // as one bright flash before the fade catches up with it.
        // The window exists for exactly as long as the log is on screen and for
        // no longer - a drag included. Lifting a card puts the log away
        // (VIS2.1), and the room it kept has to go with it: held open, every
        // card below the one being moved sat a whole window too low and slid
        // that much further than it ever should, which is what made a reorder
        // look like the cards underneath were dropping out of the screen. The
        // stack re-lays itself out the moment the window changes, so the drag
        // that is starting measures the slots the cards actually have.
        binding.cardStack.setLogGap(logAllowed ? logWindowPx() : 0);
        fadeLog(logAllowed && !logHiddenForDrag);
        // Share circle: any FINISHED run, advanced log on or off. Still hidden
        // while a run is in flight (the log is being written) and shown for a
        // saved log from a previous boot, which is finished by definition.
        setShareButtonVisible(hasRun && !running);
        // Progress bar is the simple status: always visible.
    }

    /**
     * Ease the log box in or away (VIS2.1, VIS4). The log has half a dozen
     * reasons to appear or vanish - the switch, a run starting, a card being
     * lifted, that card being collapsed - and every one of them used to flip the
     * views between GONE and VISIBLE like a light switch, which read as a flash.
     * It now moves on one alpha, and a log that is fading out only leaves the
     * layout once there is nothing left of it to see.
     * One alpha for one box: the text and the gradient over it are the same view
     * since VIS4, so there is nothing left that could fall a frame behind.
     */
    private void fadeLog(boolean show) {
        final View box = binding.logWindow;
        boolean visible = box.getVisibility() == View.VISIBLE;
        float target = show ? 1f : 0f;
        if (visible == show && box.getAlpha() == target) return;
        box.animate().cancel();
        if (show) box.setVisibility(View.VISIBLE);
        box.animate().alpha(target).setDuration(LOG_FADE_MS)
                .withEndAction(() -> {
                    if (box.getAlpha() <= 0f) box.setVisibility(View.GONE);
                })
                .start();
    }

    /** Pop the share circle in/out with the same animation the KernelSU
     *  launcher circle uses (fade + 0.6x -> 1x scale, 150ms delay). */
    private void setShareButtonVisible(boolean show) {
        android.widget.ImageButton b = binding.btnShareLog;
        boolean wasVisible = b.getVisibility() == View.VISIBLE
                && b.getAlpha() > 0.99f;
        if (show && !wasVisible) {
            b.setVisibility(View.VISIBLE);
            b.setAlpha(0f);
            b.setScaleX(0.6f);
            b.setScaleY(0.6f);
            b.postDelayed(() -> b.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180).start(), 150);
        } else if (show) {
            b.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(120).start();
        } else if (wasVisible) {
            b.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f).setDuration(200)
                    .withEndAction(() -> b.setVisibility(View.GONE)).start();
        }
    }

    /** "=== setup ===" -> "准备阶段"; "=== exploit failed: x ===" ->
     *  "提权失败". The raw protocol markers must stay byte-identical in the
     *  source (driveProgress / state restore / log triage match them), only
     *  the on-screen form is Chinese. */
    private static String stripHeader(String t) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^===\\s*(.*?)\\s*===$").matcher(t);
        if (!m.matches()) return t;
        String h = m.group(1).toUpperCase();
        // The native binary still prints "=== exploit (patching files) ===";
        // the UI shows the short form.
        switch (h) {
            case "SETUP":                    return "准备阶段";
            case "EXPLOIT (PATCHING FILES)":
            case "PATCHING":                 return "修补文件";
            case "INIT":                     return "内核装载";
            case "CLEANUP":                  return "清理恢复";
            case "EXPLOIT SUCCESS":          return "提权成功";
            default:
                if (h.startsWith("EXPLOIT FAILED")) return "提权失败";
                return h;
        }
    }

    /** The log's first line. Deliberately generic: the device banner that
     *  ExploitRunner prints immediately below it already carries manufacturer,
     *  model, Android version, patch level and kernel version, so the old
     *  model-prefixed firmware token ("S931BXXU1AYB2") was redundant noise. */
    private static final String LOG_HEADER = "SYSTEM";

    /** Raw protocol line -> Chinese on-screen line. Returns the input when
     *  there is no mapping (device paths, hex offsets etc. stay as-is).
     *  Display-only: RunLog keeps the raw English protocol lines so log
     *  matching and pasted-log triage keep working. */
    private static String zhLine(String t) {
        switch (t) {
            case "libc++: loading custom module":
                return "✓ 内核模块已装载";
            case "kernel module: launching bootstrap":
                return "✓ 模块启动引导程序";
            case "bootstrap: loading app preferences file":
                return "引导：读取应用配置";
            case "bootstrap: cloning zygote env":
                return "引导：继承 zygote 环境";
            case "bootstrap: WARNING - clone zygote env failed":
                return "⚠ 继承 zygote 环境失败（已跳过）";
            case "bootstrap: setting partitions ro":
                return "引导：分区回只读";
            case "bootstrap: WARNING - set partitions ro failed":
                return "⚠ 分区回只读失败（已跳过）";
            case "bootstrap: disabling ksu modules":
                return "引导：停用 KernelSU 模块";
            case "bootstrap: starting SU daemon":
                return "引导：启动 SU 守护进程";
            case "vr: sys_exit probe disarmed (funcs = NULL)":
                return "✓ vr 防护已拆除";
            case "vr: W1c FAILED - tracepoint/offset mismatch, vr intact":
                return "✗ vr 拆除失败：偏移不匹配，vr 防护仍生效";
            case "patch: DEVICE NOT VULNERABLE":
                return "✗ 内核未受此漏洞影响（厂商已修补）";
            case "SYSTEM":
                return "系统";
        }
        if (t.startsWith("Using KMI:"))
            return "匹配内核 KMI：" + t.substring("Using KMI:".length()).trim();
        if (t.startsWith("found ko_target:"))
            return "定位目标文件：" + t.substring("found ko_target:".length()).trim();
        if (t.startsWith("Triggering hook"))
            return "触发钩子" + t.substring("Triggering hook".length());
        if (t.startsWith("vr: cfg patched, funcs offset "))
            return "✓ vr 配置已写入（" + t.substring("vr: cfg patched, ".length()) + "）";
        if (t.startsWith("vr: WARNING - ko has no vr config slot"))
            return "⚠ 模块内无 vr 配置槽，vr 拆除已跳过";
        if (t.startsWith("restoring trampoline in "))
            return "清理：恢复 " + t.substring("restoring trampoline in ".length());
        if (t.startsWith("restoring shellcode in "))
            return "清理：恢复 " + t.substring("restoring shellcode in ".length());
        if (t.startsWith("patch: ") && t.contains("<- "))
            return "修补文件：" + t.substring("patch: ".length());
        if (t.startsWith("patched ") && t.contains(" to "))
            return "已写入 " + t.substring("patched ".length());
        if (t.startsWith("Finding symbol offsets for "))
            return "解析符号偏移：" + t.substring("Finding symbol offsets for ".length());
        if (t.startsWith("device not vulnerable"))
            return "✗ 内核未受此漏洞影响（厂商已修补）";
        if (t.startsWith("Can't parse kernel version"))
            return "✗ 无法识别内核版本（非 GKI 设备）";
        if (t.startsWith("Unsupported kernel "))
            return "✗ 内核版本暂不支持：" + t.substring("Unsupported kernel ".length()).trim();
        if (t.startsWith("patch: ") && t.contains(" patch failed"))
            return "✗ 修补文件失败：" + t.substring("patch: ".length());
        if (t.startsWith("failed to find offsets for "))
            return "✗ 解析符号偏移失败：" + t.substring("failed to find offsets for ".length());
        if (t.endsWith(" already patched"))
            return "目标已是修补状态（跳过）：" + t.substring(0, t.length() - " already patched".length());
        return t;
    }

    /** Raw "ERROR - <reason>" text -> Chinese one-line cause. */
    private static String zhFailReason(String raw) {
        String r = raw == null ? "" : raw.trim();
        if (r.contains("no SU manager selected"))
            return "未选择 SU 管理器";
        if (r.contains("no longer installed") || r.contains("has no libksud.so"))
            return "所选 SU 管理器不可用（已卸载或缺少 libksud.so）";
        if (r.contains("DEVICE NOT VULNERABLE") || r.contains("failed to patch files"))
            return "文件修补失败（内核可能已修补此漏洞）";
        if (r.contains("reading prefs failed"))
            return "引导程序读取应用配置失败";
        if (r.contains("disable modules failed"))
            return "停用 KernelSU 模块失败";
        if (r.contains("ksud nonzero exit"))
            return "SU 守护进程（ksud）异常退出";
        if (r.contains("check logcat") || r.contains("timeout"))
            return "引导流程超时（模块未在时限内完成装载）";
        if (r.contains("non-GKI") || r.contains("Can't parse kernel version"))
            return "无法识别内核版本（非 GKI 设备）";
        if (r.contains("Unsupported kernel"))
            return "内核版本暂不支持";
        if (r.isEmpty()) return "未知原因";
        return r;
    }

    /** Raw "ERROR - <reason>" text -> Chinese one-line advice. */
    private static String zhFailAdvice(String raw) {
        String r = raw == null ? "" : raw.trim();
        if (r.contains("no SU manager selected"))
            return "建议：先在 SU Manager 卡片选择你的管理器（需自带 libksud.so），再按运行";
        if (r.contains("no longer installed") || r.contains("has no libksud.so"))
            return "建议：换一个自带 libksud.so 的 SU 管理器（KernelSU / KernelSU-Next 等）后重试";
        if (r.contains("reading prefs failed"))
            return "建议：确认已在 SU Manager 卡片选择管理器后重试；反复失败请重启后再试";
        if (r.contains("disable modules failed"))
            return "建议：重启后重试；若怀疑某个模块导致崩溃，可先关闭 KernelSU Modules 开关再提权";
        if (r.contains("ksud nonzero exit"))
            return "建议：重启手机后重试；反复出现请保存运行日志反馈";
        if (r.contains("failed to patch files") || r.contains("DEVICE NOT VULNERABLE"))
            return "建议：重启手机后重试一次；若再次失败，说明设备内核已修补此漏洞，无法提权";
        if (r.contains("check logcat") || r.contains("timeout"))
            return "建议：重启手机后重试；反复超时请保存运行日志反馈";
        return "建议：重启手机后重试；反复失败请保存运行日志反馈";
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private boolean isHeader(String line) {
        return line.equals("SETUP") || line.equals("PATCHING")
                || line.equals("EXPLOIT (PATCHING FILES)")
                || line.equals("INIT") || line.equals("CLEANUP")
                || line.equals("准备阶段") || line.equals("修补文件")
                || line.equals("内核装载") || line.equals("清理恢复")
                || line.equals("提权成功") || line.equals("提权失败")
                || line.startsWith("EXPLOIT FAILED")
                || line.equals(LOG_HEADER) || line.equals("系统");
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private CharSequence styleLogLine(String line) {
        SpannableString ss = new SpannableString(line);
        if (isHeader(line)) {
            ss.setSpan(new StyleSpan(Typeface.BOLD), 0, line.length(), 0);
            ss.setSpan(new RelativeSizeSpan(1.3f), 0, line.length(), 0);
            ss.setSpan(new ForegroundColorSpan(0xFFFFFFFF), 0, line.length(), 0);
        } else {
            ss.setSpan(new ForegroundColorSpan(0xFFB3B3B3), 0, line.length(), 0);
        }
        return ss;
    }

    /** (removed) saveLog used to rewrite last_run.log with the filtered UI
     *  buffer - that clobbered RunLog's raw forensic appends. The file now
     *  belongs to RunLog: raw, append-only, fsynced per line. */

    private int bootCount() {
        try {
            return android.provider.Settings.Global.getInt(getContentResolver(),
                    android.provider.Settings.Global.BOOT_COUNT, -1);
        } catch (Exception e) {
            return -1;
        }
    }

    private String readLastLog() {
        if (lastLogFile == null || !lastLogFile.exists()) return "";
        try (java.io.FileInputStream in = new java.io.FileInputStream(lastLogFile);
             java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) != -1; ) bos.write(buf, 0, n);
            String log = bos.toString(java.nio.charset.StandardCharsets.UTF_8.name()).trim();
            // Normalize exploit-result headers to lowercase (older runs saved
            // them uppercase); the file gets rewritten on next save.
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("(===\\s*exploit\\s+(?:success|failed[^=]*)\\s*===)",
                            java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(log);
            StringBuilder sb = new StringBuilder();
            while (m.find()) m.appendReplacement(sb, java.util.regex.Matcher
                    .quoteReplacement(m.group().toLowerCase()));
            m.appendTail(sb);
            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mDeCtx = createDeviceProtectedStorageContext();
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Version tag flowing right after the header title. Straight out of
        // versionName, so the pill, the update check (which reads the installed
        // package info) and the APK itself can never disagree.
        String head = "DirtyFrag " + BuildConfig.VERSION_NAME;
        SpannableString title = new SpannableString(head);
        pillSpan = new VersionPillSpan(0.45f);
        title.setSpan(pillSpan, "DirtyFrag ".length(), head.length(),
                SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE);
        binding.toolbar.setTitle(title);
        // NOTE: no setSupportActionBar() - it makes the ActionBar delegate draw
        // the title and ignore the toolbar's titleTextAppearance (breaks bold).
        // The toolbar renders its own title via app:titleTextAppearance.

        // Update pill disabled: this build is maintained in the private fork,
        // so the upstream release check would only ever offer the wrong APK.
        // The version stays a plain pill; no check, no "Update available".
        // mExec.execute(this::checkForAppUpdate);

        // D2 vault status (Samsung VaultKeeper): Odin flashing allowed or
        // locked. Read-only; non-Samsung devices show "not available".

        // SU Manager card: upstream 3.2 deleted the bundled assets/ksud, so the
        // exploit stages libksud.so out of the chosen manager's
        // nativeLibraryDir and refuses to run without one. Only apps that
        // actually ship that library are offered.
        loadSuManagerPref();
        binding.rowSuManager.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            showSuManagerPopup();
        });

        // KSU modules toggle: since 3.2 this is a plain preference, not a root
        // operation. bootstrap.c reads disable_modules and touches a `disable`
        // flag file in every installed module before ksud runs, so the toggle
        // works before the device is rooted and applies on the next root.
        moduleRefresh = true;
        binding.switchModules.setChecked(!mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("disable_modules", false));
        moduleRefresh = false;
        binding.modulesSubtitle.setText(binding.switchModules.isChecked()
                ? "已启用 - 下次提权生效"
                : "已禁用 - 下次提权不加载模块");
        binding.switchModules.setOnCheckedChangeListener((btn, on) -> {
            if (moduleRefresh) return;
            btn.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            applyModuleState(on);
        });

        // ---- Vr disarm (W1c): toggle + funcs offset input ----------------
        // The offset is device-specific (e.g. GhostLock's extractor prints 72
        // = 0x48 for the 6.6.89-android15-8 profile). Saved as a raw string;
        // validity is enforced live in saveVrOffset().
        vrRefresh = true;
        SharedPreferences vrSp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        binding.switchVr.setChecked(vrSp.getBoolean("vr_disarm", false));
        binding.vrOffsetInput.setText(vrSp.getString("vr_off", "72"));
        applyVrState(binding.switchVr.isChecked(), false);
        vrRefresh = false;
        binding.switchVr.setOnCheckedChangeListener((btn, on) -> {
            if (vrRefresh) return;
            btn.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            applyVrState(on, true);
        });
        binding.vrOffsetInput.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                if (!vrRefresh) saveVrOffset(s.toString());
            }
            @Override public void afterTextChanged(android.text.Editable s) {}
        });

        // Vr offset extractor (GhostLock-zstd engine, see VrExtractor): pick
        // an OTA link or a boot.img file and the pipeline fills the input.
        binding.vrExtractBtn.setOnClickListener(v -> showVrExtractDialog());

        // Force real bold (wght 700) One UI Sans on the toolbar title TextView.
        binding.toolbar.post(() -> {
            Typeface base = ResourcesCompat.getFont(this, R.font.inter_vf);
            if (base == null) return;
            Typeface bold = Typeface.create(base, 700, false);
            for (int i = 0; i < binding.toolbar.getChildCount(); i++) {
                View child = binding.toolbar.getChildAt(i);
                if (child instanceof TextView) {
                    titleView = (TextView) child;
                    titleView.setTypeface(bold);
                    titleView.setOnClickListener(v -> {
                        if (updateAvailable) openUrl(
                                "https://github.com/DONGDERS/DirtyFalg-vr/releases");
                    });
                }
            }
        });

        if (new File("/dev/df").exists()) {
            setRootedState();
        }

        // Show the log from the last run, if any. No run yet -> log hidden.
        // A log saved before the current boot is stale: delete it so a reboot
        // always starts with a clean screen (log + share icon hidden).
        // RunLog owns last_run.log: roll on boot change (rename, never
        // delete - the stale run IS the crash evidence) and mirror everything
        // to the public Downloads copy so it survives without root.
        Context deCtx = createDeviceProtectedStorageContext();
        RunLog.init(deCtx);
        RunLog.flushExternal(deCtx);
        lastLogFile = RunLog.file(deCtx);
        if (lastLogFile.exists()) {
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
        }
        String last = readLastLog();
        boolean hasLastLog = !last.isEmpty();
        if (hasLastLog) {
            appendLog(zhLine(LOG_HEADER));
            for (String l : last.split("\n")) {
                String t = stripHeader(l.trim());
                // Skip stale headers, old result lines and duplicate header lines.
                if (t.isEmpty()
                        || t.equals("LAST RUN")
                        || t.equals("EXPLOIT SUCCESS")
                        || t.equals(LOG_HEADER)) {
                    continue;
                }
                t = zhLine(t);
                appendLog(t);
            }
        }

        // Advanced log toggle: full log vs. simple status (progress bar only).
        advancedLog = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("advanced_log", false);
        binding.switchAdvancedLog.setChecked(advancedLog);
        binding.switchAdvancedLog.setOnCheckedChangeListener(
                (btn, checked) -> setAdvancedLog(checked));
        updateLogVisibility();

        // Restore the simple status for the current state: rooted device or a
        // successful last run -> 100% + Verified; failed run -> Failed.
        boolean rootedNow = new File("/dev/df").exists();
        boolean lastSuccess = hasLastLog
                && createDeviceProtectedStorageContext()
                        .getSharedPreferences("dfroot", MODE_PRIVATE)
                        .getBoolean("last_run_success", false);
        boolean lastFailed = hasLastLog
                && last.toLowerCase().contains("=== exploit failed");
        if (rootedNow || lastSuccess) {
            binding.twoStep.setSeg1(1f, "100%");
            binding.twoStep.setSeg2(1f, "已验证", 0xFFFFFFFF);
        } else if (lastFailed) {
            setFailedState();
        }

        binding.btnRun.setOnClickListener(v -> {
            if (running) return;
            // Two-tap confirmation: first tap arms ("再按一次确认"), second runs.
            if (!runArmed) {
                runArmed = true;
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                binding.btnRun.setText("再按一次确认");
                return;
            }
            runArmed = false;
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            running = true;
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText("执行中");
            // Same dark greyed-out styling as the Rooted state.
            binding.btnRun.setTextColor(0xFF6E6E6E);
            binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
            ((com.google.android.material.button.MaterialButton) binding.btnRun)
                    .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
            binding.outputView.setText("");
            logBuffer.setLength(0);
            if (lastLogFile.exists()) RunLog.roll(createDeviceProtectedStorageContext());
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
            appendLog(zhLine(LOG_HEADER));
            binding.twoStep.reset();
            setCompactButton(true, false);
            updateLogVisibility();
            mExec.execute(this::runExploit);
        });

        binding.btnKsu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            openKsu();
        });

        // Subtle push-in + keyboard-tap haptic on the run button.
        binding.btnRun.setOnTouchListener((v, ev) -> {
            switch (ev.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                    v.animate().scaleX(0.96f).scaleY(0.96f).setDuration(80).start();
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    v.animate().scaleX(1f).scaleY(1f).setDuration(120).start();
                    break;
                default:
                    break;
            }
            return false;
        });

        binding.btnShareLog.setOnClickListener(v -> shareLog());

        // Overflow menu on the custom grey-circle button: the popup closes
        // ONLY on outside taps, so multi-tap actions are possible.
        binding.btnMenu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            float md = getResources().getDisplayMetrics().density;
            boolean rootedMenu = new File("/dev/df").exists();
            final android.widget.PopupWindow[] pwRef = {null};

            android.widget.LinearLayout box = new android.widget.LinearLayout(this);
            box.setOrientation(android.widget.LinearLayout.VERTICAL);
            box.setBackgroundResource(R.drawable.popup_bg);
            box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

            // -- Github Page row --
            TextView ghRow = new TextView(this);
            ghRow.setBackgroundResource(R.drawable.menu_row_highlight);
            ghRow.setText("GitHub 页面");
            ghRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            ghRow.setPadding((int) (20 * md), 0, 0, 0);
            ghRow.setTextColor(0xFFE8E8E8);
            ghRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            ghRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                openUrl("https://github.com/DONGDERS/DirtyFalg-vr");
            });
            box.addView(ghRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Expert Mode row: white dot appears when enabled --
            android.widget.LinearLayout exRow = new android.widget.LinearLayout(this);
            exRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            exRow.setPadding((int) (20 * md), 0, 0, 0);
            TextView exText = new TextView(this);
            exRow.setBackgroundResource(R.drawable.menu_row_highlight);
            exText.setText("专家模式");
            exText.setTextColor(0xFFE8E8E8);
            exText.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            exRow.addView(exText);
            final android.view.View[] dotRef = {null};
            android.view.View dot = new android.view.View(this);
            dot.setBackgroundResource(R.drawable.dot_white);
            android.widget.LinearLayout.LayoutParams dotLp =
                    new android.widget.LinearLayout.LayoutParams(
                            (int) (7 * md), (int) (7 * md));
            dotLp.setMargins((int) (7 * md), 0, 0, 0);
            dot.setVisibility(expertMode ? View.VISIBLE : View.GONE);
            exRow.addView(dot, dotLp);
            dotRef[0] = dot;
            exRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                expertMode = !expertMode;
                createDeviceProtectedStorageContext()
                        .getSharedPreferences("dfroot", MODE_PRIVATE)
                        .edit().putBoolean("expert_mode", expertMode).apply();
                applyExpertMode();
                if (dotRef[0] != null)
                    dotRef[0].setVisibility(expertMode ? View.VISIBLE : View.GONE);
            });
            box.addView(exRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Reset layout row (VIS5): this slot used to hold "Remove
            //    KSU/KSUD", which never did anything useful. It now puts the
            //    cards back in the shipped order and brings back every card the
            //    user hid. --
            TextView rlRow = new TextView(this);
            rlRow.setBackgroundResource(R.drawable.menu_row_highlight);
            rlRow.setText("重置卡片布局");
            rlRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            rlRow.setPadding((int) (20 * md), 0, 0, 0);
            rlRow.setTextColor(0xFFE8E8E8);
            rlRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            rlRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                if (pwRef[0] != null) pwRef[0].dismiss();
                resetCardLayout();
            });
            box.addView(rlRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // Width: content, but at least 210dp so the popup reads properly.
            box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
            int pw_w = Math.max(box.getMeasuredWidth(), (int) (190 * md));

            final android.widget.PopupWindow pw = new android.widget.PopupWindow(box,
                    pw_w, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, true);
            pw.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(
                    android.graphics.Color.TRANSPARENT));
            pw.setOutsideTouchable(true);
            pwRef[0] = pw;
            pw.setOnDismissListener(() ->
                    binding.dimOverlay.animate().alpha(0f).setDuration(150)
                            .withEndAction(() -> binding.dimOverlay
                                    .setVisibility(View.GONE)).start());

            // Centered separators between the rows.
            android.widget.LinearLayout.LayoutParams sepLp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sepLp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            android.view.View sep1 = new android.view.View(this);
            sep1.setBackgroundColor(0xFF3F3F3F);
            box.addView(sep1, 1, sepLp);
            android.view.View sep2 = new android.view.View(this);
            sep2.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep2Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep2Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep2, 3, sep2Lp);

            box.setOutlineProvider(new android.view.ViewOutlineProvider() {
                @Override
                public void getOutline(View view, android.graphics.Outline outline) {
                    outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
                }
            });
            box.setClipToOutline(true);
            box.setElevation(48 * md);

            int[] loc = new int[2];
            binding.menuAnchor.getLocationOnScreen(loc);
            int x = loc[0] + binding.menuAnchor.getWidth() - pw_w;
            int y = loc[1] + (int) (2 * md);
            binding.dimOverlay.setVisibility(View.VISIBLE);
            binding.dimOverlay.setAlpha(0f);
            binding.dimOverlay.animate().alpha(0.5f).setDuration(150).start();
            box.setPivotX(pw_w);
            box.setPivotY(0f);
            box.setScaleX(0.85f);
            box.setScaleY(0.9f);
            box.setAlpha(0f);
            pw.showAtLocation(binding.menuAnchor,
                    android.view.Gravity.TOP | android.view.Gravity.START, x, y);
            box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator())
                    .start();
        });
        ComponentName bootReceiver = new ComponentName(this, BootReceiver.class);
        int state = getPackageManager().getComponentEnabledSetting(bootReceiver);
        boolean bootEnabled = state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
        binding.switchBootStart.setChecked(bootEnabled);
        binding.switchBootStart.setOnCheckedChangeListener((btn, checked) -> {
            getPackageManager().setComponentEnabledSetting(bootReceiver,
                checked ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            binding.switchAutoSoftReboot.setEnabled(checked);
        });

        boolean autoSoftReboot = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", false);
        binding.switchAutoSoftReboot.setChecked(autoSoftReboot);
        binding.switchAutoSoftReboot.setEnabled(bootEnabled);
        binding.switchAutoSoftReboot.setOnCheckedChangeListener((btn, checked) ->
            createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("auto_soft_reboot", checked).apply());

        // Expert mode gates the autorun card: locked until toggled in the menu.
        expertMode = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("expert_mode", false);
        applyExpertMode();

        // Movable card stack (VIS1 - VIS5): hold-to-lift reorder with the card
        // stuck to the finger, the per-card hide badge and the order + hidden
        // flags from dfroot_ui.
        setupCardStack();

        // Run stays locked until an SU manager is selected (and, after a failed
        // run, until the device has been rebooted).
        updateRunButton();
    }

    /** Expert mode off: the autorun card is inaccessible - greyed text and
     *  disabled toggles, titles suffixed with (Expert). */
    private void applyExpertMode() {
        boolean ok = expertMode;
        binding.tvAutorunTitle.setText(ok ? "开机自启" : "开机自启 (专家)");
        binding.tvRebootTitle.setText(ok ? "自动软重启" : "自动软重启 (专家)");
        binding.tvAutorunTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvAutorunDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.tvRebootTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvRebootDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.switchBootStart.setEnabled(ok);
        binding.switchAutoSoftReboot.setEnabled(ok
                && binding.switchBootStart.isChecked());
    }

    // ---- Movable card stack (VIS1 - VIS5) -----------------------------------

    /** The stack card a prefs key refers to. */
    private DraggableCardView cardForKey(String key) {
        if (key == null) return null;
        switch (key) {
            case "sumanager": return binding.cardSuManager;
            case "autorun": return binding.cardBoot;
            case "modules": return binding.cardModules;
            case "vr": return binding.cardVr;
            case "log": return binding.cardLog;
            default: return null;
        }
    }

    /** The prefs key of a stack card, or null if it is not one of them. */
    private String keyForCard(View card) {
        for (String key : CARD_KEYS) {
            if (cardForKey(key) == card) return key;
        }
        return null;
    }

    /**
     * Wires the movable stack (VIS1): the hide badges, the order and hidden
     * flags the user left behind on last exit, and the tap-outside-to-accept
     * gesture. Nothing here changes what a card DOES - the toggles, the manager
     * picker and the autorun component are wired where they always were, only
     * the position of their card in the stack moves (RULES 4).
     */
    private void setupCardStack() {
        final CardStackLayout stack = binding.cardStack;
        // Above the log scroll and the pills (0dp), below the accept sheet
        // (5dp) and the hide badges (26dp): the stack keeps first pick of every
        // touch, the sheet catches the rest, the badge floats over both.
        stack.setElevation(10 * getResources().getDisplayMetrics().density);
        // VIS4: the log panel belongs to the advanced-log card. The stack keeps a
        // window of room under that card for the log to show through and slides
        // the panel and its fade into it - the stack owns the geometry, so a
        // settle, a collapse or a reorder can never leave the log somewhere else.
        stack.setLogCard(binding.cardLog);
        stack.setLogWindow(binding.logWindow);
        // Drags over the log box scroll the log, not the home.
        binding.scrollHome.setPassthroughView(binding.logWindow);
        stack.setLogGap(logAllowed ? logWindowPx() : 0);
        stack.setListener(new CardStackLayout.Listener() {
            @Override
            public void onCardLifted(View card) {
                // VIS4: the log belongs to a card, and lifting that card means it
                // may end up somewhere else - with the log trailing after it.
                // Chasing the window across a stack in motion is what kept
                // leaving the panel and its gradient a layout behind, so picking
                // a card up now puts the advanced log away. The thumb flips off
                // while the card is still in the hand, and the log is turned back
                // on once the card is where it belongs.
                if (advancedLog) setAdvancedLog(false);
                setLogHiddenForDrag(true);
                setAcceptOverlay(false);
                showHideButton(card);
                // Closing the window takes the cards under the log card - this one
                // included - straight back up again, and the card then snaps down
                // under the finger. Keep the chip glued through both of those
                // rather than leaving it where the card was before the layout
                // moved it; onCardMoved takes over from the next drag frame.
                followBadgeDuringSettle(card);
            }

            @Override
            public void onCardMoved(View card) {
                placeHideButton(card);
            }

            @Override
            public void onCardDropped(View card, boolean moved) {
                setLogHiddenForDrag(false);
                setAcceptOverlay(true);
                placeHideButton(card);
                followBadgeDuringSettle(card);
                if (moved) saveCardLayout();
            }

            @Override
            public void onCardSelectionCleared() {
                setAcceptOverlay(false);
                hideAllHideButtons();
            }
        });

        final float md = getResources().getDisplayMetrics().density;
        for (int i = 0; i < CARD_KEYS.length; i++) {
            final DraggableCardView card = cardForKey(CARD_KEYS[i]);
            // RULES 3: the SU Manager card moves but can never be hidden.
            card.setHideable(!"sumanager".equals(CARD_KEYS[i]));
            android.widget.ImageButton b = new android.widget.ImageButton(this);
            b.setBackgroundResource(R.drawable.bg_card_hide_button);
            b.setImageResource(R.drawable.ic_card_hide);
            b.setImageTintList(ColorStateList.valueOf(0xFF3A3A3C));
            b.setScaleType(android.widget.ImageView.ScaleType.CENTER);
            b.setPadding(0, 0, 0, 0);
            b.setContentDescription("隐藏卡片");
            // Above the lifted card (18dp), below the menu dim layer (30dp).
            b.setElevation(26 * md);
            b.setVisibility(View.GONE);
            b.setOnClickListener(v -> {
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                hideCard(card);
            });
            int size = (int) (HIDE_BTN_DP * md);
            androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                    new androidx.constraintlayout.widget.ConstraintLayout.LayoutParams(
                            size, size);
            binding.getRoot().addView(b, lp);
            hideButtons[i] = b;
        }

        // Saved order first, then the hidden flags: a hidden card keeps its
        // slot in the stack, so showing it again puts it back where it was.
        List<View> seq = new ArrayList<>();
        for (String key : CardLayoutStore.loadOrder(mDeCtx, CARD_KEYS)) {
            DraggableCardView c = cardForKey(key);
            if (c != null && !seq.contains(c)) seq.add(c);
        }
        stack.applyOrder(seq);
        hiddenCards.addAll(CardLayoutStore.loadHidden(mDeCtx, CARD_KEYS));
        for (String key : hiddenCards) {
            DraggableCardView c = cardForKey(key);
            if (c != null && c.isHideable()) c.setVisibility(View.GONE);
        }
        // Whichever card ends up on top must sit flush, so the 12dp gaps are
        // handed out again now that the hidden ones are out of the way.
        stack.applyOrder(seq);
        // The hidden flags arrive after the log was last composed, and a
        // collapsed advanced-log card takes the log with it (VIS4).
        updateLogVisibility();

        // The accept sheet: full screen, invisible, under the stack (10dp) but
        // above the log scroll and the pills, so a tap anywhere that is not a
        // card accepts the layout (VIS2.2). It has to be a real view: the log
        // scroll and the pills consume their own touches, so a listener on the
        // root layout would never hear the tap.
        androidx.constraintlayout.widget.ConstraintLayout.LayoutParams alp =
                new androidx.constraintlayout.widget.ConstraintLayout.LayoutParams(0, 0);
        alp.leftToLeft = alp.rightToRight =
                androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.PARENT_ID;
        alp.topToTop = alp.bottomToBottom =
                androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.PARENT_ID;
        acceptOverlay = new View(this);
        acceptOverlay.setClickable(true);
        acceptOverlay.setElevation(5 * md);
        acceptOverlay.setVisibility(View.GONE);
        acceptOverlay.setOnClickListener(v -> stack.clearSelection());
        binding.getRoot().addView(acceptOverlay, alp);
    }

    /** The accept sheet is up only while a card still carries the outline. */
    private void setAcceptOverlay(boolean on) {
        if (acceptOverlay != null) {
            acceptOverlay.setVisibility(on ? View.VISIBLE : View.GONE);
        }
    }

    /** The badge that belongs to a stack card, or null. */
    private android.widget.ImageButton hideButtonFor(View card) {
        String key = keyForCard(card);
        if (key == null) return null;
        for (int i = 0; i < CARD_KEYS.length; i++) {
            if (CARD_KEYS[i].equals(key)) return hideButtons[i];
        }
        return null;
    }

    /** Show the badge of the lifted card only (VIS1.4). */
    private void showHideButton(View card) {
        hideAllHideButtons();
        android.widget.ImageButton b = hideButtonFor(card);
        if (b == null || !(card instanceof DraggableCardView)
                || !((DraggableCardView) card).isHideable()) {
            return;
        }
        b.setVisibility(View.VISIBLE);
        placeHideButton(card);
    }

    private void hideAllHideButtons() {
        for (android.widget.ImageButton b : hideButtons) {
            if (b != null) b.setVisibility(View.GONE);
        }
        binding.cardStack.clearKeepTouchArea();
    }

    /**
     * Glue the badge to the card's top edge, following it while dragged. Its
     * centre is put on the LEFT edge of the card - the leftmost point of the
     * outlined top edge - so the chip straddles the outline in both directions:
     * half over the card and half over the side margin, half above the card and
     * half below. It is no longer parked a corner radius in from the left, which
     * left it floating over the card instead of on its edge (VIS1.4). The chip is
     * 30dp and the stack is inset 16dp, so the overhang stops 1dp shy of the
     * screen edge and nothing is cut off.
     */
    private void placeHideButton(View card) {
        android.widget.ImageButton b = hideButtonFor(card);
        if (b == null || b.getVisibility() != View.VISIBLE) return;
        float md = getResources().getDisplayMetrics().density;
        int size = b.getWidth() > 0 ? b.getWidth() : Math.round(HIDE_BTN_DP * md);
        int[] at = new int[2];
        int[] root = new int[2];
        int[] swin = new int[2];
        card.getLocationInWindow(at);
        binding.getRoot().getLocationInWindow(root);
        CardStackLayout stack = binding.cardStack;
        stack.getLocationInWindow(swin);
        float bx = at[0] - root[0] - size / 2f;
        float by = at[1] - root[1] - size / 2f;
        b.setX(bx);
        b.setY(by);
        // ... and tell the stack to let the badge's own taps through. The badge
        // lives in root coords, but the stack scrolls inside a ScrollView, so
        // the keep-area has to be derived from the stack's own window position.
        stack.setKeepTouchArea(bx - swin[0], by - swin[1],
                bx + size - swin[0], by + size - swin[1]);
    }

    /** The badge keeps following the card while it settles into its new slot. */
    private void followBadgeDuringSettle(final View card) {
        binding.cardStack.postDelayed(new Runnable() {
            private int ticks = 16;

            @Override
            public void run() {
                placeHideButton(card);
                if (--ticks > 0) binding.cardStack.postDelayed(this, 16);
            }
        }, 16);
    }

    /** VIS1.4: collapse a card out of the stack for good. The SU Manager card
     *  refuses to be hidden (RULES 3); "重置卡片布局" brings the rest back. */
    private void hideCard(DraggableCardView card) {
        String key = keyForCard(card);
        if (key == null || !card.isHideable() || hiddenCards.contains(key)) return;
        hiddenCards.add(key);
        // VIS4: collapsing the advanced-log card takes the log with it.
        updateLogVisibility();
        binding.cardStack.clearSelection();
        hideAllHideButtons();
        binding.cardStack.hideCard(card);
        // VIS4: the log follows the advanced-log card, so a collapse anywhere in
        // the stack moves it - but the stack re-reads the window before every
        // frame, so there is nothing left to re-glue here.
        saveCardLayout();
    }

    /** VIS5: back to the shipped order with every card showing again. */
    private void resetCardLayout() {
        CardStackLayout stack = binding.cardStack;
        stack.clearSelection();
        hideAllHideButtons();
        hiddenCards.clear();
        List<View> seq = new ArrayList<>();
        for (String key : CARD_KEYS) {
            DraggableCardView card = cardForKey(key);
            seq.add(card);
            stack.showCard(card);
        }
        stack.applyOrder(seq);
        // VIS4: everything is back where it started, including the log - the
        // stack puts it there on the next frame.
        updateLogVisibility();
        saveCardLayout();
        Toast.makeText(this, "卡片布局已重置", Toast.LENGTH_SHORT).show();
    }

    /** Write the stack order and the hidden flags to dfroot_ui. */
    private void saveCardLayout() {
        List<String> keys = new ArrayList<>();
        for (View v : binding.cardStack.cardOrder()) {
            String key = keyForCard(v);
            if (key != null && !keys.contains(key)) keys.add(key);
        }
        CardLayoutStore.saveOrder(mDeCtx, keys);
        CardLayoutStore.saveHidden(mDeCtx, hiddenCards);
    }

    /** VIS2.1: the scrollable log blacks out while a card is in flight and
     *  shows again once the card has found its spot. */
    private void setLogHiddenForDrag(boolean hidden) {
        if (logHiddenForDrag == hidden) return;
        logHiddenForDrag = hidden;
        // One fade for every reason the log has to come and go (VIS2.1): sliding
        // it away while a card is in the air is the same motion as showing it at
        // all, so it goes through the same place instead of fighting it for the
        // alpha.
        if (hidden) fadeLog(false);
        else updateLogVisibility();
    }

    /** Re-read the SU manager selection when returning to the app: the user may
     *  have installed or uninstalled a manager while we were in the background,
     *  and the Run button has to reflect that immediately. */
    @Override
    protected void onResume() {
        super.onResume();
        loadSuManagerPref();
        updateRunButton();
    }

    private void setRootedState() {
        setRootedState(true);
    }

    /** Applies the Modules card. Since 3.2 this is a preference write, not a
     *  root operation: bootstrap.c reads disable_modules and touches a
     *  `disable` flag file in every installed module before it starts ksud
     *  (a broken module otherwise bootloops the device). OFF = modules stay
     *  disabled on the next root, ON = modules load. No su required. */
    /** Vr disarm (W1c): expand the funcs-offset input while the switch is on
     *  and keep the prefs flag in step. animate=false during initial setup. */
    private void applyVrState(boolean on, boolean animate) {
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        sp.edit().putBoolean("vr_disarm", on).apply();
        binding.vrSubtitle.setText(on
                ? "开启 - 提权时零写 funcs 拆除探针（拉起管理器前）"
                : "关闭 - 不动 sys_exit 探针");
        View extractBtn = binding.vrExtractBtn;
        if (animate) {
            binding.vrOffsetInput.animate().cancel();
            extractBtn.animate().cancel();
            if (on) {
                binding.vrOffsetInput.setAlpha(0f);
                binding.vrOffsetInput.setVisibility(View.VISIBLE);
                binding.vrOffsetInput.animate().alpha(1f).setDuration(150).start();
                extractBtn.setAlpha(0f);
                extractBtn.setVisibility(View.VISIBLE);
                extractBtn.animate().alpha(1f).setDuration(150).start();
            } else {
                binding.vrOffsetInput.animate().alpha(0f).setDuration(120)
                        .withEndAction(() -> binding.vrOffsetInput.setVisibility(View.GONE))
                        .start();
                extractBtn.animate().alpha(0f).setDuration(120)
                        .withEndAction(() -> extractBtn.setVisibility(View.GONE))
                        .start();
            }
        } else {
            binding.vrOffsetInput.setVisibility(on ? View.VISIBLE : View.GONE);
            extractBtn.setVisibility(on ? View.VISIBLE : View.GONE);
        }
    }

    /** Parses "72" / "0x48" / "0X48" (> 0, < 2^31) and persists the raw text.
     *  Invalid input turns the text red and keeps the last valid value. */
    private void saveVrOffset(String text) {
        String t = text.trim();
        boolean valid;
        try {
            boolean hex = t.startsWith("0x") || t.startsWith("0X");
            long v = Long.parseLong(hex ? t.substring(2) : t, hex ? 16 : 10);
            valid = v > 0 && v < (1L << 31);
        } catch (Exception e) {
            valid = false;
        }
        binding.vrOffsetInput.setTextColor(valid ? 0xFFFFFFFF : 0xFFE57373);
        if (valid) {
            mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putString("vr_off", t).apply();
        }
    }

    // --------------------------------------------------- vr offset extractor

    private static final int REQ_VR_FILE = 0x5752;
    /** Guard: only one derive at a time (the poller stops on it, too). */
    private volatile boolean vrExtractRunning;
    private int vrLastLoggedMark = -1;

    private final Runnable vrProgressTick = new Runnable() {
        @Override public void run() {
            if (!vrExtractRunning) return;
            try {
                String[] p = VrExtractor.nativeProgress().trim().split(" ");
                int phase = Integer.parseInt(p[0]);
                long done = Long.parseLong(p[1]), total = Long.parseLong(p[2]);
                if (total > 0) {
                    int mark = vrLastLoggedMark;
                    String line = null;
                    if (phase == 0) {
                        int mb = (int) (done >> 20), totMb = (int) (total >> 20);
                        if (mb != mark) line = "extract: 下载 " + mb + "/" + totMb + " MB";
                    } else {
                        int pct = (int) (done * 100 / total);
                        if (pct != mark) line = "extract: 解包 " + pct + "%";
                    }
                    if (line != null) {
                        vrLastLoggedMark = phase == 0 ? (int) (done >> 20)
                                : (int) (done * 100 / total);
                        appendLog(line);
                    }
                }
            } catch (Exception ignored) {
            }
            mMain.postDelayed(this, 500);
        }
    };

    private void showVrExtractDialog() {
        if (vrExtractRunning) {
            Toast.makeText(this, "解析进行中…", Toast.LENGTH_SHORT).show();
            return;
        }
        CharSequence[] items = {"OTA 链接（zip / payload.bin 直链）", "选择本地 boot.img"};
        new androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("解析 Vr 偏移")
                .setItems(items, (d, which) -> {
                    if (which == 0) promptVrUrl();
                    else pickVrFile();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void promptVrUrl() {
        android.widget.EditText et = new android.widget.EditText(this);
        et.setHint("https://…（OTA zip 或 payload.bin 直链）");
        et.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        et.setSingleLine(true);
        int pad = (int) (getResources().getDisplayMetrics().density * 20);
        et.setPadding(pad, pad, pad, pad / 2);
        // No forced text color: the alert dialog surfaces from the DayNight
        // theme and can render light, where forced white text vanished.
        et.setText(prefs().getString("vr_ota_url", ""));
        new androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("OTA 链接")
                .setView(et)
                .setPositiveButton("解析", (d, w) -> {
                    String url = et.getText().toString().trim();
                    if (url.startsWith("http://") || url.startsWith("https://")) {
                        mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                                .edit().putString("vr_ota_url", url).apply();
                        runVrExtract(url);
                    } else {
                        Toast.makeText(this, "不是有效的 http(s) 链接",
                                Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private SharedPreferences prefs() {
        return mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
    }

    private void pickVrFile() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, REQ_VR_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_VR_FILE || resultCode != RESULT_OK
                || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        mExec.execute(() -> {
            try {
                File out = new File(getCacheDir(), "vr_input.bin");
                try (java.io.InputStream in = getContentResolver().openInputStream(uri);
                     FileOutputStream fo = new FileOutputStream(out)) {
                    byte[] buf = new byte[1 << 20];
                    int n;
                    while ((n = in.read(buf)) > 0) fo.write(buf, 0, n);
                }
                runVrExtract(out.getAbsolutePath());
            } catch (Exception e) {
                mMain.post(() -> appendLog("extract: 读取文件失败 - " + e.getMessage()));
            }
        });
    }

    /** Runs the extractor on the worker thread; logs progress lines and fills
     *  the funcs-offset input on success. */
    private void runVrExtract(String input) {
        if (vrExtractRunning) {
            mMain.post(() -> appendLog("extract: 已有解析任务在跑"));
            return;
        }
        vrExtractRunning = true;
        vrLastLoggedMark = -1;
        boolean url = input.startsWith("http://") || input.startsWith("https://");
        mMain.post(() -> {
            appendLog("extract: 开始解析 " + (url ? "OTA 链接" : "本地镜像"));
            mMain.postDelayed(vrProgressTick, 300);
        });
        mExec.execute(() -> {
            String json;
            try {
                json = VrExtractor.nativeDerive(
                        input, getCacheDir().getAbsolutePath(), false);
            } catch (Throwable t) {
                json = "{\"ok\":false,\"error\":\"native: " + t + "\"}";
            }
            String j = json;
            mMain.post(() -> {
                vrExtractRunning = false;
                mMain.removeCallbacks(vrProgressTick);
                handleVrResult(j);
            });
        });
    }

    private void handleVrResult(String json) {
        try {
            org.json.JSONObject o = new org.json.JSONObject(json);
            if (o.optBoolean("ok") && o.optLong("member", -1) > 0) {
                long member = o.getLong("member");
                String release = o.optString("release", "?");
                vrRefresh = true;
                binding.vrOffsetInput.setText(String.valueOf(member));
                saveVrOffset(String.valueOf(member));
                binding.vrOffsetInput.setTextColor(0xFFB9F6CA);
                vrRefresh = false;
                appendLog("extract: funcs 偏移=" + member + " (" + release + ")");
                Toast.makeText(this, "解析成功：funcs 偏移 " + member,
                        Toast.LENGTH_LONG).show();
                return;
            }
            appendLog("extract: 失败 - " + o.optString("error", "未知错误"));
        } catch (Exception e) {
            appendLog("extract: 失败 - 返回异常: " + json);
        }
    }

    private void applyModuleState(boolean on) {
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        SharedPreferences.Editor ed = sp.edit();
        if (on) ed.remove("disable_modules");
        else ed.putBoolean("disable_modules", true);
        ed.apply();
        binding.modulesSubtitle.setText(on
                ? "已启用 - 下次提权生效"
                : "已禁用 - 下次提权不加载模块");
        Toast.makeText(this,
                on ? "KSU 模块已启用 - 下次提权生效"
                        : "KSU 模块已禁用 - 下次提权生效",
                Toast.LENGTH_SHORT).show();
    }

    // ---- SU manager picker --------------------------------------------------

    /** One candidate: an app that actually ships libksud.so. */
    private static final class SuManagerEntry {
        final String packageName;
        final CharSequence label;

        SuManagerEntry(String pkg, CharSequence label) {
            this.packageName = pkg;
            this.label = label;
        }
    }

    /** Every installed app carrying libksud.so in its native lib dir - exactly
     *  the set ExploitRunner.stageAssets() can use, so anything listed here is
     *  guaranteed to pass the runtime check too. */
    private List<SuManagerEntry> scanSuManagers() {
        List<SuManagerEntry> out = new ArrayList<>();
        PackageManager pm = getPackageManager();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if (ai.packageName.equals(getPackageName())) continue;
            if (ai.nativeLibraryDir == null) continue;
            if (!new File(ai.nativeLibraryDir, "libksud.so").exists()) continue;
            out.add(new SuManagerEntry(ai.packageName, pm.getApplicationLabel(ai)));
        }
        out.sort((a, b) -> a.label.toString().compareToIgnoreCase(b.label.toString()));
        return out;
    }

    /** Restores the saved selection, dropping it if that app is gone or no
     *  longer ships libksud.so. */
    private void loadSuManagerPref() {
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        String saved = sp.getString("su_manager", null);
        suManagerPkg = null;
        suManagerLabel = null;
        if (saved != null) {
            for (SuManagerEntry e : scanSuManagers()) {
                if (e.packageName.equals(saved)) {
                    suManagerPkg = e.packageName;
                    suManagerLabel = e.label;
                    break;
                }
            }
            if (suManagerPkg == null) sp.edit().remove("su_manager").apply();
        }
        binding.suManagerSubtitle.setText(suManagerPkg == null
                ? "未选择 - 必需"
                : suManagerLabel + "  (" + suManagerPkg + ")");
        binding.suManagerSubtitle.setTextColor(suManagerPkg == null
                ? 0xFFE57373 : 0xFF9E9E9E);
    }

    /** OneUI-style rounded popup list over the dim overlay - same look and feel
     *  as the overflow menu, so the picker does not look like a stock spinner. */
    private void showSuManagerPopup() {
        float md = getResources().getDisplayMetrics().density;
        List<SuManagerEntry> apps = scanSuManagers();
        final android.widget.PopupWindow[] pwRef = {null};

        android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.popup_bg);
        box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

        if (apps.isEmpty()) {
            TextView none = new TextView(this);
            none.setText("未发现带 libksud.so 的应用");
            none.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            none.setPadding((int) (20 * md), (int) (12 * md), (int) (20 * md), (int) (12 * md));
            none.setTextColor(0xFF6E6E6E);
            none.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            box.addView(none);
        }

        for (SuManagerEntry e : apps) {
            android.widget.LinearLayout col = new android.widget.LinearLayout(this);
            col.setOrientation(android.widget.LinearLayout.VERTICAL);
            col.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            col.setBackgroundResource(R.drawable.menu_row_highlight);
            col.setPadding((int) (20 * md), 0, (int) (20 * md), 0);

            android.widget.LinearLayout line = new android.widget.LinearLayout(this);
            line.setOrientation(android.widget.LinearLayout.HORIZONTAL);
            line.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            TextView t = new TextView(this);
            t.setText(e.label);
            t.setTextColor(0xFFE8E8E8);
            t.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            line.addView(t, new android.widget.LinearLayout.LayoutParams(
                    0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            if (e.packageName.equals(suManagerPkg)) {
                android.view.View dot = new android.view.View(this);
                dot.setBackgroundResource(R.drawable.dot_white);
                android.widget.LinearLayout.LayoutParams dotLp =
                        new android.widget.LinearLayout.LayoutParams(
                                (int) (7 * md), (int) (7 * md));
                dotLp.setMargins((int) (7 * md), 0, 0, 0);
                line.addView(dot, dotLp);
            }
            col.addView(line, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (26 * md)));

            TextView sub = new TextView(this);
            sub.setText(e.packageName);
            sub.setTextColor(0xFF8E8E8E);
            sub.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
            col.addView(sub);

            col.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                selectSuManager(e);
                if (pwRef[0] != null) pwRef[0].dismiss();
            });
            box.addView(col, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (56 * md)));
        }

        box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
        int cardW = binding.cardSuManager.getWidth();
        int pw_w = cardW > 0 ? cardW : Math.max(box.getMeasuredWidth(), (int) (240 * md));

        final android.widget.PopupWindow pw = new android.widget.PopupWindow(box,
                pw_w, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, true);
        pw.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(
                android.graphics.Color.TRANSPARENT));
        pw.setOutsideTouchable(true);
        pwRef[0] = pw;
        pw.setOnDismissListener(() ->
                binding.dimOverlay.animate().alpha(0f).setDuration(150)
                        .withEndAction(() -> binding.dimOverlay
                                .setVisibility(View.GONE)).start());

        box.setOutlineProvider(new android.view.ViewOutlineProvider() {
            @Override
            public void getOutline(View view, android.graphics.Outline outline) {
                outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
            }
        });
        box.setClipToOutline(true);
        box.setElevation(48 * md);

        int[] loc = new int[2];
        binding.cardSuManager.getLocationOnScreen(loc);
        // Centered, NOT card-anchored: the popup is exactly card-wide and the
        // card sits 16dp from each edge, so half the leftover IS the card's own
        // margin. Anchoring to the card's left + 16dp pushed the popup 16dp
        // right, which read as off-centre and clipped its right edge.
        int x = (getResources().getDisplayMetrics().widthPixels - pw_w) / 2;
        int y = loc[1] + binding.cardSuManager.getHeight() + (int) (4 * md);
        binding.dimOverlay.setVisibility(View.VISIBLE);
        binding.dimOverlay.setAlpha(0f);
        binding.dimOverlay.animate().alpha(0.5f).setDuration(150).start();
        box.setPivotX(0f);
        box.setPivotY(0f);
        box.setScaleX(0.9f);
        box.setScaleY(0.9f);
        box.setAlpha(0f);
        pw.showAtLocation(binding.cardSuManager,
                android.view.Gravity.TOP | android.view.Gravity.START, x, y);
        box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                .setInterpolator(new android.view.animation.DecelerateInterpolator())
                .start();
    }

    /** Writes the DE pref that bootstrap.c reads as su_manager, then unlocks Run. */
    private void selectSuManager(SuManagerEntry e) {
        mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putString("su_manager", e.packageName).apply();
        suManagerPkg = e.packageName;
        suManagerLabel = e.label;
        binding.suManagerSubtitle.setText(e.label + "  (" + e.packageName + ")");
        binding.suManagerSubtitle.setTextColor(0xFF9E9E9E);
        updateRunButton();
    }

    /** Run needs a manager selected, no failed-run lock and no existing root. */
    private boolean canRun() {
        return suManagerPkg != null && !failedRun && !new File("/dev/df").exists();
    }

    /** Single place that decides the Run pill's look and enabled state. */
    private void updateRunButton() {
        if (running) return;
        if (new File("/dev/df").exists()) {
            setRootedState(true);
            return;
        }
        if (failedRun) {
            setFailedState();
            return;
        }
        boolean ok = suManagerPkg != null;
        binding.btnRun.setEnabled(ok);
        binding.btnRun.setText("开始提权");
        binding.btnRun.setTextColor(ok ? 0xFFE0E0E0 : 0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(ok ? 0xFF7A7A7A : 0xFF1F1F1F));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(ok ? 0xFFA6A6A6 : 0xFF1F1F1F));
    }

    /** SamSU-style GitHub release check: the pill around the version turns
     *  green when the latest published release tag differs from this build's
     *  versionName. Silent on offline / rate-limit / API hiccups. */
    private void checkForAppUpdate() {
        try {
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                    new java.net.URL("https://api.github.com/repos/DONGDERS/DirtyFalg-vr/releases/latest")
                            .openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", "DirtyFrag");
            if (conn.getResponseCode() != 200) return;
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream()));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) body.append(line);
            reader.close();
            String tag = new org.json.JSONObject(body.toString()).optString("tag_name", "");
            if (tag.isEmpty()) {
                Log.i(TAG, "update check: empty tag_name");
                return;
            }
            String latest = tag.replaceFirst("^[vV]", "").trim();
            String mine;
            try {
                mine = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            } catch (Exception e) {
                return;
            }
            if (latest.equalsIgnoreCase(mine)) return;
            Log.i(TAG, "update check: update available (latest=" + latest + ")");
            mMain.post(() -> {
                updateAvailable = true;
                // Grow the pill from its left edge into the lime update state,
                // same 250ms feel as the Run pill's shrink.
                if (titleView != null) {
                    android.animation.ValueAnimator a =
                            android.animation.ValueAnimator.ofFloat(0f, 1f);
                    a.setDuration(250);
                    a.addUpdateListener(anim -> {
                        pillSpan.setProgress((float) anim.getAnimatedValue());
                        titleView.invalidate();
                    });
                    a.start();
                } else {
                    pillSpan.setProgress(1f);
                }
            });
        } catch (Exception e) {
            Log.i(TAG, "update check failed: " + e);
        }
    }

    /** Failure presentation: left bar label "失败", right label "请重启",
     *  bars + labels red, run pill greyed out like the Running/Rooted state.
     *  The pill stays disabled because the vendor patch is page-cache only:
     *  retrying without rebooting would fail the same way. */
    private void setFailedState() {
        failedRun = true;
        binding.twoStep.setFailed(true);
        binding.twoStep.setSeg1(seg1, "失败");
        binding.twoStep.setSeg2(1f, "请重启", 0xFFE57373);
        binding.btnRun.setEnabled(false);
        binding.btnRun.setText("开始提权");
        binding.btnRun.setTextColor(0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
        setCompactButton(false, false);
    }

    private void setRootedState(boolean rooted) {
        runArmed = false;
        // Not rooted does not mean runnable: the manager still has to be picked
        // and a failed run locks the pill until reboot.
        boolean ok = !rooted && canRun();
        int fg = (rooted || !ok) ? 0xFF6E6E6E : 0xFFE0E0E0;
        int bg = (rooted || !ok) ? 0xFF1F1F1F : 0xFF7A7A7A;
        int stroke = (rooted || !ok) ? 0xFF1F1F1F : 0xFFA6A6A6;
        binding.btnRun.setEnabled(ok);
        binding.btnRun.setText(rooted ? "已 Root" : "开始提权");
        binding.btnRun.setTextColor(fg);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(bg));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(stroke));
        // Rooted/running: shrink the pill left and pop the KSU circle next to
        // it (lit when rooted); fresh run state: full-width pill, no circle.
        setCompactButton(rooted, rooted);
    }

    /** Shrinks the main pill to the left and pops the KSU launcher circle
     *  next to it (compact=true, ksuLit=lit after successful root), or
     *  restores the full-width pill. */
    private void setCompactButton(boolean compact, boolean ksuLit) {
        // Fresh pill: 48% wide starting at the 26% guideline → right edge at
        // 74%. Compact: pill + 12dp gap + 54dp circle must occupy the same
        // 48% total (left edge pinned), so pill = 48% - extras.
        float parentW = ((View) binding.btnRun.getParent()).getWidth();
        if (parentW <= 0) parentW = getResources().getDisplayMetrics().widthPixels;
        float density = getResources().getDisplayMetrics().density;
        float target = 0.48f;
        if (compact) {
            float extrasPx = (KSU_GAP_DP + KSU_CIRCLE_DP) * density;
            target = Math.max(0.20f, 0.48f - extrasPx / parentW);
        }
        android.animation.ValueAnimator a =
                android.animation.ValueAnimator.ofFloat(pillPercent, target);
        a.setDuration(250);
        a.addUpdateListener(anim -> {
            pillPercent = (float) anim.getAnimatedValue();
            androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                    (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                            binding.btnRun.getLayoutParams();
            lp.matchConstraintPercentWidth = pillPercent;
            binding.btnRun.setLayoutParams(lp);
        });
        a.start();
        // The launcher pill ends up exactly as wide as the shrunken Run pill
        // (measured off the user's mockups: 331 vs 332 px on the S25), which is
        // what fills the old 100dp right-hand deadzone and mirrors the share
        // circle on the left.
        int ksuPillPx = (int) (target * parentW);
        int ksuCirclePx = (int) (KSU_CIRCLE_DP * density);
        binding.btnKsu.setEnabled(ksuLit);
        boolean wasVisible = binding.btnKsu.getVisibility() == View.VISIBLE
                && binding.btnKsu.getAlpha() > 0.99f;
        binding.btnKsu.setBackgroundTintList(ColorStateList.valueOf(
                ksuLit ? 0xFFB0B0B0 : 0xFF1F1F1F));
        // Dark ink on the lit pill, mid-grey on the unlit one - same grey as
        // the share glyph.
        binding.ksuChevron.setImageTintList(ColorStateList.valueOf(
                ksuLit ? 0xFF1F1F1F : 0xFF6E6E6E));
        if (compact && !wasVisible) {
            // First appearance: pop in as a circle. The morph is chained to the
            // pop-in's end so the Run pill has already finished shrinking - its
            // right edge is the launcher's start anchor, so the launcher's left
            // edge must be stable before we animate the width.
            setKsuWidth(ksuCirclePx);
            binding.ksuLabel.setAlpha(0f);
            binding.btnKsu.setVisibility(View.VISIBLE);
            binding.btnKsu.setAlpha(0f);
            binding.btnKsu.setScaleX(0.6f);
            binding.btnKsu.setScaleY(0.6f);
            binding.btnKsu.postDelayed(() -> binding.btnKsu.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180)
                    .withEndAction(() -> {
                        settleKsuTint(ksuLit);
                        morphKsuToPill(ksuLit, ksuPillPx, ksuCirclePx);
                    }).start(), 150);
        } else if (compact) {
            // Already visible (state change): stay in place, recolor + grow.
            settleKsuTint(ksuLit);
            morphKsuToPill(ksuLit, ksuPillPx, ksuCirclePx);
        } else {
            binding.ksuLabel.animate().alpha(0f).setDuration(150).start();
            binding.btnKsu.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f)
                    .setDuration(200)
                    .withEndAction(() -> {
                        binding.btnKsu.setVisibility(View.GONE);
                        setKsuWidth(ksuCirclePx);
                    })
                    .start();
        }
    }

    /** After the lit circle settles, ease it slightly towards grey. */
    private void settleKsuTint(boolean ksuLit) {
        if (!ksuLit) return;
        android.animation.ValueAnimator g =
                android.animation.ValueAnimator.ofFloat(0f, 1f);
        g.setStartDelay(250);
        g.setDuration(300);
        g.addUpdateListener(anim -> binding.btnKsu
                .setBackgroundTintList(ColorStateList.valueOf(
                        mixColor(0xFFB0B0B0, 0xFF9A9A9E,
                                (float) anim.getAnimatedValue()))));
        g.start();
    }

    /** Circle -> pill (or back): width only, left edge pinned, 250ms
     *  Decelerate - the same one-axis / one-side feel as the Run pill's
     *  shrink. The label fades in as the pill opens up. */
    private void morphKsuToPill(boolean lit, int pillPx, int circlePx) {
        int from = binding.btnKsu.getWidth();
        int to = lit ? pillPx : circlePx;
        if (from <= 0 || from == to) return;
        if (ksuMorph != null && ksuMorph.isRunning()) ksuMorph.cancel();
        ksuMorph = android.animation.ValueAnimator.ofInt(from, to);
        ksuMorph.setDuration(250);
        ksuMorph.setInterpolator(
                new android.view.animation.DecelerateInterpolator());
        ksuMorph.addUpdateListener(
                anim -> setKsuWidth((int) anim.getAnimatedValue()));
        // One final re-layout after the last width frame: the label and the
        // chevron are positioned by the FrameLayout, and a mid-morph width can
        // leave them stale (seen on device: the label stayed at the circle's
        // left edge instead of moving into the pill). ValueAnimator has no
        // withEndAction - that is ViewPropertyAnimator's API.
        ksuMorph.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                binding.btnKsu.requestLayout();
            }
        });
        ksuMorph.start();
        binding.ksuLabel.animate().alpha(lit ? 1f : 0f)
                .setStartDelay(lit ? 120 : 0).setDuration(220).start();
    }

    /** The launcher's animated width. layout_constraintHorizontal_bias="0"
     *  welds its left edge to the Run pill while the right edge travels. */
    private void setKsuWidth(int px) {
        androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                        binding.btnKsu.getLayoutParams();
        lp.width = px;
        binding.btnKsu.setLayoutParams(lp);
    }

    /** Opens the SU manager that is actually selected - pre-3.2 this walked a
     *  hardcoded package list that no longer matches reality. */
    private void openKsu() {
        if (suManagerPkg == null) {
            Toast.makeText(this, "未选择 SU 管理器", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent launch = getPackageManager().getLaunchIntentForPackage(suManagerPkg);
        if (launch == null) {
            Toast.makeText(this, suManagerPkg + " cannot be launched",
                    Toast.LENGTH_SHORT).show();
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(launch);
    }

    private static int mixColor(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF;
        int br = (b >> 16) & 0xFF, bg = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000
                | (Math.round(ar + (br - ar) * t) << 16)
                | (Math.round(ag + (bg - ag) * t) << 8)
                | Math.round(ab + (bb - ab) * t);
    }

    /** Saves the current log to Downloads and opens the Downloads screen. */
    private void shareLog() {
        String log = logBuffer.length() > 0 ? logBuffer.toString() : readLastLog();
        if (log.trim().isEmpty()) {
            return;
        }
        try {
            ContentValues values = new ContentValues();
            values.put(MediaStore.Downloads.DISPLAY_NAME, "dirtyfrag_log.txt");
            values.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
            Uri uri = getContentResolver().insert(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri != null) {
                try (java.io.OutputStream out = getContentResolver().openOutputStream(uri)) {
                    out.write(log.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "save log failed", e);
        }
        try {
            startActivity(new Intent(android.app.DownloadManager.ACTION_VIEW_DOWNLOADS));
        } catch (Exception e) {
            Log.e(TAG, "open downloads failed", e);
        }
    }

    private void runExploit() {
        // bootstrap.c reads soft_reboot straight out of the DE prefs, so mirror
        // the Autorun card's choice into the key it reads right before launch.
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        boolean autoSoftReboot = sp.getBoolean("auto_soft_reboot", false);
        sp.edit().putBoolean("soft_reboot", autoSoftReboot).apply();
        lastFailReason = null;
        try {
            int rc = ExploitRunner.run(mDeCtx, this);
            if (rc != 0) {
                // 0 ok, 1 ksud/bootstrap error, 2 poll timeout or bad setup,
                // 3 failed to patch files (see exp.c markers[]).
                String why = lastFailReason != null ? lastFailReason
                        : rc == 1 ? "ksud nonzero exit"
                        : rc == 2 ? "check logcat & dmesg"
                        : "failed to patch files";
                // The "=== exploit failed ===" line is protocol: state restore
                // greps for it. The Chinese block below is display-only.
                report("\n=== exploit failed: " + why + " ===\n");
                report("\n失败原因：" + zhFailReason(why)
                        + "\n" + zhFailAdvice(why) + "\n");
            } else {
                report("\n提权成功：内核模块已装载，SU 守护进程已启动。\n"
                        + "说明：本次 root 为临时性，重启后自动恢复原状。\n");
            }
            mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", rc == 0).apply();
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\nexception: " + e + "\n");
            report("\n失败原因：运行异常（" + e.getClass().getSimpleName() + "）\n"
                    + "建议：重启手机后重试；反复失败请保存运行日志反馈\n");
        } finally {
            mMain.post(() -> {
                running = false;
                boolean rooted = new File("/dev/df").exists();
                if (rooted) {
                    setRootedState(true);
                    binding.twoStep.setSeg2(1f, "已验证", 0xFFFFFFFF);
                } else {
                    setFailedState();
                    setRootedState(false);
                }
                updateLogVisibility();
            });
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Toast.makeText(this, "未找到浏览器", Toast.LENGTH_SHORT).show();
        }
    }

}
