//! vr offset extractor: recover the W1c write target
//! (`__tracepoint_sys_exit->funcs`, as a member offset inside
//! `struct tracepoint`, e.g. 72 for the 6.6.89-android15-8 profile) from a
//! boot.img / payload.bin / OTA source.
//!
//! The engine is GhostLock's own extractor (tools/extract_rs), used as a path
//! dependency; this crate only wires the input plumbing (boot image vs
//! payload.bin vs OTA ZIP, local file vs HTTP URL) and reports JSON.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

/// Progress callback: `(phase, done, total)` where phase is 0 = download,
/// 1 = extraction. Units are bytes for phase 0, operations for phase 1.
pub type ProgressFn = dyn Fn(u32, u64, u64) + Sync + Send;

/// Run the whole pipeline. `input` is a boot.img / payload.bin / OTA ZIP path,
/// or an http(s) URL to any of those. Returns a JSON object:
///   { "ok": true, "member": 72, "abs": 36315432, "tp": 36315360,
///     "funcs_off": 72, "release": "6.6.89-..." }
/// or { "ok": false, "error": "..." }.
pub fn derive_json(
    input: &str,
    work_dir: &str,
    insecure: bool,
    progress: Option<Arc<ProgressFn>>,
) -> String {
    match run(input, work_dir, insecure, progress) {
        Ok(v) => v.to_string(),
        Err(err) => {
            serde_json::json!({ "ok": false, "error": format!("{err:#}") }).to_string()
        }
    }
}

fn run(
    input: &str,
    work_dir: &str,
    insecure: bool,
    progress: Option<Arc<ProgressFn>>,
) -> anyhow::Result<serde_json::Value> {
    let work = PathBuf::from(work_dir).join("vrext");
    std::fs::create_dir_all(&work).with_context(|| format!("mkdir {}", work.display()))?;

    // ---- 1) obtain a boot image file path -----------------------------
    let boot_path: PathBuf = if ghostlock_extract::payload::looks_like_payload(input) {
        let want = vec!["boot".to_string()];
        let cb: Option<payload_extract::input::ProgressCallback> = progress.map(|p| {
            Arc::new(move |done: u64, total: u64| p(0, done, total))
                as payload_extract::input::ProgressCallback
        });
        let view = payload_extract::input::open_for_extract_with(
            input,
            &want,
            &payload_extract::input::OpenOptions {
                insecure,
                temp_dir: Some(work.clone()),
                download_progress: cb,
                ..Default::default()
            },
        )?;
        let produced = ghostlock_extract::payload::extract_partitions(&view, &work, &want)?;
        produced
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("payload produced no boot image"))?
    } else {
        PathBuf::from(input)
    };

    // ---- 2) parse the boot image, decompress the kernel ---------------
    let boot = BootImage::load(&boot_path)?;
    let btf_at = boot.embedded_btf_at();
    let btf = match &btf_at {
        Some((_, blob)) => Some(Btf::new(blob)?),
        None => None,
    };

    // ---- 3) recover the embedded kallsyms table (no root needed) ------
    let ks = kallsyms_finder::recover(
        &boot.kernel,
        btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len())),
    )
    .map_err(|err| anyhow::anyhow!("kallsyms: {err}"))?;
    let symbols = ks.symbols;

    let base = kallsyms::unique(&symbols, "_text")
        .or_else(|| kallsyms::unique(&symbols, "_head"))
        .ok_or_else(|| anyhow::anyhow!("_text/_head is not unique in kallsyms"))?;
    let (rel_symbols, sorted_offsets) = relative_symbols(&symbols, base);

    // ---- 4) derive the funcs field address from the iterator code -----
    let abs = derive_sys_exit_tp_funcs(&boot.kernel, &rel_symbols, &sorted_offsets, btf.as_ref())
        .map_err(|err| anyhow::anyhow!("derive: {err}"))?;

    // ---- 5) convert to a member offset ---------------------------------
    // Prefer the real symbol from kallsyms (GKI KALLSYMS_ALL carries data
    // symbols); fall back to the derivation's own struct base (funcs_off
    // from BTF, else the extractor's 0x48 default).
    let funcs_off = btf
        .as_ref()
        .and_then(|b| b.field("tracepoint", "funcs"))
        .unwrap_or(0x48);
    let tp = kallsyms::unique(&symbols, "__tracepoint_sys_exit")
        .map(|v| v.wrapping_sub(base))
        .or_else(|| abs.checked_sub(u64::from(funcs_off)))
        .ok_or_else(|| anyhow::anyhow!("cannot locate __tracepoint_sys_exit"))?;
    let member = abs.checked_sub(tp).ok_or_else(|| {
        anyhow::anyhow!("funcs field precedes tracepoint struct ({abs:#x} < {tp:#x})")
    })?;
    if member == 0 || member > 0x100 {
        anyhow::bail!("implausible funcs member offset {member} (abs {abs:#x}, tp {tp:#x})");
    }

    let mut out = serde_json::json!({
        "ok": true,
        "member": member,
        "abs": abs,
        "tp": tp,
        "funcs_off": funcs_off,
    });
    if let Some(release) = boot.release() {
        out["release"] = serde_json::Value::String(release);
    }
    Ok(out)
}

use ghostlock_extract::btf::Btf;
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{derive_sys_exit_tp_funcs, relative_symbols};
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

// ---- JNI surface (Android only) -------------------------------------------
#[cfg(target_os = "android")]
mod jni {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::ProgressFn;
    use jni::objects::{JClass, JString};
    use jni::sys::jboolean;
    use jni::JNIEnv;

    use super::derive_json;

    /// Latest progress triplet, mirrored into Java so the UI can show it.
    static PROG_PHASE: AtomicU64 = AtomicU64::new(0);
    static PROG_DONE: AtomicU64 = AtomicU64::new(0);
    static PROG_TOTAL: AtomicU64 = AtomicU64::new(0);

    /// Called from Java on a poller thread: "phase done total", phase
    /// 0 = download (bytes), 1 = extraction (ops). Returned as a plain
    /// string to keep the native surface trivial to parse.
    #[no_mangle]
    pub extern "system" fn Java_df_root_VrExtractor_nativeProgress<'local>(
        env: JNIEnv<'local>,
        _class: JClass,
    ) -> JString<'local> {
        let s = format!(
            "{} {} {}",
            PROG_PHASE.load(Ordering::Relaxed),
            PROG_DONE.load(Ordering::Relaxed),
            PROG_TOTAL.load(Ordering::Relaxed)
        );
        let j = env
            .new_string(s)
            .or_else(|_| env.new_string("0 0 0"))
            .map(JString::from);
        match j {
            Ok(v) => v,
            Err(e) => panic!("jni new_string failed twice: {e}"),
        }
    }

    /// Derive the vr funcs member offset. `input` = path or URL, `work_dir`
    /// = app cacheDir, `insecure` = skip TLS verification. Returns JSON.
    #[no_mangle]
    pub extern "system" fn Java_df_root_VrExtractor_nativeDerive<'local>(
        env: JNIEnv<'local>,
        _class: JClass,
        input: JString<'local>,
        work_dir: JString<'local>,
        insecure: jboolean,
    ) -> JString<'local> {
        let input: String = env.get_string(&input).map(|s| s.into()).unwrap_or_default();
        let work: String = env
            .get_string(&work_dir)
            .map(|s| s.into())
            .unwrap_or_else(|_| "/data/local/tmp".into());
        let progress: Option<Arc<ProgressFn>> = Some(Arc::new(
            |phase, done, total| {
                PROG_PHASE.store(phase as u64, Ordering::Relaxed);
                PROG_DONE.store(done, Ordering::Relaxed);
                PROG_TOTAL.store(total, Ordering::Relaxed);
            },
        ));
        let json = derive_json(&input, &work, insecure == 1, progress);
        let j = env
            .new_string(json)
            .or_else(|_| {
                env.new_string(r#"{"ok":false,"error":"jni new_string failed"}"#)
            })
            .map(JString::from);
        match j {
            Ok(v) => v,
            Err(e) => panic!("jni new_string failed twice: {e}"),
        }
    }
}
