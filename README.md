# DirtyFrag-vr (CVE-2026-43284)

**A vivo/MTK-hardened build of [mitschud/DirtyFrag](https://github.com/mitschud/DirtyFrag), which is itself a hardened fork of [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot).**

DirtyFrag exploits **CVE-2026-43284 (DirtyFrag)**, a kernel page-cache write primitive, to load a
kernel module on a **locked bootloader and a stock kernel** — no unlock, no custom kernel, no
flashing. This fork takes the upstream 1.16 engine and grafts on the **vivo `vr.ko` disarm stack**
(the anti-root module that otherwise kills KernelSU-family managers), BTF-based automatic offset
resolution, and a crash-proof kernel-log follower.

> [!IMPORTANT]
> Root is **ephemeral**. The kernel module, `su` and any loaded modules are gone the moment the
> device reboots. A reboot always returns the phone to a clean, unrooted state — which is also the
> recovery path if a run goes wrong.

## What this fork adds over upstream

This build is based on mitschud DirtyFrag **v1.16** (upstream DFRoot 4.2–4.5 engine). Everything
below is original work on top of that base.

### 1. vivo `vr.ko` disarm (W1c)

vivo ships `vr.ko`, a vendor anti-root module that watches for root activity and tears down
KernelSU-family managers. This fork disarms it instead of fighting it:

- The kernel module walks the **`sys_exit` tracepoint** and clears the probe vivo registered
  against it, so `vr.ko` stops observing process exits and loses its detection trigger.
- The write target is `__tracepoint_sys_exit->funcs`, addressed as a **member offset of
  `struct tracepoint`** — the offset differs per KMI, which is why it is resolved, not hardcoded.
- **BTF auto-resolve**: `dfroot.ko` reads `/sys/kernel/btf/vmlinux` itself and derives that
  offset at run time, in chunked reads so large BTF blobs do not blow the allocation. You do not
  need to know your KMI.
- **Manual override**: if auto-resolve fails, the UI exposes a raw offset field and the onboarding
  extractor below can compute it for you. `exp.c` accepts both (`auto` or an explicit decimal/hex
  value) and logs which path it took.
- **Abort chain**: if the tracepoint or the offset does not match, the run aborts cleanly and
  reports `W1c FAILED - tracepoint/offset mismatch, vr intact` rather than proceeding into a
  half-patched state.

### 2. Offset extractor (app-side, `/libvrext.so`)

A Rust `cdylib` bridged through `VrExtractor.java`. Point it at a **`boot.img`, `payload.bin` or
an OTA ZIP** — a local path or an `http(s)` URL — and it:

1. recovers the embedded **kallsyms** from the image,
2. **disassembles `__traceiter_sys_exit`**,
3. derives the `__tracepoint_sys_exit->funcs` member offset for your exact kernel
   (e.g. `72` on `6.6.89-android15-8`).

URL mode downloads **only the boot partition**, via ranged requests. `derive()` blocks and runs on
a background thread; progress is polled as `phase done total`. This is what makes the feature
usable without a PC and without knowing your offset in advance.

### 3. Crash-proof logging (`kmsglog` + `RunLog`)

Two independent log paths, both designed around the case where the device wedges mid-run:

- **`kmsglog.c`** — a persistent `/dev/kmsg` follower spawned from the module init at
  `UMH_WAIT_EXEC` time (root, permissive). It appends **message by message with a per-line
  `fsync`**, so anything the kernel prints reaches disk within milliseconds and survives a watchdog
  hard reset that would take the page cache and pstore with it. A `/dev/dfkmsg` tmpfs mutex keeps
  it to one follower per boot; a file-size cap and a wall-clock lifetime bound its growth.
- **`RunLog.java`** — every report line from **both** run chains (app button *and* boot autorun)
  lands here, line-synchronous and fsynced, written through MediaStore to the public Downloads
  folder. A panic mid-run cannot eat the lines that led up to it.

This matters because pstore is structurally absent on some of these devices — without it there is
no record of the lead-up to a hang.

### 4. UI work

- **`HomeScrollView`** — the run log lives inside the home scroller and has its own; a plain outer
  `ScrollView` would steal every vertical drag. A press landing in the log window is handed over
  untouched for the whole gesture.
- **`VersionPillSpan`** — the version digits in the header are a `ReplacementSpan`: a compact grey
  pill normally, growing from its left edge into a lime **Update available** pill when a newer
  release exists.
- **Chinese run logs** for the main report lines, alongside the English originals.

### 5. Build and release

- **8 prebuilt GKI KMIs committed** under `app/src/main/jni/ko/`, rebuilt for 1.16-vr with the vr
  config slot, CI-verified (magic ×8): `android12-5.10`, `android13-5.10`, `android13-5.15`,
  `android14-5.15`, `android14-6.1`, `android15-6.6`, `android16-6.12`, `android17-6.18`.
- Because they are committed, a plain clone builds **without a DDK toolchain**. Rebuild them
  whenever `lkm/dfroot.c` changes (see [Building](#building)).

| | upstream mitschud v1.16 | this fork (1.16-vr) |
|---|---|---|
| `lkm/dfroot.c` | 7.6 KB | **19.0 KB** |
| Prebuilt `.ko` | CI-only, gitignored | **8 KMIs committed** |
| Kernel-log follower | — | `kmsglog` (per-line fsync) |
| App-side extractor | — | `libvrext.so` (Rust) |
| vivo `vr.ko` handling | — | **W1c disarm + BTF auto-resolve** |
| Version | 1.16 | **1.16-vr (46)** |

## Install

1. Install the DirtyFrag-vr APK from [**Releases**](https://github.com/DONGDERS/DirtyFalg-vr/releases/latest).
2. Install an SU manager that **ships `libksud.so`**:
   - [KernelSU](https://github.com/tiann/KernelSU/releases/latest)
   - [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)
   - [KowSU](https://github.com/KOWX712/KernelSU/releases/latest)
   - [BakaSU](https://github.com/Baka-SU/BakaSU/releases/latest) (formerly ReSukiSU)
   - Samsung: **required** — [diabl0w's KernelSU](https://github.com/diabl0w/KernelSU/releases)
3. Open DirtyFrag-vr, pick your manager in the **SU Manager** card, then press **Run exploit**.

> [!WARNING]
> Since 1.10 (upstream 3.2) DirtyFrag no longer bundles `ksud` — it is staged from the selected
> manager's own `libksud.so`. A manager that does not ship that library cannot give you root. The
> older advice to install a CI / Actions build of the manager no longer applies.

A fresh install of DirtyFrag-vr gets a new Android UID, so the grant in the manager has to be given
again after every reinstall.

## Features

- Choose your SU manager inside the app
- **Autorun** (start on boot), gated behind Expert mode, with a failed-run interlock that disables
  itself after a failed attempt so a bad run cannot boot-loop you
- **Auto reboot** (soft reboot) — since 1.11 (upstream 4.1) this works with every KernelSU
  derivative: `dfroot.ko` is unloaded after late-load and ksud's own `soft-reboot` is run
- **KernelSU Modules** on/off — works without root, applied by the kernel module before ksud starts
- RO Partition Protection
- Advanced log, with one tap to save it to Downloads
- **Odin** pill in the toolbar: its dot says whether this firmware will let the device into download mode, and
  tapping it opens the three facts that decision is made from
- When a newer release is published, the headline itself becomes a lime **Update** pill — one tap from the release
- Shizuku not needed
- **[This fork]** **Vr disarm (W1c)** switch with automatic BTF offset resolution and a manual
  offset override
- **[This fork]** **Boot-image offset extractor** — feed it a `boot.img` / `payload.bin` / OTA ZIP
  (local or URL) and it derives the offset for you
- **[This fork]** **Crash-proof kernel log** — per-line fsynced `/dev/kmsg` follower, survives a
  watchdog reset
- **[This fork]** Chinese run-log lines alongside English

## FAQ

**Q: Log says patching failed and that my device isn't vulnerable**
A: Sorry, there is no fix. Either:
  - your device's kernel is too new
  - your device manufacturer backported the official mitigation
  - [accidental mitigation](https://github.com/V4bel/dirtyfrag/issues/23#issuecomment-4405314290)
    (typically seen on kernel 6.1)

**Q: Log says "SUCCESS" or "ksud exited with error", but I don't have root**
A: Turn off **Auto reboot** on the Autorun card if it is enabled — a soft reboot that the manager
cannot complete leaves the loaded module unloaded again. Otherwise see
[upstream discussion 69](https://github.com/diabl0w/DFRoot/discussions/69).

**Q: I installed a module and now I can't launch root without crashing**
A: Set the **KernelSU Modules** card to Disabled and reroot. The switch works without root, which is
the point — it is the escape hatch when a module is the thing that is crashing the run.

**Q: Module + Autorun and now I am bootlooping**
A: Android usually detects the bootloop and offers Safe Mode; otherwise hold **Volume Down** during
boot. From Safe Mode turn Autorun off and set KernelSU Modules to Disabled, or just uninstall
DirtyFrag until you stabilise. If you cannot get far enough into the system, `adb uninstall df.root`
from any PC works on user builds without root.

**Q: The progress bar sits at 0 percent**
A: That is the app's log-marker mapping, not the exploit. The run window is 70 seconds — do not
re-run a "slow" run, the daemon may still be working.

**Q: How do I remove root cleanly?**
A: Before unrooting, use file manager with root and delete /data/adb/ (KernelSU, KSUD residue)

**Q: [This fork] Vr auto-resolve failed — what do I do?**
A: Two paths. Either turn the automatic resolve off and paste the offset from the onboard extractor
(**Vr disarm → extract**, point it at your `boot.img` / `payload.bin` / OTA ZIP), or leave it off
entirely and run again — the `vr` stage is then skipped and root proceeds as it does upstream,
subject to `vr.ko` interfering as usual. The advanced log states which path was taken
(`auto-resolve` or `funcs offset provided`) and aborts with
`W1c FAILED - tracepoint/offset mismatch` if the write did not land.

**Q: [This fork] Where is the kernel log if the device hard-resets?**
A: In the public **Downloads** folder. `kmsglog` writes message by message with a per-line
`fsync`, so the last line on disk marks the entry point of the hang. This is the only witness on
devices where pstore is absent.

## Building

```sh
JAVA_HOME="<Android Studio jbr>" ./gradlew assembleRelease
```

The APK is written to `app/build/outputs/apk/release/dirtyfrag.apk`.
Release builds are signed with `app/keystore.jks`, which is gitignored (the signing config expects
alias `dirtyfrag` and `dirtyfrag` for both passwords). Generate your own before building:

```sh
keytool -genkeypair -v -keystore app/keystore.jks -alias dirtyfrag \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass dirtyfrag -keypass dirtyfrag
```

The eight prebuilt kernel modules are committed under `app/src/main/jni/ko/`. Upstream gitignores
them and builds them per-KMI in CI; this fork commits them so a plain clone builds without a DDK
toolchain. They are built by this repo's `Build` workflow (the `LKMs / <kmi>` jobs) from the
current `lkm/dfroot.c`, so they must be rebuilt whenever that file changes: run the workflow,
download the `df-lkm-<kmi>` artifacts and drop them in this directory. To build them yourself
instead, use upstream's `make` / podman DDK flow.

The app-side extractor is a separate Rust crate under `app/src/main/jni/vrext/` (built as
`libvrext.so` via the NDK toolchain in `CMakeLists.txt`).

## How it works

The Android kernel decrypts AES-CBC ESP packets directly into the page cache of files open for
`splice()`. By crafting `IV = AES_ECB_DEC(key, current_content) XOR desired_content`, any
16-byte-aligned block in a mapped shared library can be overwritten without write permission and
without copy-on-write.

The exploit uses this primitive to patch shellcode into `libc++.so` in the kernel's page cache. The
next privileged call to the hooked function runs the shellcode, which loads the kernel module via
`insmod`.

### Exploit chain

1. **IpSec transform** — the app allocates a `UdpEncapsulationSocket` plus an SPI and builds an
   AES-CBC/HMAC-SHA256 ESP transform through `IpSecManager`.
2. **splicehelper -> crash_dump64** — splicehelper is spliced into `crash_dump64` using the CBC
   primitive. `crash_dump64` runs in the `crash_dump` SELinux domain, which can open `vendor_file`
   labelled files that `untrusted_app` cannot read — the bridge we need.
3. **dfroot.ko -> vendor_file** — the kernel module is written through that bridge into a
   `vendor_file`-labelled file.
4. **libc++ hook** (fires in init, uid=0, tid=1) — shellcode patched at
   `std::ostream::sentry::sentry()`. It checks uid and tid, creates `/dev/df` as a one-shot mutex so
   it cannot re-enter, then execs `insmod` in the `vendor_modprobe` domain.
5. **dfroot.ko init** — sets SELinux permissive, bypasses DEFEX via kprobes where present, then uses
   `call_usermodehelper` to run the bootstrap.
6. **bootstrap** — reads the app's device-protected settings, adopts the zygote environment, sets
   partitions read-only, optionally disables all modules, and finally launches the SU daemon from
   your installed SU manager.

### The vr step (this fork)

Before root is handed over, `dfroot.ko` optionally runs an extra stage: it locates
`__tracepoint_sys_exit`, resolves the `funcs` member offset (from BTF at run time, or from the value
`exp.c` passed in), and clears the probe slot that `vr.ko` installed.
With the probe gone, `vr.ko` no longer observes process exits and cannot trigger its teardown path
against the manager. If the tracepoint or offset does not match, the stage aborts and reports it —
the root path is not left half-patched.

## Credits

- Upstream project and exploit chain: https://github.com/diabl0w/DFRoot
- DirtyFrag engine base (v1.16, DFRoot 4.2–4.5): https://github.com/mitschud/DirtyFrag
- Original PoC and various code: https://github.com/lsposed/lspromise
- SELinux permissive kernel modules and various code: https://github.com/polygraphene/DFReroot
- Unprivileged XFRM socket method: https://github.com/combeng6th/DirtyInit
- vr offset extractor engine: this project's Ghostlock-vr toolchain

## License

本项目使用 [GNU General Public License v2.0](LICENSE)，继承自上游
[diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)（GPL-2.0）。
This project is licensed under the [GNU General Public License v2.0](LICENSE),
inherited from [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot).