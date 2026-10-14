//! Host smoke test: run the same pipeline as the JNI entry against a local
//! boot.img / payload.bin / OTA file or URL. Not shipped in the APK; also
//! handy as a desktop debug tool.
//!
//!   cargo run --features http --bin vrext-cli -- <input> [work_dir]

use std::sync::Arc;
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let input = args.next().unwrap_or_else(|| {
        eprintln!("usage: vrext-cli <boot.img|payload.bin|OTA.zip|URL> [work_dir]");
        std::process::exit(2);
    });
    let work = args.next().unwrap_or_else(|| "/tmp".into());
    let started = Instant::now();
    let json = vrext::derive_json(&input, &work, false, Some(Arc::new(|phase, done, total| {
        eprintln!("progress: phase={phase} {done}/{total}");
    })));
    println!("{json}");
    eprintln!("elapsed: {:.1}s", started.elapsed().as_secs_f32());
}
