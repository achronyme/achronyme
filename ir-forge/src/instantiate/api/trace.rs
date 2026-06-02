pub(super) fn lysis_drain_trace_enabled() -> bool {
    std::env::var("ACH_LYSIS_TRACE").is_ok()
}

pub(super) fn positive_usize_or_default(value: Option<&str>, default: usize) -> usize {
    value
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

pub(super) fn lysis_malloc_trim_enabled() -> bool {
    std::env::var("ACH_LYSIS_MALLOC_TRIM").as_deref() == Ok("1")
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) fn trim_process_allocator() -> bool {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    unsafe { malloc_trim(0) != 0 }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(super) fn trim_process_allocator() -> bool {
    false
}

pub(super) fn lysis_drain_trace(stage: &str, fields: &str) {
    let (rss_kib, vmsize_kib) = lysis_process_mem_kib().unwrap_or((0, 0));
    eprintln!("[lysis-drain] {stage} rss_kib={rss_kib} vmsize_kib={vmsize_kib} {fields}");
}

pub(super) fn lysis_process_mem_kib() -> Option<(u64, u64)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut rss = None;
    let mut vmsize = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss = rest.split_whitespace().next()?.parse::<u64>().ok();
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            vmsize = rest.split_whitespace().next()?.parse::<u64>().ok();
        }
        if rss.is_some() && vmsize.is_some() {
            break;
        }
    }
    Some((rss.unwrap_or(0), vmsize.unwrap_or(0)))
}
