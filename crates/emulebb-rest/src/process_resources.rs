//! Bounded, on-demand metrics for this daemon, including native Android builds.

use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Mutex;

const MIN_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
pub(crate) struct ProcessResourceMonitor {
    sampler: Mutex<Sampler>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessResources {
    sampled_at_ms: Option<i64>,
    resident_memory_bytes: Option<u64>,
    /// Total process CPU use: 100% means one occupied core, not the whole host.
    cpu_usage_percent: Option<f64>,
    cpu_sample_interval_ms: Option<u64>,
}

impl ProcessResourceMonitor {
    /// Share a sample across REST consumers for at least one second. OS reads
    /// stay off the async executor; missing counters remain null, never zero.
    pub(crate) async fn snapshot(&self) -> ProcessResources {
        let mut sampler = self.sampler.lock().await;
        if sampler
            .previous
            .as_ref()
            .is_some_and(|sample| sample.at.elapsed() < MIN_SAMPLE_INTERVAL)
        {
            return sampler.current;
        }
        match tokio::task::spawn_blocking(RawSample::read).await {
            Ok(sample) => sampler.record(sample),
            Err(_) => {
                *sampler = Sampler::default();
                ProcessResources::default()
            }
        }
    }
}

#[derive(Debug, Default)]
struct Sampler {
    previous: Option<RawSample>,
    current: ProcessResources,
}

#[derive(Debug)]
struct RawSample {
    at: Instant,
    sampled_at_ms: i64,
    cpu_time: Option<Duration>,
    resident_memory_bytes: Option<u64>,
}

impl RawSample {
    fn read() -> Self {
        let cpu_time = cpu_time();
        let at = Instant::now();
        Self {
            at,
            sampled_at_ms: chrono::Utc::now().timestamp_millis(),
            cpu_time,
            resident_memory_bytes: resident_memory_bytes(),
        }
    }
}

impl Sampler {
    fn record(&mut self, sample: RawSample) -> ProcessResources {
        let cpu_sample = self.previous.as_ref().and_then(|previous| {
            let elapsed = sample.at.checked_duration_since(previous.at)?;
            let cpu = sample.cpu_time?.checked_sub(previous.cpu_time?)?;
            (elapsed >= MIN_SAMPLE_INTERVAL).then(|| {
                (
                    cpu.as_secs_f64() / elapsed.as_secs_f64() * 100.0,
                    elapsed.as_millis().min(u64::MAX as u128) as u64,
                )
            })
        });
        self.current = ProcessResources {
            sampled_at_ms: Some(sample.sampled_at_ms),
            resident_memory_bytes: sample.resident_memory_bytes,
            cpu_usage_percent: cpu_sample.map(|(percent, _)| percent),
            cpu_sample_interval_ms: cpu_sample.map(|(_, interval)| interval),
        };
        self.previous = Some(sample);
        self.current
    }
}

#[cfg(unix)]
fn cpu_time() -> Option<Duration> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the writable output on success; RUSAGE_SELF
    // includes every thread in this process and excludes child processes.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful call initialized `usage`.
    let usage = unsafe { usage.assume_init() };
    let duration = |time: libc::timeval| {
        Some(Duration::new(
            time.tv_sec.try_into().ok()?,
            u32::try_from(time.tv_usec).ok()?.checked_mul(1_000)?,
        ))
    };
    duration(usage.ru_utime)?.checked_add(duration(usage.ru_stime)?)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn resident_memory_bytes() -> Option<u64> {
    use std::io::Read;

    // WHY: Android restricts global /proc counters. The current process's statm
    // remains readable without JVM/root access; its RSS is in runtime pages,
    // which must not be assumed to be 4 KiB on Android's 16 KiB builds.
    let mut statm = String::new();
    std::fs::File::open("/proc/self/statm")
        .ok()?
        .take(256)
        .read_to_string(&mut statm)
        .ok()?;
    // SAFETY: sysconf has no pointer arguments; nonpositive results are rejected.
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
    resident_bytes_from_statm(&statm, page_size)
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
fn resident_bytes_from_statm(statm: &str, page_size: u64) -> Option<u64> {
    if page_size == 0 {
        return None;
    }
    statm
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?
        .checked_mul(page_size)
}

#[cfg(target_os = "macos")]
fn resident_memory_bytes() -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::uninit();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: the flavor, output size and count describe mach_task_basic_info.
    // The current task port is borrowed; the output is read only on success.
    let result = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS || count != libc::MACH_TASK_BASIC_INFO_COUNT {
        return None;
    }
    // SAFETY: the successful call initialized the complete requested structure.
    Some(unsafe { info.assume_init() }.resident_size)
}

#[cfg(windows)]
fn cpu_time() -> Option<Duration> {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetProcessTimes},
    };

    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle and all four
    // output pointers address writable FILETIME values for this call.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return None;
    }
    let ticks =
        |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    let total = ticks(kernel).checked_add(ticks(user))?;
    Some(Duration::new(
        total / 10_000_000,
        ((total % 10_000_000) * 100) as u32,
    ))
}

#[cfg(windows)]
fn resident_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::{
        ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::GetCurrentProcess,
    };

    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size,
        ..Default::default()
    };
    // SAFETY: the current-process pseudo-handle is borrowed, and counters is a
    // writable structure whose size matches the buffer length supplied.
    if unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) } == 0 {
        return None;
    }
    Some(counters.WorkingSetSize as u64)
}

#[cfg(not(any(unix, windows)))]
fn cpu_time() -> Option<Duration> {
    None
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
)))]
fn resident_memory_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_uses_interval_deltas_and_can_exceed_one_core() {
        let start = Instant::now();
        let mut sampler = Sampler::default();
        let sample = |seconds, cpu: Option<u64>| RawSample {
            at: start + Duration::from_secs(seconds),
            sampled_at_ms: 1_000 + seconds as i64 * 1_000,
            cpu_time: cpu.map(Duration::from_millis),
            resident_memory_bytes: Some(42),
        };
        let first = sampler.record(sample(0, Some(500)));
        assert_eq!(first.resident_memory_bytes, Some(42));
        assert_eq!(first.cpu_usage_percent, None);
        assert_eq!(first.cpu_sample_interval_ms, None);
        let busy = sampler.record(sample(2, Some(3_000)));
        assert_eq!(busy.cpu_usage_percent, Some(125.0));
        assert_eq!(busy.cpu_sample_interval_ms, Some(2_000));
        assert_eq!(
            sampler.record(sample(4, Some(3_000))).cpu_usage_percent,
            Some(0.0)
        );
        assert_eq!(sampler.record(sample(6, None)).cpu_usage_percent, None);
        assert_eq!(
            sampler.record(sample(8, Some(4_000))).cpu_usage_percent,
            None
        );
        assert_eq!(sampler.record(sample(10, Some(1))).cpu_usage_percent, None);
    }

    #[test]
    fn resident_memory_uses_runtime_page_size_and_rejects_bad_counters() {
        assert_eq!(
            resident_bytes_from_statm("200 100 50 0 0 10 0\n", 16_384),
            Some(1_638_400)
        );
        assert_eq!(resident_bytes_from_statm("200 100", 4_096), Some(409_600));
        for invalid in [
            "",
            "200",
            "200 invalid",
            "200 -1",
            "200 18446744073709551615",
        ] {
            assert_eq!(resident_bytes_from_statm(invalid, 16_384), None);
        }
        assert_eq!(resident_bytes_from_statm("200 100", 0), None);
    }

    #[tokio::test]
    async fn native_metrics_are_live_and_repeated_requests_reuse_the_sample() {
        let monitor = ProcessResourceMonitor::default();
        let first = monitor.snapshot().await;
        assert!(first.sampled_at_ms.is_some());
        assert!(first.resident_memory_bytes.is_some_and(|bytes| bytes > 0));
        assert!(
            monitor
                .sampler
                .lock()
                .await
                .previous
                .as_ref()
                .unwrap()
                .cpu_time
                .is_some()
        );
        let second = monitor.snapshot().await;
        assert_eq!(first.sampled_at_ms, second.sampled_at_ms);
        assert_eq!(first.resident_memory_bytes, second.resident_memory_bytes);
        assert_eq!(second.cpu_usage_percent, None);
    }
}
