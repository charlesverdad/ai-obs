//! macOS platform layer: process enumeration, per-process resource usage,
//! and mach-timebase conversion.
//!
//! Everything here was validated empirically before being designed around:
//! - `proc_pid_rusage` works unprivileged on any same-uid process.
//! - Time fields in `rusage_info_v4` are mach absolute ticks, NOT nanoseconds.
//!   On Apple Silicon the timebase is 125/3 (~24 MHz); reading raw is 41.67x low.
//! - Reading another process's environment is root-only, so attribution uses
//!   PID ancestry, never env vars.

use std::ffi::c_void;
use std::sync::OnceLock;

pub const RUSAGE_INFO_V4: i32 = 4;
const PROC_PIDTBSDINFO: i32 = 3;
const PROC_ALL_PIDS: u32 = 1;

extern "C" {
    fn proc_listpids(t: u32, typeinfo: u32, buffer: *mut c_void, buffersize: i32) -> i32;
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, buffersize: i32) -> i32;
    fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut c_void) -> i32;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

/// nanoseconds per mach tick, as a ratio. 125/3 on Apple Silicon, 1/1 on Intel.
fn timebase() -> (u64, u64) {
    static TB: OnceLock<(u64, u64)> = OnceLock::new();
    *TB.get_or_init(|| {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: mach_timebase_info fills the struct; it cannot fail for a valid pointer.
        unsafe { mach_timebase_info(&mut info) };
        if info.numer == 0 || info.denom == 0 {
            (1, 1)
        } else {
            (info.numer as u64, info.denom as u64)
        }
    })
}

/// Convert mach absolute ticks to nanoseconds. Uses u128 to avoid overflow:
/// ticks * numer can exceed u64 for long-lived processes.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let (numer, denom) = timebase();
    ((ticks as u128 * numer as u128) / denom as u128) as u64
}

/// `struct proc_bsdinfo` from <sys/proc_info.h>. Stable ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

/// `struct rusage_info_v4` from <sys/resource.h>. Stable ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RusageInfoV4 {
    pub ri_uuid: [u8; 16],
    pub ri_user_time: u64,
    pub ri_system_time: u64,
    pub ri_pkg_idle_wkups: u64,
    pub ri_interrupt_wkups: u64,
    pub ri_pageins: u64,
    pub ri_wired_size: u64,
    pub ri_resident_size: u64,
    pub ri_phys_footprint: u64,
    pub ri_proc_start_abstime: u64,
    pub ri_proc_exit_abstime: u64,
    pub ri_child_user_time: u64,
    pub ri_child_system_time: u64,
    pub ri_child_pkg_idle_wkups: u64,
    pub ri_child_interrupt_wkups: u64,
    pub ri_child_pageins: u64,
    pub ri_child_elapsed_abstime: u64,
    pub ri_diskio_bytesread: u64,
    pub ri_diskio_byteswritten: u64,
    pub ri_cpu_time_qos_default: u64,
    pub ri_cpu_time_qos_maintenance: u64,
    pub ri_cpu_time_qos_background: u64,
    pub ri_cpu_time_qos_utility: u64,
    pub ri_cpu_time_qos_legacy: u64,
    pub ri_cpu_time_qos_user_initiated: u64,
    pub ri_cpu_time_qos_user_interactive: u64,
    pub ri_billed_system_time: u64,
    pub ri_serviced_system_time: u64,
    pub ri_logical_writes: u64,
    pub ri_lifetime_max_phys_footprint: u64,
    pub ri_instructions: u64,
    pub ri_cycles: u64,
    pub ri_billed_energy: u64,
    pub ri_serviced_energy: u64,
    pub ri_interval_max_phys_footprint: u64,
    pub ri_runnable_time: u64,
    pub ri_flags: u64,
}

/// A process as seen by one enumeration pass.
#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    /// Short command name (16 bytes, truncated by the kernel).
    pub comm: String,
    /// Longer name (32 bytes).
    pub name: String,
    /// Process start time, unix seconds.
    pub start_sec: u64,
}

/// Resource counters for one process, times already converted to ns.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcUsage {
    pub cpu_user_ns: u64,
    pub cpu_sys_ns: u64,
    pub child_cpu_user_ns: u64,
    pub child_cpu_sys_ns: u64,
    pub phys_footprint: u64,
    pub lifetime_max_footprint: u64,
    pub disk_read: u64,
    pub disk_write: u64,
    pub instructions: u64,
    pub cycles: u64,
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Enumerate all visible processes. Unprivileged; root-owned processes appear
/// in the pid list but their bsdinfo may be readable anyway (it is public info).
pub fn list_processes() -> Vec<ProcInfo> {
    // First call with null to size, then fetch. Add slack for races.
    // SAFETY: proc_listpids with a null buffer returns the byte size needed.
    let bytes = unsafe { proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Vec::new();
    }
    let cap = (bytes as usize / 4) + 64;
    let mut pids = vec![0i32; cap];
    // SAFETY: buffer is cap*4 bytes of valid memory.
    let got = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut c_void,
            (cap * 4) as i32,
        )
    };
    if got <= 0 {
        return Vec::new();
    }
    pids.truncate(got as usize / 4);

    let mut out = Vec::with_capacity(pids.len());
    for pid in pids {
        if pid <= 0 {
            continue;
        }
        let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<ProcBsdInfo>() as i32;
        // SAFETY: buffer matches the flavor's struct size.
        let n = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut c_void, size) };
        if n < size {
            continue; // exited mid-scan or not permitted
        }
        out.push(ProcInfo {
            pid,
            ppid: info.pbi_ppid as i32,
            comm: cstr(&info.pbi_comm),
            name: cstr(&info.pbi_name),
            start_sec: info.pbi_start_tvsec,
        });
    }
    out
}

/// Read resource usage for one process. Returns None for exited or
/// not-permitted (root-owned) processes.
pub fn usage(pid: i32) -> Option<ProcUsage> {
    let mut ri = RusageInfoV4::default();
    // SAFETY: buffer matches RUSAGE_INFO_V4 layout.
    let rc = unsafe { proc_pid_rusage(pid, RUSAGE_INFO_V4, &mut ri as *mut _ as *mut c_void) };
    if rc != 0 {
        return None;
    }
    Some(ProcUsage {
        cpu_user_ns: ticks_to_ns(ri.ri_user_time),
        cpu_sys_ns: ticks_to_ns(ri.ri_system_time),
        child_cpu_user_ns: ticks_to_ns(ri.ri_child_user_time),
        child_cpu_sys_ns: ticks_to_ns(ri.ri_child_system_time),
        phys_footprint: ri.ri_phys_footprint,
        lifetime_max_footprint: ri.ri_lifetime_max_phys_footprint,
        disk_read: ri.ri_diskio_bytesread,
        disk_write: ri.ri_diskio_byteswritten,
        instructions: ri.ri_instructions,
        cycles: ri.ri_cycles,
    })
}

/// Self-check used by `ai-obs doctor` and the test suite: our own CPU time via
/// proc_pid_rusage (mach ticks, converted) must agree with getrusage(RUSAGE_SELF)
/// (timevals, authoritative) within tolerance. Catches timebase mistakes — the
/// class of bug where every number is wrong but plausible.
pub fn timebase_self_check() -> Result<(), String> {
    // Burn a little CPU so both counters are clearly nonzero.
    let t0 = std::time::Instant::now();
    let mut acc: u64 = 0;
    while t0.elapsed() < std::time::Duration::from_millis(120) {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1);
    }
    std::hint::black_box(acc);

    let ours = usage(std::process::id() as i32).ok_or("proc_pid_rusage failed on self")?;
    let mine_ns = ours.cpu_user_ns + ours.cpu_sys_ns;

    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: standard getrusage call.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    if rc != 0 {
        return Err("getrusage failed".into());
    }
    let ref_ns = (ru.ru_utime.tv_sec as u64 * 1_000_000_000
        + ru.ru_utime.tv_usec as u64 * 1_000)
        + (ru.ru_stime.tv_sec as u64 * 1_000_000_000 + ru.ru_stime.tv_usec as u64 * 1_000);

    let ratio = mine_ns as f64 / ref_ns.max(1) as f64;
    if !(0.8..=1.25).contains(&ratio) {
        return Err(format!(
            "timebase conversion off: proc_pid_rusage says {mine_ns} ns, getrusage says {ref_ns} ns (ratio {ratio:.3})"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timebase_matches_getrusage() {
        timebase_self_check().unwrap();
    }

    #[test]
    fn tree_walk_sees_self_with_correct_parent() {
        let me = std::process::id() as i32;
        let parent = unsafe { libc::getppid() };
        let procs = list_processes();
        let mine = procs.iter().find(|p| p.pid == me).expect("self not found");
        assert_eq!(mine.ppid, parent);
        assert!(!mine.comm.is_empty());
    }

    #[test]
    fn usage_readable_on_self_and_parent() {
        let me = usage(std::process::id() as i32).expect("self");
        assert!(me.phys_footprint > 1_000_000, "footprint implausibly small");
        // Parent is a same-uid non-child process (cargo / shell): the
        // unprivileged-read guarantee the whole design rests on.
        let parent = unsafe { libc::getppid() };
        assert!(usage(parent).is_some(), "cannot read same-uid non-child");
    }

    #[test]
    fn child_cpu_accounts_reaped_children() {
        // Spawn a child that burns ~150ms CPU and exits; our ri_child_* must
        // grow by roughly that much. This is the exact-CPU primitive used for
        // tool spans.
        let before = usage(std::process::id() as i32).unwrap();
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", "i=0; while [ $i -lt 400000 ]; do i=$((i+1)); done"])
            .status()
            .unwrap();
        assert!(status.success());
        let after = usage(std::process::id() as i32).unwrap();
        let delta =
            (after.child_cpu_user_ns + after.child_cpu_sys_ns)
                .saturating_sub(before.child_cpu_user_ns + before.child_cpu_sys_ns);
        assert!(
            delta > 20_000_000,
            "child CPU delta {delta} ns implausibly small — reaped-child accounting broken"
        );
    }
}
