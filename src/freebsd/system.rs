//
// Sysinfo
//
// Copyright (c) 2015 Guillaume Gomez
//

use crate::{
    common::{Gid, Uid},
    sys::{component::Component, Disk, Networks, Process, Processor},
    LoadAvg, Pid, ProcessExt, RefreshKind, SystemExt, User,
};

use libc::{c_char, c_int, c_uint, endpwent, getgrgid, getgrouplist, getpwent, gid_t, setpwent};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::CStr;
use std::mem;
use std::path::PathBuf;
use std::ptr;

use crate::sys::ffi::{kinfo_file, procstat_freeprocs, procstat_getprocs, procstat_open_sysctl};
use crate::sys::util::{sysctl, sysctl_str};

/// Structs containing system's information.
pub struct System {
    processes: HashMap<Pid, Process>,
    networks: Networks,
    global_processor: Processor,
    boot_time: u64,
    users: Vec<User>,
    mem_total: u64,
    mem_free: u64,
}

impl SystemExt for System {
    const IS_SUPPORTED: bool = false; // todo: make true when ready

    fn new_with_specifics(refreshes: RefreshKind) -> Self {
        let mem_total = realmem().unwrap();
        let mem_free = usermem().unwrap();
        let mut s = Self {
            processes: HashMap::default(),
            networks: Networks::new(),
            global_processor: Processor::new(),
            boot_time: boot_time().unwrap(),
            users: Vec::new(),
            mem_total,
            mem_free,
        };
        s.refresh_specifics(refreshes);
        s
    }

    fn refresh_memory(&mut self) {}

    fn refresh_cpu(&mut self) {}

    fn refresh_components_list(&mut self) {}

    fn refresh_processes(&mut self) {
        let mut count: c_uint = 0;
        let prstat = unsafe { procstat_open_sysctl() };
        let p = unsafe {
            procstat_getprocs(
                prstat,
                libc::KERN_PROC_PROC,
                0,
                ptr::addr_of_mut!(count),
            )
        };
        let mut processes = HashMap::with_capacity(count.try_into().unwrap());
        let count: isize = count.try_into().unwrap();
        let ccpu = ccpu();
        for i in 0..count {
            let kinfo = unsafe { p.offset(i).as_mut() }.unwrap();
            let pid = kinfo.ki_pid;
            let parent = Some(kinfo.ki_ppid).filter(|p| *p != 0);
            let start_time = kinfo.ki_start.tv_sec.try_into().unwrap();
            let mut process = Process::new(pid, parent, start_time);
            process.status = kinfo.ki_stat.into();
            process.name = String::from(
                unsafe { CStr::from_ptr(ptr::addr_of_mut!(kinfo.ki_comm).cast()) }
                    .to_str()
                    .unwrap(),
            );
            process.cpu = cpu(kinfo.ki_pctcpu, kinfo.ki_swtime, ccpu);
            process.exe = PathBuf::from({
                let mut mib = [
                    libc::CTL_KERN,
                    libc::KERN_PROC,
                    libc::KERN_PROC_PATHNAME,
                    pid,
                ];
                unsafe { sysctl_str(&mut mib) }.unwrap_or_default()
            });
            process.cwd = PathBuf::from(
                {
                    const KERN_PROC_CWD: c_int = 42; // todo: if added to libc crate, use that instead
                    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, KERN_PROC_CWD, pid];
                    unsafe {
                        CStr::from_ptr(
                            sysctl::<kinfo_file>(&mut mib)
                                .map_or([0].as_ptr(), |kinfo_file| kinfo_file.kf_path.as_ptr()),
                        )
                    }
                }
                .to_str()
                .unwrap(),
            );
            processes.insert(pid, process);
        }
        unsafe { procstat_freeprocs(prstat, p) };
        self.processes = processes;
    }

    fn refresh_process(&mut self, _pid: Pid) -> bool {
        false
    }

    fn refresh_disks_list(&mut self) {}

    fn refresh_users_list(&mut self) {
        self.users = get_users_list();
    }

    fn get_processes(&self) -> &HashMap<Pid, Process> {
        &self.processes
    }

    fn get_process(&self, _pid: Pid) -> Option<&Process> {
        None
    }

    fn get_networks(&self) -> &Networks {
        &self.networks
    }

    fn get_networks_mut(&mut self) -> &mut Networks {
        &mut self.networks
    }

    fn get_global_processor_info(&self) -> &Processor {
        &self.global_processor
    }

    fn get_processors(&self) -> &[Processor] {
        &[]
    }

    fn get_physical_core_count(&self) -> Option<usize> {
        const KERN_SMP: c_int = 0x7fff_fc58; // todo: if added to libc crate, use that instead
        const KERN_SMP_CORES: c_int = 0x7fff_fc51; // todo: if added to libc crate, use that instead
        let mut mib: [c_int; 3] = [libc::CTL_KERN, KERN_SMP, KERN_SMP_CORES];
        unsafe { sysctl::<u32>(&mut mib) }.and_then(|x| x.try_into().ok())
    }

    fn get_total_memory(&self) -> u64 {
        self.mem_total
    }

    fn get_free_memory(&self) -> u64 {
        // todo: determine if FreeBSD distinguishes free & available memory?
        self.mem_free
    }

    fn get_available_memory(&self) -> u64 {
        // todo: determine if FreeBSD distinguishes free & available memory?
        self.mem_free
    }

    fn get_used_memory(&self) -> u64 {
        // todo: determine if FreeBSD distinguishes free & available memory?
        self.mem_total - self.mem_free
    }

    fn get_total_swap(&self) -> u64 {
        0
    }

    fn get_free_swap(&self) -> u64 {
        0
    }

    fn get_used_swap(&self) -> u64 {
        0
    }

    fn get_components(&self) -> &[Component] {
        &[]
    }

    fn get_components_mut(&mut self) -> &mut [Component] {
        &mut []
    }

    fn get_disks(&self) -> &[Disk] {
        &[]
    }

    fn get_disks_mut(&mut self) -> &mut [Disk] {
        &mut []
    }

    fn get_uptime(&self) -> u64 {
        uptime()
    }

    fn get_boot_time(&self) -> u64 {
        self.boot_time
    }

    fn get_load_average(&self) -> LoadAvg {
        let mut loads = vec![0_f64; 3];
        unsafe {
            libc::getloadavg(loads.as_mut_ptr(), 3);
        }
        LoadAvg {
            one: loads[0],
            five: loads[1],
            fifteen: loads[2],
        }
    }

    fn get_users(&self) -> &[User] {
        &self.users
    }

    fn get_name(&self) -> Option<String> {
        // "FreeBSD"
        let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_OSTYPE];
        unsafe { sysctl_str(&mut mib) }
    }

    fn get_long_os_version(&self) -> Option<String> {
        // e.g. "FreeBSD 12.2-STABLE r369362 GENERIC"
        let mut info: libc::utsname = unsafe { mem::zeroed() };

        if unsafe { libc::uname(ptr::addr_of_mut!(info)) } == 0 {
            let release = info
                .version
                .iter()
                .filter(|c| **c != 0)
                .map(|c| *c as u8)
                .map(char::from)
                .collect();

            Some(release)
        } else {
            None
        }
    }

    fn get_kernel_version(&self) -> Option<String> {
        // e.g. "1202505"
        let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_OSRELDATE];
        unsafe { sysctl::<u32>(&mut mib) }.map(|x| format!("{}", x))
    }

    fn get_os_version(&self) -> Option<String> {
        // e.g. "12.2-STABLE"
        let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_OSRELEASE];
        unsafe { sysctl_str(&mut mib) }
    }

    fn get_host_name(&self) -> Option<String> {
        let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_HOSTNAME];
        unsafe { sysctl_str(&mut mib) }
    }
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

// Equation is based on the source of ps(1),
// so it should yield identical results
fn cpu(pct: u32, dur: u32, ccpu: u32) -> f32 {
    fn fxtofl(x: u32) -> f64 {
        const FSCALE: f64 = (1 << 11) as f64;
        f64::from(x) / FSCALE
    }

    if dur == 0 || pct == 0 {
        return 0.0;
    }

    let pct = fxtofl(pct);
    let dur = f64::from(dur);
    let ccpu = fxtofl(ccpu);
    let num = 100.0 * pct;
    let den = 1.0 - (dur * (ccpu.ln()).exp());
    let cpu = (num / den) as f32;
    // if cpu.is_nan() {
    //     cpu = 0.0;
    // }
    cpu.clamp(0.0, 100.0)
}

fn ccpu() -> u32 {
    const KERN_CCPU: c_int = 0x7fff_fc9d; // todo: if added to libc crate, use that instead
    let mut mib: [c_int; 2] = [libc::CTL_KERN, KERN_CCPU];
    unsafe { sysctl(&mut mib) }.unwrap()
}

fn realmem() -> Option<u64> {
    let mut mib: [c_int; 2] = [libc::CTL_HW, libc::HW_REALMEM];
    unsafe { sysctl(&mut mib) }
}

fn usermem() -> Option<u64> {
    let mut mib: [c_int; 2] = [libc::CTL_HW, libc::HW_USERMEM];
    unsafe { sysctl(&mut mib) }
}

fn boot_time() -> Option<u64> {
    let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    unsafe { sysctl::<libc::timeval>(&mut mib) }.and_then(|b| b.tv_sec.try_into().ok())
}

fn uptime() -> u64 {
    let mut up = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_UPTIME, &mut up) } == 0 {
        up.tv_sec.try_into().unwrap_or(0)
    } else {
        sysinfo_debug!("clock_gettime failed: cannot retrieve uptime...");
        0
    }
}

fn get_user_groups(name: *const c_char, group_id: gid_t) -> Vec<String> {
    let mut groups = Vec::with_capacity(1);
    let mut nb_groups = groups.capacity().try_into().unwrap();
    while let -1 = unsafe { getgrouplist(name, group_id, groups.as_mut_ptr(), &mut nb_groups) } {
        let nb_needed = usize::try_from(nb_groups).unwrap();
        groups.reserve(nb_needed - groups.len());
        debug_assert!(groups.capacity() >= nb_groups.try_into().unwrap());
    }
    unsafe {
        groups.set_len(nb_groups.try_into().unwrap());
    }
    groups
        .into_iter()
        .filter_map(|g| {
            let group = unsafe { getgrgid(g) };
            if group.is_null() {
                return None;
            }
            unsafe { CStr::from_ptr((*group).gr_name) }
                .to_str()
                .ok()
                .map(String::from)
        })
        .collect()
}

fn users_list() -> Vec<User> {
    let mut users = Vec::new();

    unsafe { setpwent() };
    loop {
        let pw = unsafe {
            match getpwent() {
                p if p.is_null() => break,
                pw => *pw,
            }
        };

        let pw_shell = unsafe { CStr::from_ptr(pw.pw_shell) }.to_bytes();
        if pw_shell.ends_with(b"/false") || pw_shell.ends_with(b"/uucico") || pw.pw_uid > u16::MAX.into() {
            // This is not a "real" or "local" user.
            continue;
        }

        let groups = get_user_groups(pw.pw_name, pw.pw_gid);
        let uid = pw.pw_uid;
        let gid = pw.pw_gid;
        let cstr = unsafe { CStr::from_ptr(pw.pw_name) }
            .to_str()
            .ok()
            .map(String::from);
        if let Some(name) = cstr {
            users.push(User {
                uid: Uid(uid),
                gid: Gid(gid),
                name,
                groups,
            });
        }
    }
    unsafe { endpwent() };
    users.sort_unstable_by(|x, y| x.name.partial_cmp(&y.name).unwrap());
    users.dedup_by(|a, b| a.name == b.name);
    users
}

fn get_users_list() -> Vec<User> {
    users_list()
}
