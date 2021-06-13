use libc::{c_char, c_int, c_long, c_schar, c_short, c_uchar, c_uint, c_ushort, c_void};
use std::marker;

#[link(name = "procstat")]
extern "C" {
    pub fn procstat_open_sysctl() -> *mut procstat;
    pub fn procstat_getprocs(
        procstat: *mut procstat,
        what: c_int,
        arg: c_int,
        count: *mut c_uint,
    ) -> *mut kinfo_proc;
    pub fn procstat_freeprocs(procstat: *mut procstat, p: *mut kinfo_proc);
}

// Generates opaque structure types
//
// See:
//  * https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
//  * https://github.com/rust-lang/nomicon/issues/29
//  * https://github.com/rust-lang/nomicon/issues/250
//
// todo: make these extern types when they land in stable
macro_rules! declare_opaque {
    ($name:ident) => {
        #[derive(Clone, Copy)]
        #[repr(C)]
        pub struct $name {
            _data: [u8; 0],
            _marker: marker::PhantomData<(*mut u8, marker::PhantomPinned)>,
        }
    };
}

// todo: if any of these structs are added to the libc crate,
// use them instead
declare_opaque! {kvm_t}
declare_opaque! {procstat_core}
declare_opaque! {pargs}
declare_opaque! {proc}
declare_opaque! {user}
declare_opaque! {vnode}
declare_opaque! {filedesc}
declare_opaque! {vmspace}
declare_opaque! {pcb}
declare_opaque! {thread}

// todo: if the priority struct is added to the libc crate,
// use that instead
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct priority {
    pub pri_class: c_uchar,
    pub pri_level: c_uchar,
    pub pri_native: c_uchar,
    pub pri_user: c_uchar,
}

// todo: if the kinfo_proc struct is added to the libc crate,
// use that instead
#[derive(Clone, Copy)]
#[repr(C)]
pub struct kinfo_proc {
    pub ki_structsize: c_int,
    pub ki_layout: c_int,
    pub ki_args: *mut pargs,
    pub ki_paddr: *mut proc,
    pub ki_addr: *mut user,
    pub ki_tracep: *mut vnode,
    pub ki_textvp: *mut vnode,
    pub ki_fd: *mut filedesc,
    pub ki_vmspace: *mut vmspace,
    pub ki_wchan: *const c_void,
    pub ki_pid: libc::pid_t,
    pub ki_ppid: libc::pid_t,
    pub ki_pgid: libc::pid_t,
    pub ki_tpgid: libc::pid_t,
    pub ki_sid: libc::pid_t,
    pub ki_tsid: libc::pid_t,
    pub ki_jobc: c_short,
    pub ki_spare_short1: c_short,
    pub ki_tdev_freebsd11: u32,
    pub ki_siglist: libc::sigset_t,
    pub ki_sigmask: libc::sigset_t,
    pub ki_sigignore: libc::sigset_t,
    pub ki_sigcatch: libc::sigset_t,
    pub ki_uid: libc::uid_t,
    pub ki_ruid: libc::uid_t,
    pub ki_svuid: libc::uid_t,
    pub ki_rgid: libc::gid_t,
    pub ki_svgid: libc::gid_t,
    pub ki_ngroups: c_short,
    pub ki_spare_short2: c_short,
    pub ki_groups: [libc::gid_t; 16],
    pub ki_size: libc::vm_size_t,
    pub ki_rssize: isize, // todo: change to segsz_t if added to libc
    pub ki_swrss: isize,  // todo: change to segsz_t if added to libc
    pub ki_tsize: isize,  // todo: change to segsz_t if added to libc
    pub ki_dsize: isize,  // todo: change to segsz_t if added to libc
    pub ki_ssize: isize,  // todo: change to segsz_t if added to libc
    pub ki_xstat: c_ushort,
    pub ki_acflag: c_ushort,
    pub ki_pctcpu: u32, // todo: change to fixpt_t if added to libc
    pub ki_estcpu: c_uint,
    pub ki_slptime: c_uint,
    pub ki_swtime: c_uint,
    pub ki_cow: c_uint,
    pub ki_runtime: u64,
    pub ki_start: libc::timeval,
    pub ki_childtime: libc::timeval,
    pub ki_flag: c_long,
    pub ki_kiflag: c_long,
    pub ki_traceflag: c_int,
    pub ki_stat: c_char,
    pub ki_nice: c_schar,
    pub ki_lock: c_char,
    pub ki_rqindex: c_char,
    pub ki_oncpu_old: c_uchar,
    pub ki_lastcpu_old: c_uchar,
    pub ki_tdname: [c_char; 16 + 1],
    pub ki_wmesg: [c_char; 8 + 1],
    pub ki_login: [c_char; 17 + 1],
    pub ki_lockname: [c_char; 8 + 1],
    pub ki_comm: [c_char; 19 + 1],
    pub ki_emul: [c_char; 16 + 1],
    pub ki_loginclass: [c_char; 17 + 1],
    pub ki_moretdname: [c_char; 19 - 16 + 1],
    pub ki_sparestrings: [c_char; 46],
    pub ki_spareints: [c_int; 2],
    pub ki_tdev: u64,
    pub ki_oncpu: c_int,
    pub ki_lastcpu: c_int,
    pub ki_tracer: c_int,
    pub ki_flag2: c_int,
    pub ki_fibnum: c_int,
    pub ki_cr_flags: c_uint,
    pub ki_jid: c_int,
    pub ki_numthreads: c_int,
    pub ki_tid: libc::lwpid_t,
    pub ki_pri: priority,
    pub ki_rusage: libc::rusage,
    pub ki_rusage_ch: libc::rusage,
    pub ki_pcb: *mut pcb,
    pub ki_kstack: *mut c_void,
    pub ki_udata: *mut c_void,
    pub ki_tdaddr: *mut thread,
    pub ki_spareptrs: [*mut c_void; 6],
    pub ki_sparelongs: [c_long; 12],
    pub ki_sflag: c_long,
    pub ki_tdflags: c_long,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct procstat {
    pub type_: c_int,
    pub kd: *mut kvm_t,
    pub vmentries: *mut c_void,
    pub files: *mut c_void,
    pub argv: *mut c_void,
    pub envv: *mut c_void,
    pub core: *mut procstat_core,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct filestat {
    pub fs_type: c_int,
    pub fs_flags: c_int,
    pub fs_fflags: c_int,
    pub fs_uflags: c_int,
    pub fs_fd: c_int,
    pub fs_ref_count: c_int,
    pub fs_offset: libc::off_t,
    pub fs_typedep: *mut c_void,
    pub fs_path: *mut c_char,
    pub next: _filestat_unnamed0,
    pub fs_cap_rights: libc::cap_rights_t,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct _filestat_unnamed0 {
    pub stqe_next: *mut filestat,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct filestat_list {
    pub stqh_first: *mut filestat,
    pub stqh_last: *mut *mut filestat,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct vnstat {
    pub vn_fileid: u64,
    pub vn_size: u64,
    pub vn_dev: u64,
    pub vn_fsid: u64,
    pub vn_mntdir: c_char,
    pub vn_type: c_int,
    pub vn_mode: u16,
    pub vn_devname: [c_char; 63 + 1],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_len: c_uchar,
    pub ss_family: libc::sa_family_t,
    pub __ss_pad1: [c_char; 6],
    pub __ss_align: i64,
    pub __ss_pad2: [c_char; 112],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct kinfo_file {
    pub kf_structsize: c_int,
    pub kf_type: c_int,
    pub kf_fd: c_int,
    pub kf_ref_count: c_int,
    pub kf_flags: c_int,
    pub kf_pad0: c_int,
    pub kf_offset: i64,
    pub _unnamed0: _kinfo_file_unnamed0,
    pub kf_status: u16,
    pub kf_pad1: u16,
    pub _kf_ispare0: c_int,
    pub kf_cap_rights: libc::cap_rights_t, //c_int,
    pub _kf_cap_spare: u64,
    pub kf_path: [c_char; libc::PATH_MAX as _],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union _kinfo_file_unnamed0 {
    pub _unnamed0: _kinfo_file_unnamed9,
    pub kf_un: _kinfo_file_unnamed1,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union _kinfo_file_unnamed1 {
    pub kf_sock: _kinfo_file_unnamed8,
    pub kf_file: _kinfo_file_unnamed7,
    pub kf_sem: _kinfo_file_unnamed6,
    pub kf_pipe: _kinfo_file_unnamed5,
    pub kf_pts: _kinfo_file_unnamed4,
    pub kf_proc: _kinfo_file_unnamed3,
    pub kf_eventfd: _kinfo_file_unnamed2,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed2 {
    pub kf_eventfd_value: u64,
    pub kf_eventfd_flags: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed3 {
    pub kf_spareint: [u32; 4],
    pub kf_spareint64: [u64; 32],
    pub kf_pid: libc::pid_t,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed4 {
    pub kf_spareint: [u32; 4],
    pub kf_spareint64: [u64; 32],
    pub kf_pts_dev_freebsd11: u32,
    pub kf_pts_pad0: u32,
    pub kf_pts_dev: u64,
    pub kf_pts_pad1: [u32; 4],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed5 {
    pub kf_spareint: [u32; 4],
    pub kf_spareint64: [u64; 32],
    pub kf_pipe_addr: u64,
    pub kf_pipe_peer: u64,
    pub kf_pipe_buffer_cnt: u32,
    pub kf_pipe_pad0: [u32; 3],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed6 {
    pub kf_spareint: [u32; 4],
    pub kf_spareint64: [u64; 32],
    pub kf_sem_value: u32,
    pub kf_sem_mode: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed7 {
    pub kf_file_type: c_int,
    pub kf_spareint: [c_int; 3],
    pub kf_spareint64: [u64; 30],
    pub kf_file_fsid: u64,
    pub kf_file_rdev: u64,
    pub kf_file_fileid: u64,
    pub kf_file_size: u64,
    pub kf_file_fsid_freebsd11: u32,
    pub kf_file_rdev_freebsd11: u32,
    pub kf_file_mode: u16,
    pub kf_file_pad0: u16,
    pub kf_file_pad1: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed8 {
    pub kf_sock_sendq: u32,
    pub kf_sock_domain0: c_int,
    pub kf_sock_type0: c_int,
    pub kf_sock_protocol0: c_int,
    pub kf_sa_local: sockaddr_storage,
    pub kf_sa_peer: sockaddr_storage,
    pub kf_sock_pcb: u64,
    pub kf_sock_inpcb: u64,
    pub kf_sock_unpconn: u64,
    pub kf_sock_snd_sb_state: u16,
    pub kf_sock_rcv_sb_state: u16,
    pub kf_sock_recvq: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct _kinfo_file_unnamed9 {
    pub kf_vnode_type: c_int,
    pub kf_sock_domain: c_int,
    pub kf_sock_type: c_int,
    pub kf_sock_protocol: c_int,
    pub kf_sa_local: sockaddr_storage,
    pub kf_sa_peer: sockaddr_storage,
}
