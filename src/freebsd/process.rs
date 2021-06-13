//
// Sysinfo
//
// Copyright (c) 2015 Guillaume Gomez
//

use crate::{DiskUsage, Pid, ProcessExt, Signal};

use std::fmt;
use std::path::{Path, PathBuf};

use libc::{gid_t, kill, uid_t};

/// Enum describing the different status of a process.
#[derive(Clone, Copy, Debug)]
#[repr(i8)]
pub enum ProcessStatus {
    /// Idle.
    Idle,
    /// Runnable.
    Run,
    /// Sleeping.
    Sleep,
    /// Suspended.
    Stop,
    /// Awaiting collection.
    Zombie,
    /// Waiting for interrupt.
    Wait,
    /// Blocked on a lock.
    Lock,
    /// Unknown.
    Unknown(i8), // todo: determine if i8 large enough?
}

impl From<i8> for ProcessStatus {
    fn from(status: i8) -> Self {
        match status {
            1 => Self::Idle,
            2 => Self::Run,
            3 => Self::Sleep,
            4 => Self::Stop,
            5 => Self::Zombie,
            6 => Self::Wait,
            7 => Self::Lock,
            x => Self::Unknown(x),
        }
    }
}

impl ProcessStatus {
    /// Used to display `ProcessStatus`.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match *self {
            Self::Idle => "Idle",
            Self::Run => "Runnable",
            Self::Sleep => "Sleeping",
            Self::Stop => "Stopped",
            Self::Zombie => "Zombie",
            Self::Wait => "Waiting",
            Self::Lock => "Locked",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for ProcessStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Struct containing a process' information.
#[derive(Clone)]
pub struct Process {
    pub(crate) name: String,
    cmd: Vec<String>,
    pub(crate) exe: PathBuf,
    pid: Pid,
    parent: Option<Pid>,
    environ: Vec<String>,
    pub(crate) cwd: PathBuf,
    root: PathBuf,
    memory: u64,
    virtual_memory: u64,
    utime: u64,
    stime: u64,
    old_utime: u64,
    old_stime: u64,
    start_time: u64,
    updated: bool,
    pub(crate) cpu: f32,
    /// User id of the process owner.
    pub uid: uid_t,
    pub(crate) status: ProcessStatus,
    /// Group id of the process owner.
    pub gid: gid_t,
    old_read_bytes: u64,
    old_written_bytes: u64,
    read_bytes: u64,
    written_bytes: u64,
}

impl ProcessExt for Process {
    fn new(pid: Pid, parent: Option<Pid>, start_time: u64) -> Self {
        Self {
            name: String::with_capacity(20),
            pid,
            parent,
            cmd: Vec::with_capacity(2),
            environ: Vec::with_capacity(10),
            exe: PathBuf::new(),
            cwd: PathBuf::new(),
            root: PathBuf::new(),
            memory: 0,
            virtual_memory: 0,
            cpu: 0.,
            utime: 0,
            stime: 0,
            old_utime: 0,
            old_stime: 0,
            updated: true,
            start_time,
            uid: 0,
            gid: 0,
            old_read_bytes: 0,
            old_written_bytes: 0,
            read_bytes: 0,
            written_bytes: 0,
            status: ProcessStatus::Unknown(0),
        }
    }

    fn kill(&self, signal: Signal) -> bool {
        let c_signal = match signal {
            Signal::Hangup => libc::SIGHUP,
            Signal::Interrupt => libc::SIGINT,
            Signal::Quit => libc::SIGQUIT,
            Signal::Illegal => libc::SIGILL,
            Signal::Trap => libc::SIGTRAP,
            Signal::Abort => libc::SIGABRT,
            Signal::IOT => libc::SIGIOT,
            Signal::Bus => libc::SIGBUS,
            Signal::FloatingPointException => libc::SIGFPE,
            Signal::Kill => libc::SIGKILL,
            Signal::User1 => libc::SIGUSR1,
            Signal::Segv => libc::SIGSEGV,
            Signal::User2 => libc::SIGUSR2,
            Signal::Pipe => libc::SIGPIPE,
            Signal::Alarm => libc::SIGALRM,
            Signal::Term => libc::SIGTERM,
            Signal::Child => libc::SIGCHLD,
            Signal::Continue => libc::SIGCONT,
            Signal::Stop => libc::SIGSTOP,
            Signal::TSTP => libc::SIGTSTP,
            Signal::TTIN => libc::SIGTTIN,
            Signal::TTOU => libc::SIGTTOU,
            Signal::Urgent => libc::SIGURG,
            Signal::XCPU => libc::SIGXCPU,
            Signal::XFSZ => libc::SIGXFSZ,
            Signal::VirtualAlarm => libc::SIGVTALRM,
            Signal::Profiling => libc::SIGPROF,
            Signal::Winch => libc::SIGWINCH,
            // todo: SIGPOLL doesn't exist on FreeBSD targets, but it appears
            // to be equivalent to SIGIO on unix, so this is hopefully okay?
            Signal::IO | Signal::Poll => libc::SIGIO,
            Signal::Power => return false,
            Signal::Sys => libc::SIGSYS,
        };
        unsafe { kill(self.pid, c_signal) == 0 }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn cmd(&self) -> &[String] {
        &self.cmd
    }

    fn exe(&self) -> &Path {
        self.exe.as_path()
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn environ(&self) -> &[String] {
        &self.environ
    }

    fn cwd(&self) -> &Path {
        self.cwd.as_path()
    }

    fn root(&self) -> &Path {
        self.root.as_path()
    }

    fn memory(&self) -> u64 {
        self.memory
    }

    fn virtual_memory(&self) -> u64 {
        self.virtual_memory
    }

    fn parent(&self) -> Option<Pid> {
        self.parent
    }

    fn status(&self) -> ProcessStatus {
        self.status
    }

    fn start_time(&self) -> u64 {
        self.start_time
    }

    fn cpu_usage(&self) -> f32 {
        self.cpu
    }

    fn disk_usage(&self) -> DiskUsage {
        DiskUsage {
            read_bytes: self.read_bytes - self.old_read_bytes,
            total_read_bytes: self.read_bytes,
            written_bytes: self.written_bytes - self.old_written_bytes,
            total_written_bytes: self.written_bytes,
        }
    }
}
