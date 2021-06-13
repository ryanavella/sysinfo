use libc::c_int;
use std::convert::TryInto;
use std::mem;
use std::ptr;

pub fn sysctl_len(mib: &mut [c_int]) -> Option<usize> {
    let mut len = 0;
    let code = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len().try_into().ok()?,
            ptr::null_mut(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if code < 0 {
        sysinfo_debug!(
            "sysctl failed with code {}: cannot retrieve length for mib {:?}...",
            code,
            mib
        );
        None
    } else {
        Some(len)
    }
}

pub unsafe fn sysctl_str(mib: &mut [c_int]) -> Option<String> {
    let mut len = sysctl_len(mib)?;
    let mut buf = vec![0_u8; len];
    let code = libc::sysctl(
        mib.as_mut_ptr(),
        mib.len().try_into().ok()?,
        buf.as_mut_ptr().cast(),
        &mut len,
        ptr::null_mut(),
        0,
    );
    if code < 0 {
        sysinfo_debug!(
            "sysctl failed with code {}: cannot retrieve value for mib {:?}...",
            code,
            mib
        );
        None
    } else {
        if let Some(pos) = buf.iter().position(|x| *x == 0) {
            // Remove null bytes
            buf.resize(pos, 0);
        }
        String::from_utf8(buf).ok()
    }
}

pub unsafe fn sysctl<T>(mib: &mut [c_int]) -> Option<T> {
    let mut old: T = mem::zeroed();
    let mut len = mem::size_of::<T>();
    if sysctl_len(mib) != Some(len) {
        return None;
    }
    let code = libc::sysctl(
        mib.as_mut_ptr(),
        mib.len().try_into().ok()?,
        ptr::addr_of_mut!(old).cast(),
        &mut len,
        ptr::null_mut(),
        0,
    );
    if code < 0 {
        sysinfo_debug!(
            "sysctl failed with code {}: cannot retrieve value for mib {:?}...",
            code,
            mib
        );
        None
    } else {
        Some(old)
    }
}
