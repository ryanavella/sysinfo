//
// Sysinfo
//
// Copyright (c) 2017 Guillaume Gomez
//

use crate::sys::{ffi, utils};
use crate::utils::to_cpath;
use crate::{Disk, DiskType};

use core_foundation_sys::base::{kCFAllocatorDefault, kCFAllocatorNull, CFRelease};
use core_foundation_sys::dictionary::{CFDictionaryGetValueIfPresent, CFDictionaryRef};
use core_foundation_sys::number::{kCFBooleanTrue, CFBooleanRef};
use core_foundation_sys::string as cfs;

use libc::{c_char, c_int, c_void, statfs};

use std::ffi::{OsStr, OsString};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

fn to_path(mount_path: &[c_char]) -> Option<PathBuf> {
    let mut tmp = Vec::with_capacity(mount_path.len());
    for &c in mount_path {
        if c == 0 {
            break;
        }
        tmp.push(c as u8);
    }
    if tmp.is_empty() {
        None
    } else {
        let path = OsStr::from_bytes(&tmp);
        Some(PathBuf::from(path))
    }
}

pub(crate) fn get_disks(session: ffi::DASessionRef) -> Vec<Disk> {
    if session.is_null() {
        return Vec::new();
    }
    let count = unsafe { libc::getfsstat(ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if count < 1 {
        return Vec::new();
    }
    let bufsize = count * mem::size_of::<libc::statfs>() as c_int;
    let mut disks = Vec::with_capacity(count as _);
    let count = unsafe { libc::getfsstat(disks.as_mut_ptr(), bufsize, libc::MNT_NOWAIT) };
    if count < 1 {
        return Vec::new();
    }
    unsafe {
        disks.set_len(count as _);
    }
    disks
        .into_iter()
        .filter_map(|c_disk| {
            let mount_point = to_path(&c_disk.f_mntonname)?;
            unsafe {
                let disk = ffi::DADiskCreateFromBSDName(
                    kCFAllocatorDefault as _,
                    session,
                    c_disk.f_mntfromname.as_ptr(),
                );
                let dict = ffi::DADiskCopyDescription(disk);
                if dict.is_null() {
                    return None;
                }
                // Keeping this around in case one might want the list of the available
                // keys in "dict".
                // core_foundation_sys::base::CFShow(dict as _);
                let name = match get_str_value(dict, b"DAMediaName\0").map(OsString::from) {
                    Some(n) => n,
                    None => return None,
                };
                let removable = get_bool_value(dict, b"DAMediaRemovable\0").unwrap_or(false);
                let ejectable = get_bool_value(dict, b"DAMediaEjectable\0").unwrap_or(false);
                // This is very hackish but still better than nothing...
                let type_ = if let Some(model) = get_str_value(dict, b"DADeviceModel\0") {
                    if model.contains("SSD") {
                        DiskType::SSD
                    } else {
                        // We just assume by default that this is a HDD
                        DiskType::HDD
                    }
                } else {
                    DiskType::Unknown(-1)
                };

                CFRelease(dict as _);
                new_disk(name, mount_point, type_, removable || ejectable)
            }
        })
        .collect::<Vec<_>>()
}

unsafe fn get_dict_value<T, F: FnOnce(*const c_void) -> Option<T>>(
    dict: CFDictionaryRef,
    key: &[u8],
    callback: F,
) -> Option<T> {
    let key = ffi::CFStringCreateWithCStringNoCopy(
        ptr::null_mut(),
        key.as_ptr() as *const c_char,
        cfs::kCFStringEncodingUTF8,
        kCFAllocatorNull as _,
    );
    let mut value = std::ptr::null();
    let ret = if CFDictionaryGetValueIfPresent(dict, key as _, &mut value) != 0 {
        callback(value)
    } else {
        None
    };
    CFRelease(key as _);
    ret
}

unsafe fn get_str_value(dict: CFDictionaryRef, key: &[u8]) -> Option<String> {
    get_dict_value(dict, key, |v| {
        let v = v as cfs::CFStringRef;
        let len = cfs::CFStringGetLength(v);
        utils::cstr_to_rust_with_size(
            cfs::CFStringGetCStringPtr(v, cfs::kCFStringEncodingUTF8),
            Some(len as _),
        )
    })
}

unsafe fn get_bool_value(dict: CFDictionaryRef, key: &[u8]) -> Option<bool> {
    get_dict_value(dict, key, |v| Some(v as CFBooleanRef == kCFBooleanTrue))
}

fn new_disk(
    name: OsString,
    mount_point: PathBuf,
    type_: DiskType,
    is_removable: bool,
) -> Option<Disk> {
    let mount_point_cpath = to_cpath(&mount_point);
    let mut total_space = 0;
    let mut available_space = 0;
    let mut file_system = None;
    unsafe {
        let mut stat: statfs = mem::zeroed();
        if statfs(mount_point_cpath.as_ptr() as *const i8, &mut stat) == 0 {
            total_space = u64::from(stat.f_bsize) * stat.f_blocks;
            available_space = u64::from(stat.f_bsize) * stat.f_bavail;
            let mut vec = Vec::with_capacity(stat.f_fstypename.len());
            for x in &stat.f_fstypename {
                if *x == 0 {
                    break;
                }
                vec.push(*x as u8);
            }
            file_system = Some(vec);
        }
    }
    if total_space == 0 {
        return None;
    }
    Some(Disk {
        type_,
        name,
        file_system: file_system.unwrap_or_else(|| b"<Unknown>".to_vec()),
        mount_point,
        total_space,
        available_space,
        is_removable,
    })
}
