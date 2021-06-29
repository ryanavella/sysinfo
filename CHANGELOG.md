# 0.19.0

 * Renamed functions/methods to follow [Rust API guidelines on naming](https://rust-lang.github.io/api-guidelines/naming.html#getter-names-follow-rust-convention-c-getter).
 * Linux: Set processes' executable path from command line if not found.
 * Linux: Added extra information about `ProcessExt::name()`.
 * macOS: Removed unneeded (re)import of CoreFoundation library at compile-time.
 * Reworked `DiskType` enum: there is no more `Removable` variant, it's now set into the `Disk` struct. `DiskExt::is_removable` was added.
 * Linux: Added support for removable disks.
 * Linux: Ensured there's a value in `global_processor` frequency.
 * Fixed tests to make them a bit less strict (which was problematic when run on VMs).
 * Linux: Fixed CPU usage subtraction overflow.

# 0.18.2

 * macOS: Brand and vendor ID information were reversed.
 * macOS: On Apple M1 processors, the vendor ID is empty, so instead we return "Apple".
 * Added tests to ensure that the processors are always set after `System::new()`.

# 0.18.1

 * Added `SystemExt::IS_SUPPORTED` constant to allow to easily query if a system is supported or not.
 * Used `SystemExt::IS_SUPPORTED` to fix tests on non-supported platforms and simplify others.

# 0.18.0

 * Improved documentation to make it more clear how to use the different information.
 * Turned the `Signal` enum into a full rust one by removing the `#[repr(C)]` attribute on it. Each platform now implements its own conversion.
 * Removed `Signal::Stklft` which wasn't used on any supported system.
 * Linux: Added support for paravirtualized disks.

# 0.17.5

 * Improved network code: network interfaces were handled a bit differently depending on the platform, it is now unified.

# 0.17.4

 * Linux: fixed invalid network interface cleanup when an interface was removed from the system in `refresh_networks_list`.
 * Added freebsd to CI runs.
 * Added `cargo test` command for freebsd on CI.
 * freebsd: Fixed build.

# 0.17.3

 * Removed manual FFI bindings in both Apple and Windows targets.
 * Fixed C-interface compilation.
 * Added information on how to add new platform.

# 0.17.2

 * Linux: fixed `System::refresh_process` return value.

# 0.17.1

 * Windows: fixed process CPU usage computation.
 * Linux: improved CPU usage values on first query by returning 0: it now waits the second cycle before computing it to avoid abherent values.
 * Linux: fixed process name retrieval by using `stat` information instead.
 * Apple: only list local users.

# 0.17.0

 * Linux: fixed OS version retrieval by adding a fallback to `/etc/lsb-release`.
 * iOS: fixed warnings.
 * Renamed `ProcessStatus::to_string` method to `as_str`.
 * macOS: fixed CPU usage computation.

# 0.16.5

 * Windows: Removed trailing NUL bytes in hostname.
 * Added user ID and group ID.

# 0.16.4

 * macOS: Removed trailing NUL bytes in various values returned by the `sysctl` calls.

# 0.16.3

 * Updated minimum libc version to 0.2.86.

# 0.16.2

 * Fixed network values computation: replaced the simple arithmetic with `saturating_sub` and `saturating_add`.
 * Converted values read in `/proc/meminfo` from KiB to KB (because contrary to what is said in the manual, they are in KiB, not in KB).
 * macOS: Rewrote `get_disks` function to remove the Objective-C dependency.
 * Added `SystemExt::get_long_os_version`.
 * Linux: Fixed sequences for disks.
 * Linux: Allowed `/run/media` as a mount path.
 * Windows: Fixed disk size computation.
 * Linux: Fixed virtual memory size computation.

# 0.16.1

 * Added support for Android.
 * Added flag to remove APIs prohibited in Apple store.

# 0.16.0

 * Windows: show removeable drives on Windows.
 * Switched to Rust 2018 edition.
 * Split `SystemExt::get_version` into `SystemExt::get_kernel_version` and `SystemExt::get_os_version`.
 * Windows: added support for `get_kernel_version` and `get_os_version`.
 * Changed return type of `SystemExt::get_physical_core_count` from `usize` to `Option<usize>`.
 * Added `SystemExt::get_physical_core_numbers`.

# 0.15.9

 * iOS: Fixed build.
 * Fixed cross-compilation.

# 0.15.8

 * Apple: fixed Objective-C library imports.

# 0.15.7

 * Added `SystemExt::get_host_name`.

# 0.15.6

 * Upgraded `cfg-if` dependency version to `1.0`.

# 0.15.5

 * Added `SystemExt::get_name` and `SystemExt::get_version`.
 * Added `multithread` feature, making the `rayon` dependency optional.

# 0.15.4

 * Apple: gig source code cleanup.
 * Apple: improved disk handling.
 * Removed manual FFI code and used libc's instead.

# 0.15.3

 * Prevented CPU value to be NaN.

# 0.15.2

 * macOS: fixed disk space computation.

# 0.15.1

 * Improved documentation.
 * Extended example.

# 0.15.0

 * Added `SystemExt::get_available_memory`.

# 0.14.15

 * Linux: improved task source code.

# 0.14.14

 * macOS: renamed "CPU" into "CPU Die".
 * macOS: added "CPU proximity" information.

# 0.14.13

 * Linux: improved process name retrieval.

# 0.14.12

 * Linux: fixed infinite recursion when gathering disk information.

# 0.14.11

 * Added iOS support.

# 0.14.10

 * Simplified `DiskType` handling by removing `From` implementation.
 * Linux: fixed SSD/HDD detection.

# 0.14.9

 * Linux: fixed CPU usage computation.
 * Windows: fixed load average constants.

# 0.14.8

 * Linux: fixed network information retrieval by replacing `usize` with `u64` because it was too small on 32 bits systems.
 * Linux: get each core frequency.

# 0.14.7

 * Raspberry Pi: fixed temperature retrieval.

# 0.14.6

 * Linux: fixed infinite recursion when getting disk.

# 0.14.5

 * Strengthened cfg checks: use "linux" and "android" instead of "unix".

# 0.14.4

 * Linux: fixed memory usage computation.

# 0.14.3

 * Linux: fixed memory usage computation.

# 0.14.2

 * Windows: fixed CPU usage computation overflow.
 * macOS: fixed CPU usage computation overflow.
 * Windows: retrieved command line.

# 0.14.1

* Removed empty disks.

# 0.14.0

 * Converted KiB to KB.

# 0.13.4

 * Code improvements.

# 0.13.3

 * Linux: fixed some issues on disks retrieval.
 * Linux: fixed out-of-bound access in `boot_time`.
 * Added benchmark on `Disk::refresh`.
