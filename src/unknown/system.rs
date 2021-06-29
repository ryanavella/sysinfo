//
// Sysinfo
//
// Copyright (c) 2015 Guillaume Gomez
//

use crate::{
    sys::{component::Component, Disk, Networks, Process, Processor},
    LoadAvg, Pid, RefreshKind, SystemExt, User,
};

use std::collections::HashMap;

/// Structs containing system's information.
pub struct System {
    processes_list: HashMap<Pid, Process>,
    networks: Networks,
    global_processor: Processor,
}

impl SystemExt for System {
    const IS_SUPPORTED: bool = false;

    fn new_with_specifics(_: RefreshKind) -> System {
        System {
            processes_list: Default::default(),
            networks: Networks::new(),
            global_processor: Processor::new(),
        }
    }

    fn refresh_memory(&mut self) {}

    fn refresh_cpu(&mut self) {}

    fn refresh_components_list(&mut self) {}

    fn refresh_processes(&mut self) {}

    fn refresh_process(&mut self, _pid: Pid) -> bool {
        false
    }

    fn refresh_disks_list(&mut self) {}

    fn refresh_users_list(&mut self) {}

    // COMMON PART
    //
    // Need to be moved into a "common" file to avoid duplication.

    fn processes(&self) -> &HashMap<Pid, Process> {
        &self.processes_list
    }

    fn process(&self, _pid: Pid) -> Option<&Process> {
        None
    }

    fn networks(&self) -> &Networks {
        &self.networks
    }

    fn networks_mut(&mut self) -> &mut Networks {
        &mut self.networks
    }

    fn global_processor_info(&self) -> &Processor {
        &self.global_processor
    }

    fn processors(&self) -> &[Processor] {
        &[]
    }

    fn physical_core_count(&self) -> Option<usize> {
        None
    }

    fn total_memory(&self) -> u64 {
        0
    }

    fn free_memory(&self) -> u64 {
        0
    }

    fn available_memory(&self) -> u64 {
        0
    }

    fn used_memory(&self) -> u64 {
        0
    }

    fn total_swap(&self) -> u64 {
        0
    }

    fn free_swap(&self) -> u64 {
        0
    }

    fn used_swap(&self) -> u64 {
        0
    }

    fn components(&self) -> &[Component] {
        &[]
    }

    fn components_mut(&mut self) -> &mut [Component] {
        &mut []
    }

    fn disks(&self) -> &[Disk] {
        &[]
    }

    fn disks_mut(&mut self) -> &mut [Disk] {
        &mut []
    }

    fn uptime(&self) -> u64 {
        0
    }

    fn boot_time(&self) -> u64 {
        0
    }

    fn load_average(&self) -> LoadAvg {
        LoadAvg {
            one: 0.,
            five: 0.,
            fifteen: 0.,
        }
    }

    fn users(&self) -> &[User] {
        &[]
    }

    fn name(&self) -> Option<String> {
        None
    }

    fn long_os_version(&self) -> Option<String> {
        None
    }

    fn kernel_version(&self) -> Option<String> {
        None
    }

    fn os_version(&self) -> Option<String> {
        None
    }

    fn host_name(&self) -> Option<String> {
        None
    }
}

impl Default for System {
    fn default() -> System {
        System::new()
    }
}
