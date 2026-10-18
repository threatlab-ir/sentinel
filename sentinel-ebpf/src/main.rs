#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use sentinel_common::ExecEvent;

#[map]
static EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

// Attached to sched:sched_process_exec, which fires once the new program's
// image (and comm) has fully replaced the old one. sys_enter_execve fires
// too early: comm still reflects the calling process, not the exec'd one.
#[tracepoint]
pub fn sentinel_execve(ctx: TracePointContext) -> u32 {
    match try_sentinel_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sentinel_execve(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let ppid = unsafe {
        let task = aya_ebpf::helpers::bpf_get_current_task() as *const u8;
        // Reading real_parent->tgid reliably needs BTF offsets (handled via
        // vmlinux.h / CO-RE in a fuller build). Left as 0 for this scaffold.
        let _ = task;
        0u32
    };

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = ExecEvent {
        pid,
        ppid,
        uid,
        gid,
        cgroup_id,
        comm,
    };

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
