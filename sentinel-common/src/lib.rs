#![cfg_attr(not(feature = "user"), no_std)]

pub const COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; COMM_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

#[cfg(feature = "user")]
pub mod protocol;
