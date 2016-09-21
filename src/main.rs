extern crate libc;

#[macro_use]
mod macros;
mod sysname;

const ORIG_RAX: usize = 15;
const RAX: usize = 10;

const PTRACE_O_TRACESYSGOOD: libc::c_int = 1;
const PTRACE_O_TRACEEXEC: libc::c_int = 16;
const PTRACE_O_EXITKILL: libc::c_int = 1048576;

use std::ops::{BitAnd, BitXor, Mul, Not};
use std::ffi::CString;
use std::ptr;
use std::mem;
use self::sysname::SyscallName;

#[repr(C)]
#[derive(Default,Clone,Debug)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub fs: u64,
    pub gs: u64
}

fn my_stop_condition(pid: libc::pid_t) -> bool {
    unsafe {
        let mut status: libc::c_int = 0;

        loop {
            libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0);
            libc::waitpid(pid, &mut status, 0);
            if libc::WIFSTOPPED(status).bitand(
                libc::WSTOPSIG(status).bitand(0x80).is_positive()
            ) {
                return true
            } else if libc::WIFEXITED(status) {
                return false
            }
        }
    }
}

fn main() {
    unsafe {
        match libc::fork() {
            0 => {
                let mut ptrs = [
                    CString::new("bash").unwrap().as_ptr(),
                    ptr::null(),
                ];
                libc::execvp(*ptrs.as_ptr(), ptrs.as_mut_ptr());
            },
            pid => {
                let mut in_syscall: bool = true;
                libc::ptrace(
                    libc::PTRACE_SEIZE, pid, 0,
                    self::PTRACE_O_TRACESYSGOOD.bitxor(PTRACE_O_TRACEEXEC)
                                               .bitxor(PTRACE_O_EXITKILL)
                );
                libc::ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0);
                while my_stop_condition(pid) {
                    if in_syscall {
                        let mut regs: UserRegs = UserRegs::default();
                        libc::ptrace(
                            libc::PTRACE_PEEKUSER,
                            pid,
                            mem::size_of::<libc::c_long>().mul(ORIG_RAX),
                            ptr::null_mut::<*const libc::c_void>()
                        );
                        libc::ptrace(
                            libc::PTRACE_GETREGS,
                            pid,
                            ptr::null_mut::<*const libc::c_void>(),
                            &mut regs,
                        );
                        println!("{}", SyscallName::new(regs.orig_rax).unwrap() );
                    } else {
                        libc::ptrace(
                            libc::PTRACE_PEEKUSER,
                            pid,
                            mem::size_of::<libc::c_long>().mul(RAX),
                            ptr::null_mut::<*const libc::c_void>()
                        );
                    }
                    in_syscall = in_syscall.not();
                }
            },
        }
    }
}
