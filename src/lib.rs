/*
 * Copyright 2025 Jason King
 */

use bitflags::bitflags;
use libc::{c_int, c_short, c_uchar, c_ulong, c_void, ioctl, size_t, uintptr_t};
use std::os::fd::RawFd;

pub const USCSIIOC: c_ulong = 0x04 << 8;
pub const USCSICMD: c_ulong = USCSIIOC | 201;
pub const USCSIMAXXFER: c_ulong = USCSIIOC | 202;

bitflags! {
    pub struct Flags: c_int {
        const SILENT = 0x0000_0001;
        const DIAGNOSE = 0x0000_0002;
        const ISOLATE = 0x0000_0004;
        const READ = 0x0000_0008;
        const WRITE = 0x0000_0000;
        const RESET = 0x0000_4000;
        const RESET_ALL = 0x0000_8000;
        const RQENABLE = 0x0001_0000;
        const RENEGOT = 0x0002_0000;
        const RESET_LUN = 0x0004_0000;
        const PATH_INSTANCE = 0x0008_0000;
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct UScsiCmd {
    flags: c_int,
    status: c_short,
    timeout: c_short,
    cdb: uintptr_t,
    bufaddr: uintptr_t,
    buflen: size_t,
    resid: size_t,
    cdblen: c_uchar,
    rqlen: c_uchar,
    rqstatus: c_uchar,
    rqresid: c_uchar,
    rqbuf: uintptr_t,
    path_instance: c_ulong,
}

unsafe fn common(
    fd: RawFd,
    cdb: &[u8],
    data: uintptr_t,
    datalen: usize,
    sense: Option<&mut [u8]>,
    flags: Flags,
    timeout: u16,
) -> Result<(usize, usize), std::io::Error> {
    let mut flags = flags;
    let (rqbuf, rqlen) = if let Some(sensebuf) = sense {
        flags = flags | Flags::RQENABLE;
        (sensebuf.as_ptr() as uintptr_t, sensebuf.len() as c_uchar)
    } else {
        (0, 0)
    };

    let mut cmd = UScsiCmd {
        flags: flags.bits(),
        status: 0,
        timeout: timeout as i16,
        cdb: cdb.as_ptr() as _,
        bufaddr: data,
        buflen: datalen as size_t,
        resid: 0,
        cdblen: cdb.len() as c_uchar,
        rqlen: rqlen,
        rqstatus: 0,
        rqresid: 0,
        rqbuf: rqbuf,
        path_instance: 0,
    };

    match ioctl(fd, USCSICMD, &mut cmd as *mut _ as *mut c_void) {
        0 => Ok((cmd.resid, cmd.rqresid as usize)),
        _ => Err(std::io::Error::last_os_error()),
    }
}

pub unsafe fn read(
    fd: RawFd,
    cdb: &[u8],
    data: &mut [u8],
    sense: Option<&mut [u8]>,
    flags: Flags,
    timeout: u16
) -> Result<(usize, usize), std::io::Error> {
    let data_addr = data.as_mut_ptr() as uintptr_t;
    let data_len = data.len();
    let flags = flags | Flags::READ;

    common(fd, cdb, data_addr, data_len, sense, flags, timeout)
}

pub unsafe fn write(
    fd: RawFd,
    cdb: &[u8],
    data: &mut [u8],
    sense: Option<&mut [u8]>,
    flags: Flags,
    timeout: u16
) -> Result<(usize, usize), std::io::Error> {
    let data_addr = data.as_ptr() as uintptr_t;
    let data_len = data.len();
    let flags = flags | Flags::WRITE;

    common(fd, cdb, data_addr, data_len, sense, flags, timeout)
}

pub unsafe fn reset(fd: RawFd) -> Result<(), std::io::Error> {
    let flags = Flags::RESET;
    let mut cmd = UScsiCmd::default();

    cmd.flags = flags.bits();

    match ioctl(fd, USCSICMD, &mut cmd as *mut _ as *mut c_void) {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

pub fn max_xfer(fd: RawFd) -> Result<usize, std::io::Error> {
    let mut val: u64 = 0;

    // SAFETY: This should only query the kernel driver and not result
    // in any device I/O
    match unsafe { ioctl(fd, USCSIMAXXFER, &mut val as *mut _) } {
        0 => Ok(val as usize),
        _ => Err(std::io::Error::last_os_error()),
    }
}