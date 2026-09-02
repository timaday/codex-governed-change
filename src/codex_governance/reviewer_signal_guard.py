"""Linux seccomp guard that prevents a reviewer tree from attacking supervisors."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import platform
import signal
import sys


PR_SET_PDEATHSIG = 1
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JSET_K = 0x45
BPF_RET_K = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
X32_SYSCALL_BIT = 0x40000000

AUDIT_ARCH = {
    "aarch64": 0xC00000B7,
    "x86_64": 0xC000003E,
}

DENIED_SYSCALLS = {
    "aarch64": (
        117,  # ptrace
        129,  # kill
        130,  # tkill
        131,  # tgkill
        138,  # rt_sigqueueinfo
        240,  # rt_tgsigqueueinfo
        261,  # prlimit64
        271,  # process_vm_writev
        424,  # pidfd_send_signal
        440,  # process_madvise
    ),
    "x86_64": (
        62,   # kill
        101,  # ptrace
        129,  # rt_sigqueueinfo
        200,  # tkill
        234,  # tgkill
        297,  # rt_tgsigqueueinfo
        302,  # prlimit64
        311,  # process_vm_writev
        424,  # pidfd_send_signal
        440,  # process_madvise
    ),
}

PRLIMIT64_SYSCALLS = {
    "aarch64": 261,
    "x86_64": 302,
}

FCNTL_SYSCALLS = {
    "aarch64": 25,
    "x86_64": 72,
}

IOCTL_SYSCALLS = {
    "aarch64": 29,
    "x86_64": 16,
}

# Linux fcntl commands that unconditionally configure asynchronous delivery.
DENIED_FCNTL_COMMANDS = (
    8,     # F_SETOWN
    10,    # F_SETSIG
    15,    # F_SETOWN_EX
    1024,  # F_SETLEASE
    1026,  # F_NOTIFY
)

# Linux socket/terminal ioctl requests that configure asynchronous delivery.
# These public UAPI values are stable across the supported architectures.
DENIED_IOCTL_REQUESTS = (
    0x5452,  # FIOASYNC
    0x8901,  # FIOSETOWN / SIOCSETOWN
    0x8902,  # SIOCSPGRP
)

SECCOMP_DATA_ARGUMENT_1_LOW = 24
SECCOMP_DATA_ARGUMENT_2_LOW = 32
F_SETFL_COMMAND = 4
ASYNC_STATUS_FLAG = os.O_ASYNC


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(_SockFilter)),
    ]


def _install_signal_guard() -> bool:
    machine = platform.machine().lower()
    architecture = AUDIT_ARCH.get(machine)
    syscalls = DENIED_SYSCALLS.get(machine)
    if architecture is None or syscalls is None:
        return False
    instructions = [
        _SockFilter(BPF_LD_W_ABS, 0, 0, 4),
        _SockFilter(BPF_JMP_JEQ_K, 1, 0, architecture),
        _SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        _SockFilter(BPF_LD_W_ABS, 0, 0, 0),
    ]
    if machine == "x86_64":
        instructions.extend(
            (
                _SockFilter(BPF_JMP_JSET_K, 0, 1, X32_SYSCALL_BIT),
                _SockFilter(
                    BPF_RET_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | errno.EPERM,
                ),
            )
        )
    fcntl_syscall = FCNTL_SYSCALLS[machine]
    fcntl_filter_length = 6 + 2 * len(DENIED_FCNTL_COMMANDS)
    instructions.append(
        _SockFilter(BPF_JMP_JEQ_K, 0, fcntl_filter_length, fcntl_syscall)
    )
    instructions.append(_SockFilter(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARGUMENT_1_LOW))
    for command in DENIED_FCNTL_COMMANDS:
        instructions.extend(
            (
                _SockFilter(BPF_JMP_JEQ_K, 0, 1, command),
                _SockFilter(
                    BPF_RET_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | errno.EPERM,
                ),
            )
        )
    instructions.extend(
        (
            _SockFilter(BPF_JMP_JEQ_K, 0, 3, F_SETFL_COMMAND),
            _SockFilter(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARGUMENT_2_LOW),
            _SockFilter(BPF_JMP_JSET_K, 0, 1, ASYNC_STATUS_FLAG),
            _SockFilter(
                BPF_RET_K,
                0,
                0,
                SECCOMP_RET_ERRNO | errno.EPERM,
            ),
        )
    )
    instructions.append(_SockFilter(BPF_LD_W_ABS, 0, 0, 0))
    ioctl_syscall = IOCTL_SYSCALLS[machine]
    ioctl_filter_length = 2 + 2 * len(DENIED_IOCTL_REQUESTS)
    instructions.append(
        _SockFilter(BPF_JMP_JEQ_K, 0, ioctl_filter_length, ioctl_syscall)
    )
    instructions.append(_SockFilter(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARGUMENT_1_LOW))
    for request in DENIED_IOCTL_REQUESTS:
        instructions.extend(
            (
                _SockFilter(BPF_JMP_JEQ_K, 0, 1, request),
                _SockFilter(
                    BPF_RET_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | errno.EPERM,
                ),
            )
        )
    instructions.append(_SockFilter(BPF_LD_W_ABS, 0, 0, 0))
    for syscall in sorted(set(syscalls)):
        instructions.extend(
            (
                _SockFilter(BPF_JMP_JEQ_K, 0, 1, syscall),
                _SockFilter(
                    BPF_RET_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | errno.EPERM,
                ),
            )
        )
    instructions.append(_SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    filters = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), filters)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            return False
        if libc.prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            ctypes.byref(program),
            0,
            0,
        ) != 0:
            return False
    except (AttributeError, OSError):
        return False
    return True


def _write_handshake(descriptor: int) -> bool:
    payload = json.dumps(
        {
            "boundary": "seccomp_signal_guard",
            "cross_process_write_blocked": True,
            "no_new_privs": True,
            "process_signals_blocked": True,
            "resource_limit_changes_blocked": True,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    try:
        return os.write(descriptor, payload) == len(payload)
    except OSError:
        return False
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 3 or arguments[1] != "--":
        return 126
    try:
        handshake_descriptor = int(arguments[0])
    except ValueError:
        return 126
    command = arguments[2:]
    supervisor_pid = os.getppid()
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            return 126
    except (AttributeError, OSError):
        return 126
    if os.getppid() != supervisor_pid or not _install_signal_guard():
        return 126
    try:
        os.kill(supervisor_pid, 0)
    except PermissionError:
        pass
    else:
        return 126
    if not _write_handshake(handshake_descriptor):
        return 126
    try:
        os.execvpe(command[0], command, os.environ)
    except OSError:
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
