"""Kernel namespace manager for one untrusted reviewer process tree."""

from __future__ import annotations

import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


PR_SET_PDEATHSIG = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
STOP_REQUESTED = False


def _set_stop_requested(_signum: int, _frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def _set_parent_death_signal() -> bool:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) == 0
    except (AttributeError, OSError):
        return False


def _write_user_mapping(outer_uid: int, outer_gid: int) -> None:
    setgroups = Path("/proc/self/setgroups")
    if setgroups.is_file():
        setgroups.write_text("deny", encoding="ascii")
    Path("/proc/self/uid_map").write_text(
        f"0 {outer_uid} 1", encoding="ascii"
    )
    Path("/proc/self/gid_map").write_text(
        f"0 {outer_gid} 1", encoding="ascii"
    )


def _mount_private_proc() -> bool:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return (
            libc.mount(
                b"proc",
                b"/proc",
                b"proc",
                MS_NOSUID | MS_NODEV | MS_NOEXEC,
                None,
            )
            == 0
        )
    except (AttributeError, OSError):
        return False


def _proc_is_pid_namespace_local() -> bool:
    try:
        visible = {
            entry.name
            for entry in Path("/proc").iterdir()
            if entry.name.isascii() and entry.name.isdecimal()
        }
        status = Path("/proc/1/status").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return False
    return os.getpid() == 1 and visible == {"1"} and "\nNSpid:\t1\n" in status


def _write_handshake(descriptor: int) -> bool:
    payload = json.dumps(
        {
            "boundary": "pid_namespace",
            "inner_pid": os.getpid(),
            "mount_namespace": True,
            "pid_namespace": True,
            "proc_isolated": True,
            "user_namespace": True,
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


def _direct_children() -> dict[int, str]:
    children: dict[int, str] = {}
    parent = os.getpid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        _, separator, suffix = raw.rpartition(")")
        fields = suffix.split()
        if not separator or len(fields) < 2:
            raise RuntimeError("namespace procfs child state is malformed")
        if int(fields[1]) == parent:
            children[int(entry.name)] = fields[0]
    return children


def _reap_zombies(children: dict[int, str]) -> None:
    for pid, state in children.items():
        if state != "Z":
            continue
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass


def _signal_live_children(children: dict[int, str], signum: int) -> None:
    for pid, state in children.items():
        if state == "Z":
            continue
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass


def _drain_descendants(timeout: float = 2.0) -> tuple[bool, bool]:
    deadline = time.monotonic() + timeout
    kill_after = time.monotonic() + min(0.5, timeout / 2)
    observed_live = False
    empty_observations = 0
    while time.monotonic() < deadline:
        try:
            children = _direct_children()
        except (OSError, RuntimeError, UnicodeError, ValueError):
            return observed_live, False
        _reap_zombies(children)
        try:
            children = _direct_children()
        except (OSError, RuntimeError, UnicodeError, ValueError):
            return observed_live, False
        live = {pid: state for pid, state in children.items() if state != "Z"}
        if live:
            observed_live = True
            empty_observations = 0
            _signal_live_children(
                live,
                signal.SIGKILL if time.monotonic() >= kill_after else signal.SIGTERM,
            )
        elif not children:
            empty_observations += 1
            if empty_observations >= 2:
                return observed_live, True
        else:
            empty_observations = 0
        time.sleep(0.02)
    try:
        children = _direct_children()
        _reap_zombies(children)
        return observed_live, not _direct_children()
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return observed_live, False


def _run_namespace_init(command: list[str], handshake_descriptor: int) -> int:
    signal.signal(signal.SIGTERM, _set_stop_requested)
    signal.signal(signal.SIGINT, _set_stop_requested)
    if not _write_handshake(handshake_descriptor):
        return 126
    try:
        child = subprocess.Popen(command, close_fds=True)
    except OSError:
        return 126
    term_sent_at: float | None = None
    while child.poll() is None:
        if STOP_REQUESTED:
            if term_sent_at is None:
                term_sent_at = time.monotonic()
                try:
                    child.terminate()
                except ProcessLookupError:
                    pass
            elif time.monotonic() - term_sent_at >= 0.5:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
        time.sleep(0.02)
    child_return_code = child.wait()
    descendants_observed, cleanup_complete = _drain_descendants()
    if not cleanup_complete:
        return 126
    if descendants_observed or STOP_REQUESTED:
        return 125
    if child_return_code < 0:
        return min(255, 128 + -child_return_code)
    return child_return_code


def _exit_from_wait_status(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return min(255, 128 + os.WTERMSIG(status))
    return 126


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 3 or arguments[1] != "--":
        return 126
    try:
        handshake_descriptor = int(arguments[0])
    except ValueError:
        return 126
    command = arguments[2:]
    required_flags = ("CLONE_NEWUSER", "CLONE_NEWPID", "CLONE_NEWNS")
    if not sys.platform.startswith("linux") or not hasattr(os, "unshare") or any(
        not hasattr(os, name) for name in required_flags
    ):
        return 126
    outer_uid = os.getuid()
    outer_gid = os.getgid()
    supervisor_pid = os.getppid()
    if not _set_parent_death_signal() or os.getppid() != supervisor_pid:
        return 126
    try:
        os.unshare(os.CLONE_NEWUSER)
        _write_user_mapping(outer_uid, outer_gid)
        os.unshare(os.CLONE_NEWPID | os.CLONE_NEWNS)
        child_pid = os.fork()
    except (OSError, RuntimeError):
        return 126
    if child_pid != 0:
        try:
            os.close(handshake_descriptor)
        except OSError:
            pass
        try:
            _, status = os.waitpid(child_pid, 0)
        except (ChildProcessError, OSError):
            return 126
        return _exit_from_wait_status(status)

    if not _set_parent_death_signal():
        os._exit(126)
    if not _mount_private_proc() or not _proc_is_pid_namespace_local():
        os._exit(126)
    os._exit(_run_namespace_init(command, handshake_descriptor))


if __name__ == "__main__":
    raise SystemExit(main())
