"""Linux child-subreaper supervisor for one fresh reviewer invocation."""

from __future__ import annotations

import ctypes
import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path


PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
STOP_REQUESTED = False


def _set_stop_requested(_signum: int, _frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def _enable_subreaper() -> bool:
    if not sys.platform.startswith("linux") or not Path("/proc").is_dir():
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        current = ctypes.c_int()
        if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) != 0:
            return False
        if current.value == 0 and libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            return False
        return True
    except (AttributeError, OSError):
        return False


def _direct_children() -> dict[int, str]:
    children: dict[int, str] = {}
    parent = os.getpid()
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        raise RuntimeError("procfs enumeration is unavailable")
    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError) as exc:
            raise RuntimeError("procfs child state is unavailable") from exc
        _, separator, suffix = raw.rpartition(")")
        fields = suffix.split()
        if not separator or len(fields) < 2:
            raise RuntimeError("procfs child state is malformed")
        try:
            process_parent = int(fields[1])
        except ValueError as exc:
            raise RuntimeError("procfs child state is malformed") from exc
        if process_parent == parent:
            children[int(entry.name)] = fields[0]
    return children


def _procfs_containment_available() -> bool:
    """Prove that procfs can identify descendants in this PID namespace."""
    try:
        raw_stat = Path("/proc/self/stat").read_text(encoding="ascii")
        prefix, separator, suffix = raw_stat.rpartition(")")
        fields = suffix.split()
        if not separator or len(fields) < 2:
            return False
        pid_text, opening, _command = prefix.partition("(")
        if not opening:
            return False
        if int(pid_text.strip()) != os.getpid() or int(fields[1]) != os.getppid():
            return False
        status = Path("/proc/self/status").read_text(encoding="ascii")
        namespace_lines = [
            line.split(":", 1)[1].split()
            for line in status.splitlines()
            if line.startswith("NSpid:")
        ]
        if len(namespace_lines) != 1 or not namespace_lines[0]:
            return False
        namespace_pids = namespace_lines[0]
        if any(
            not value.isascii()
            or not value.isdecimal()
            or int(value) < 1
            for value in namespace_pids
        ) or int(namespace_pids[-1]) != os.getpid():
            return False
        _direct_children()
        return True
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return False


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
            current = _direct_children()
            if current.get(pid) not in {None, "Z"}:
                os.kill(pid, signum)
        except ProcessLookupError:
            pass


def _drain_descendants(timeout: float = 2.0) -> tuple[bool, bool]:
    """Return whether a live descendant was observed and cleanup completed."""
    deadline = time.monotonic() + timeout
    kill_after = time.monotonic() + min(0.5, timeout / 2)
    observed_live = False
    empty_observations = 0
    while time.monotonic() < deadline:
        try:
            children = _direct_children()
        except RuntimeError:
            return observed_live, False
        _reap_zombies(children)
        try:
            children = _direct_children()
        except RuntimeError:
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
    except RuntimeError:
        return observed_live, False


def _write_status(descriptor: int, value: dict[str, object]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        os.write(descriptor, data)
    except OSError:
        pass
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _boundary_handshake(
    descriptor: int, child: subprocess.Popen[bytes], timeout: float = 5.0
) -> str | None:
    deadline = time.monotonic() + timeout
    data = bytearray()
    try:
        while time.monotonic() < deadline and len(data) <= 4096:
            ready, _, _ = select.select(
                [descriptor], [], [], min(0.05, deadline - time.monotonic())
            )
            if not ready:
                if child.poll() is not None:
                    return None
                continue
            chunk = os.read(descriptor, 4097 - len(data))
            if not chunk:
                break
            data.extend(chunk)
            try:
                value = json.loads(data.decode("ascii"))
            except (UnicodeError, ValueError):
                continue
            namespace = {
                "boundary": "pid_namespace",
                "inner_pid": 1,
                "mount_namespace": True,
                "pid_namespace": True,
                "proc_isolated": True,
                "user_namespace": True,
            }
            signal_guard = {
                "boundary": "seccomp_signal_guard",
                "cross_process_write_blocked": True,
                "no_new_privs": True,
                "process_signals_blocked": True,
                "resource_limit_changes_blocked": True,
            }
            if value == namespace:
                return "pid_namespace"
            if value == signal_guard:
                return "seccomp_signal_guard"
            return None
        return None
    except (OSError, ValueError):
        return None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _stop_boundary_child(child: subprocess.Popen[bytes]) -> bool:
    try:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=1.0)
        return True
    except OSError:
        return False
    except subprocess.TimeoutExpired:
        try:
            child.kill()
            child.wait(timeout=1.0)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 3 or arguments[1] != "--":
        return 126
    try:
        status_descriptor = int(arguments[0])
    except ValueError:
        return 126
    command = arguments[2:]
    status: dict[str, object] = {
        "boundary_available": False,
        "descendants_observed": False,
        "cleanup_complete": False,
        "child_return_code": None,
    }
    if not _enable_subreaper():
        _write_status(status_descriptor, status)
        return 126
    if not _procfs_containment_available():
        _write_status(status_descriptor, status)
        return 126
    signal.signal(signal.SIGTERM, _set_stop_requested)
    signal.signal(signal.SIGINT, _set_stop_requested)
    for async_signal in (signal.SIGIO, signal.SIGURG):
        signal.signal(async_signal, signal.SIG_IGN)
    handshake_read: int | None = None
    handshake_write: int | None = None
    try:
        handshake_read, handshake_write = os.pipe()
        os.set_inheritable(handshake_write, True)
        namespace_command = [
            sys.executable,
            os.fspath(Path(__file__).with_name("reviewer_namespace.py")),
            str(handshake_write),
            "--",
            *command,
        ]
        child = subprocess.Popen(
            namespace_command,
            close_fds=True,
            pass_fds=(handshake_write,),
        )
        os.close(handshake_write)
        handshake_write = None
    except OSError:
        for descriptor in (handshake_read, handshake_write):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        _write_status(status_descriptor, status)
        return 126
    boundary_kind = (
        _boundary_handshake(handshake_read, child)
        if handshake_read is not None
        else None
    )
    if boundary_kind is None:
        child_stopped = _stop_boundary_child(child)
        _, cleanup_complete = _drain_descendants()
        if not child_stopped or not cleanup_complete:
            status["cleanup_complete"] = False
            _write_status(status_descriptor, status)
            return 126
        handshake_read = None
        handshake_write = None
        try:
            handshake_read, handshake_write = os.pipe()
            os.set_inheritable(handshake_write, True)
            guard_command = [
                sys.executable,
                os.fspath(Path(__file__).with_name("reviewer_signal_guard.py")),
                str(handshake_write),
                "--",
                *command,
            ]
            child = subprocess.Popen(
                guard_command,
                close_fds=True,
                pass_fds=(handshake_write,),
            )
            os.close(handshake_write)
            handshake_write = None
        except OSError:
            for descriptor in (handshake_read, handshake_write):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            _write_status(status_descriptor, status)
            return 126
        boundary_kind = (
            _boundary_handshake(handshake_read, child)
            if handshake_read is not None
            else None
        )
        if boundary_kind != "seccomp_signal_guard":
            child_stopped = _stop_boundary_child(child)
            _, cleanup_complete = _drain_descendants()
            status["cleanup_complete"] = child_stopped and cleanup_complete
            _write_status(status_descriptor, status)
            return 126
    status["boundary_available"] = True
    status["boundary_kind"] = boundary_kind
    try:
        devnull = os.open(os.devnull, os.O_RDWR)
        for descriptor in (0, 1, 2):
            os.dup2(devnull, descriptor)
        if devnull > 2:
            os.close(devnull)
    except OSError:
        status["cleanup_complete"] = False
        _write_status(status_descriptor, status)
        try:
            child.terminate()
        except ProcessLookupError:
            pass
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
    status["child_return_code"] = child_return_code
    descendants_observed, cleanup_complete = _drain_descendants()
    status["descendants_observed"] = descendants_observed or child_return_code == 125
    status["cleanup_complete"] = cleanup_complete
    _write_status(status_descriptor, status)
    if not cleanup_complete:
        return 126
    if descendants_observed or STOP_REQUESTED:
        return 125
    if child_return_code < 0:
        return min(255, 128 + -child_return_code)
    return child_return_code


if __name__ == "__main__":
    raise SystemExit(main())
