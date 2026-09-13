"""Check that `-cgroup-root` is honoured, the way upstream envd honours it.

Run as root: python3 cgroup_root_e2e.py /path/to/cube-envd [/sys/fs/cgroup]

Upstream Go envd registers `-cgroup-root` and passes a non-empty value to its
cgroup2 manager (`main.go:99-100`, `main.go:281-282`). cube-envd used to
recognise the flag, warn, and ignore it, so a deployment that passed it got a
different cgroup root than Go would have used. This script pins the fixed
behaviour by starting the daemon under each configuration and asking a command
where it landed (`cat /proc/self/cgroup`):

  1. `-cgroup-root <flag-root>`                     -> flag-root
  2. `CUBE_ENVD_CGROUP_ROOT=<env-root>` only        -> env-root
  3. both, with different values                    -> flag-root (flag wins)
  4. neither                                        -> the /sys/fs/cgroup default

Each case checks that the cgroup subtree the daemon created really is the one
the command reports, not just what the daemon logged. Needs a writable cgroup v2
root (so: root, in a guest or on a host with cgroup2 mounted); only the
subtrees it creates are removed afterwards.
"""

import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

AUTH = {"Authorization": "Basic cm9vdDo="}
CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  — ' + detail) if detail else ''}", flush=True)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def start_daemon(binary, port, log, env=None, extra_args=()):
    environment = {**os.environ, **(env or {})}
    return subprocess.Popen(
        [str(binary), "-port", str(port), *extra_args],
        stdout=log.open("w"), stderr=subprocess.STDOUT, env=environment,
    )


def wait_healthy(port, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            connection.request("GET", "/health")
            status = connection.getresponse().status
            connection.close()
            if status in (200, 204):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def run_command(port, command):
    """One Connect-JSON `Start`, returning the decoded stdout."""
    payload = json.dumps(
        {"process": {"cmd": "/bin/sh", "args": ["-c", command], "envs": {}}, "stdin": False}
    ).encode()
    body = bytes([0]) + struct.pack(">I", len(payload)) + payload
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    connection.request(
        "POST", "/process.Process/Start", body=body,
        headers={**AUTH, "Content-Type": "application/connect+json", "Connect-Protocol-Version": "1"},
    )
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    out = b""
    index = 0
    while index + 5 <= len(raw):
        length = struct.unpack(">I", raw[index + 1:index + 5])[0]
        frame = raw[index + 5:index + 5 + length]
        index += 5 + length
        try:
            event = json.loads(frame).get("event", {})
        except ValueError:
            continue
        data = event.get("data", {}).get("stdout")
        if data:
            import base64
            out += base64.b64decode(data)
    return out.decode(errors="replace")


def case(binary, label, flag_root, env_root, expect_marker, workdir):
    """Start the daemon and check where a command lands.

    `/proc/self/cgroup` reports the path relative to the *cgroup namespace*
    root, which inside a sandbox is the sandbox's own scope (e.g.
    `/default/<template>_0`), not `/sys/fs/cgroup` — so the assertion is on the
    tail the daemon chose, which is exactly what the flag/env test is about.
    """
    port = free_port()
    log = workdir / f"envd-{label}.log"
    args = ["-cgroup-root", str(flag_root)] if flag_root else []
    env = {"CUBE_ENVD_CGROUP_ROOT": str(env_root)} if env_root else None
    daemon = start_daemon(binary, port, log, env=env, extra_args=args)
    try:
        if not wait_healthy(port):
            check(f"{label}: daemon healthy", False, f"see {log}")
            return
        tail = run_command(port, "cat /proc/self/cgroup").strip().split("::", 1)[-1]
        if expect_marker is None:
            landed = "/user/process-" in tail and "cube-envd-e2e" not in tail
            check(f"{label}: command lands in the default subtree", landed, tail)
        else:
            landed = expect_marker + "/user/process-" in tail
            # The losing form must not be what took effect (precedence).
            other = "cube-envd-e2e-env" if "flag" in expect_marker else "cube-envd-e2e-flag"
            precedence = other not in tail
            check(f"{label}: command lands under {expect_marker}", landed and precedence, tail)
        # The daemon must have created its subtree under that root, not merely
        # reported it: the user/ptys subtrees live there.
        if flag_root or env_root:
            user_dir = Path(flag_root or env_root) / "user"
            check(f"{label}: {user_dir} exists", user_dir.is_dir())
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()


def cleanup(root):
    for _ in range(20):
        if not root.exists():
            return
        for child in sorted(root.rglob("*"), key=lambda p: -len(p.parts)):
            if child.is_dir():
                child.rmdir() if not any(child.iterdir()) else None
        try:
            if not any(root.iterdir()):
                root.rmdir()
                return
        except OSError:
            pass
        time.sleep(0.2)


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "target/x86_64-linux-musl/release/cube-envd")
    base = Path(sys.argv[2] if len(sys.argv) > 2 else "/sys/fs/cgroup")
    if not binary.exists():
        raise SystemExit(f"cube-envd binary not found: {binary}")
    if os.geteuid() != 0:
        raise SystemExit("this check writes cgroup subtrees; run it as root")
    if not (base / "cgroup.controllers").exists():
        raise SystemExit(f"{base} is not a cgroup v2 root")

    workdir = Path(tempfile.mkdtemp(prefix="cube-envd-cgroup-e2e-"))
    flag_root = base / "cube-envd-e2e-flag"
    env_root = base / "cube-envd-e2e-env"
    for root in (flag_root, env_root):
        root.mkdir(exist_ok=True)
    try:
        case(binary, "flag", flag_root, None, "cube-envd-e2e-flag", workdir)
        case(binary, "env", None, env_root, "cube-envd-e2e-env", workdir)
        case(binary, "both", flag_root, env_root, "cube-envd-e2e-flag", workdir)
        case(binary, "default", None, None, None, workdir)
    finally:
        for root in (flag_root, env_root):
            cleanup(root)
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\n{sum(CHECKS)} passed, {len(CHECKS) - sum(CHECKS)} failed")
    if not all(CHECKS):
        raise SystemExit(1)


main()
