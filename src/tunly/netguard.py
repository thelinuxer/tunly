#!/usr/bin/env python3
"""Privileged half of Tunly's transparent mode. Runs as root under pkexec.

Speaks newline-JSON on stdin; every reply is a JSON line on stdout. The one
guarantee that matters: when stdin reaches EOF — which happens the instant the
parent Tunly process dies, SIGKILL included — the ruleset is torn down before
this process exits. That needs no signal handler in the dying parent, which is
why it survives kills that ordinary cleanup cannot.
"""

import os
import sys
import json
import time
import shutil
import signal
import subprocess

# Runs standalone under pkexec (no PYTHONPATH), so make the package importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tunly.netfilter import (  # noqa: E402
    CONNTRACK_FLUSH, RuleError, up_commands, teardown_plan, check_plan,
)

MAX_JUMP_UNHOOK = 16  # a crash can stack duplicate jumps; bound the unhook loop


def log(msg):
    sys.stderr.write(f"netguard: {msg}\n")
    sys.stderr.flush()


def _run(cmd, quiet=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 and not quiet:
        log(f"FAILED rc={r.returncode}: {' '.join(cmd)}: {r.stderr.strip()}")
    return r


def _teardown_pass():
    """One sweep. Returns labels of anything still standing afterwards.
    Probes and misses are expected on a clean system, so they stay quiet."""
    leftovers = []
    for step in teardown_plan():
        for _ in range(MAX_JUMP_UNHOOK):
            if _run(step["probe"], quiet=True).returncode != 0:
                break
            if _run(step["delete"]).returncode != 0:
                break
        _run(step["flush"], quiet=True)
        _run(step["drop"], quiet=True)
        still_jumped = _run(step["probe"], quiet=True).returncode == 0
        still_there = _run(step["exists"], quiet=True).returncode == 0
        if still_jumped or still_there:
            leftovers.append(step["label"])
    return leftovers


def teardown(attempts=4):
    """Idempotent, and retried: a single sweep can lose to xtables lock
    contention, which is exactly how rules get stranded."""
    leftovers = []
    for attempt in range(attempts):
        leftovers = _teardown_pass()
        if not leftovers:
            return True
        log(f"teardown pass {attempt + 1} left {leftovers}; retrying")
        time.sleep(0.5)
    log(f"TEARDOWN INCOMPLETE, still present: {leftovers}")
    return False


def chains_intact():
    missing = [" ".join(p) for p in check_plan()
               if _run(p, quiet=True).returncode != 0]
    if missing:
        log(f"check: MISSING {missing}")
    return not missing


def bring_up(msg):
    cmds = up_commands(
        msg.get("ssh_ip"), msg.get("ssh_port"),
        msg.get("redir_port"), msg.get("dns_port"))
    teardown()  # clean slate; a previous crash may have left chains behind
    for cmd in cmds:
        r = _run(cmd)
        if r.returncode != 0:
            teardown()  # all-or-nothing: never leave a half-built ruleset
            return {"ok": False,
                    "error": f"{' '.join(cmd)}: {r.stderr.strip()}"}
    flush_conntrack()
    return {"ok": True}


def flush_conntrack():
    """Force pre-existing sockets through the tunnel. Optional: without the
    conntrack tool the rules still work, older connections just stay direct."""
    if shutil.which(CONNTRACK_FLUSH[0]) is None:
        log("conntrack tool absent — connections opened before now stay direct")
        return False
    r = _run(CONNTRACK_FLUSH, quiet=True)
    log(f"conntrack flush rc={r.returncode}")
    return r.returncode == 0


def handle(msg):
    op = msg.get("op")
    if op == "up":
        return bring_up(msg)
    if op == "down":
        return {"ok": teardown()}
    if op == "check":
        return {"ok": True, "intact": chains_intact()}
    return {"ok": False, "error": f"unknown op {op!r}"}


def reply(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    if os.geteuid() != 0:
        sys.stderr.write("netguard must run as root\n")
        return 1
    if "--teardown" in sys.argv:  # tunly --repair
        teardown()
        return 0

    def _bail(*_):
        teardown()
        os._exit(0)

    signal.signal(signal.SIGTERM, _bail)
    signal.signal(signal.SIGINT, _bail)
    log(f"started (pid {os.getpid()})")
    try:
        # readline(), not `for line in sys.stdin`: iteration read-aheads and
        # would sit on a full buffer instead of answering each command.
        while True:
            line = sys.stdin.readline()
            if not line:  # EOF == parent died
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                out = handle(msg)
                if msg.get("op") != "check":
                    log(f"{msg.get('op')} -> {out}")
            except (ValueError, RuleError) as e:
                log(f"bad request {line!r}: {e}")
                out = {"ok": False, "error": str(e)}
            reply(out)
        log("stdin closed (parent gone) — tearing down")
    finally:
        teardown()
        log("exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
