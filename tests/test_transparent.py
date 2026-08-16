import os
import socket
import struct
import asyncio
import subprocess

import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tunly import netfilter  # noqa: E402
from tunly.netfilter import RuleError, up_commands, teardown_plan  # noqa: E402
from tunly import redirector  # noqa: E402
from tunly import nmcheck  # noqa: E402
from tunly import netguard  # noqa: E402


def index_of(cmds, *needles):
    """First rule containing every needle, as an index into the command list."""
    for i, cmd in enumerate(cmds):
        joined = " ".join(cmd)
        if all(n in joined for n in needles):
            return i
    raise AssertionError(f"no rule matching {needles}")


@pytest.fixture
def cmds():
    return up_commands("203.0.113.7", 22, 40001, 40002)


class TestRuleOrder:
    def test_loopback_returns_first_in_nat_chain(self, cmds):
        first = index_of(cmds, "-A", netfilter.NAT_CHAIN)
        assert "-o lo -j RETURN" in " ".join(cmds[first])

    def test_dns_redirect_precedes_private_returns(self, cmds):
        """The leak is resolved forwarding upstream to a private resolver, so
        the DNS rules are worthless below the private RETURNs."""
        udp53 = index_of(cmds, "nat", "udp", "--dport", "53")
        tcp53 = index_of(cmds, "nat", "tcp", "--dport", "53")
        private = index_of(cmds, "nat", "-A", netfilter.NAT_CHAIN,
                           "192.168.0.0/16")
        assert udp53 < private
        assert tcp53 < private

    def test_dns_goes_to_dns_port_not_redir_port(self, cmds):
        rule = cmds[index_of(cmds, "nat", "udp", "--dport", "53")]
        assert "40002" in rule and "40001" not in rule

    def test_ssh_carrier_exempt_before_catch_all(self, cmds):
        exempt = index_of(cmds, "nat", "203.0.113.7", "--dport", "22", "RETURN")
        catch_all = index_of(cmds, "nat", "-p", "tcp", "-j", "REDIRECT",
                             "--to-ports", "40001")
        assert exempt < catch_all

    def test_every_private_net_returned_in_nat(self, cmds):
        joined = "\n".join(" ".join(c) for c in cmds if "nat" in c)
        for net in netfilter.PRIVATE_V4:
            assert f"-d {net} -j RETURN" in joined

    def test_nat_jump_is_unqualified(self, cmds):
        """A `-p tcp` jump would hide UDP/53 from the chain."""
        jump = cmds[index_of(cmds, "nat", "-A", "OUTPUT", "-j",
                             netfilter.NAT_CHAIN)]
        assert jump == ["iptables", "-w", "5", "-t", "nat", "-A", "OUTPUT",
                        "-j", netfilter.NAT_CHAIN]


class TestLockWait:
    """Docker rewrites iptables constantly. Without -w a call aborts on lock
    contention, and a teardown that aborts that way strands rules."""

    def test_every_apply_command_waits_for_the_lock(self, cmds):
        for c in cmds:
            assert c[1:3] == ["-w", "5"], f"missing -w: {c}"

    def test_every_teardown_command_waits_for_the_lock(self):
        for step in teardown_plan():
            for key in ("probe", "delete", "flush", "drop", "exists"):
                assert step[key][1:3] == ["-w", "5"], f"missing -w: {step[key]}"


class TestGuardFirst:
    """Installing the redirect first leaves a window where traffic is neither
    blocked nor captured — measured leaking the real IP for 5-10s."""

    def test_guard_is_jumped_before_the_redirect(self, cmds):
        guard_jump = index_of(cmds, "-A", "OUTPUT", "-j", netfilter.GUARD_CHAIN)
        nat_jump = index_of(cmds, "nat", "-A", "OUTPUT", "-j",
                            netfilter.NAT_CHAIN)
        assert guard_jump < nat_jump

    def test_no_nat_rule_precedes_the_guard_jump(self, cmds):
        guard_jump = index_of(cmds, "-A", "OUTPUT", "-j", netfilter.GUARD_CHAIN)
        assert not [c for c in cmds[:guard_jump] if "nat" in c]


class TestKillSwitch:
    def test_udp_rejected_not_dropped(self, cmds):
        rule = cmds[index_of(cmds, netfilter.GUARD_CHAIN, "-p", "udp")]
        assert "REJECT" in rule and "icmp-port-unreachable" in rule

    def test_icmp_blocked_everywhere_including_lan(self, cmds):
        """ICMP cannot ride a SOCKS TCP tunnel, so any that escapes carries the
        real source address — the reject must outrank the private RETURNs."""
        icmp = index_of(cmds, netfilter.GUARD_CHAIN, "-p", "icmp", "REJECT")
        private = index_of(cmds, netfilter.GUARD_CHAIN, "192.168.0.0/16")
        assert icmp < private

    def test_guard_has_final_catch_all_reject(self, cmds):
        guard = [c for c in cmds
                 if "-A" in c and c[c.index("-A") + 1] == netfilter.GUARD_CHAIN]
        assert guard[-1][-3:] == ["REJECT", "--reject-with",
                                  "icmp-admin-prohibited"]

    def test_ipv6_is_rejected(self, cmds):
        """v4-only rules would leave v6 a wide-open side channel."""
        guard6 = [c for c in cmds if c[0] == netfilter.IP6TABLES]
        assert guard6, "no ip6tables rules generated"
        assert "REJECT" in guard6[-2]
        assert guard6[-1] == ["ip6tables", "-w", "5", "-A", "OUTPUT", "-j",
                              netfilter.GUARD6_CHAIN]


class TestValidation:
    @pytest.mark.parametrize("bad", ["", "not-an-ip", "203.0.113.999",
                                     "2001:db8::1"])
    def test_rejects_bad_ssh_ip(self, bad):
        with pytest.raises(RuleError):
            up_commands(bad, 22, 40001, 40002)

    @pytest.mark.parametrize("bad", [0, -1, 65536, "22", None, True])
    def test_rejects_bad_port(self, bad):
        with pytest.raises(RuleError):
            up_commands("203.0.113.7", bad, 40001, 40002)

    def test_rejects_colliding_listener_ports(self):
        with pytest.raises(RuleError):
            up_commands("203.0.113.7", 22, 40001, 40001)


class TestTeardownPlan:
    def test_covers_every_chain_created(self, cmds):
        created = {c[c.index("-N") + 1] for c in cmds if "-N" in c}
        planned = {s["flush"][s["flush"].index("-F") + 1]
                   for s in teardown_plan()}
        assert created == planned

    def test_each_step_probes_before_deleting(self):
        for step in teardown_plan():
            assert "-C" in step["probe"]
            assert "-D" in step["delete"]
            assert step["probe"][step["probe"].index("-C") + 1:] == \
                step["delete"][step["delete"].index("-D") + 1:]


class TestOriginalDst:
    def test_parses_sockaddr_in(self):
        raw = struct.pack("!HH4s8s", socket.AF_INET, 443,
                          socket.inet_aton("93.184.216.34"), b"\x00" * 8)

        class FakeSock:
            def getsockopt(self, level, optname, buflen):
                assert (level, optname) == (socket.SOL_IP,
                                            redirector.SO_ORIGINAL_DST)
                return raw[:buflen]

        assert redirector.original_dst(FakeSock()) == ("93.184.216.34", 443)


# ---- SOCKS5 client against a real stub server (no root needed) ----

class StubSocks:
    """Minimal SOCKS5 server. Records the CONNECT target, then echoes or
    replies with a canned payload."""

    def __init__(self, canned=None, fail_code=0):
        self.canned = canned
        self.fail_code = fail_code
        self.target = None
        self.received = b""
        self.server = None
        self.port = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        nmethods = (await reader.readexactly(2))[1]
        await reader.readexactly(nmethods)
        writer.write(b"\x05\x00")
        await writer.drain()
        header = await reader.readexactly(4)
        host = socket.inet_ntoa(await reader.readexactly(4))
        port = int.from_bytes(await reader.readexactly(2), "big")
        self.target = (host, port)
        assert header[1] == 1  # CONNECT
        writer.write(bytes([5, self.fail_code, 0, 1]) + b"\x00" * 4
                     + b"\x00\x00")
        await writer.drain()
        if self.fail_code:
            writer.close()
            return
        if self.canned is not None:
            size = int.from_bytes(await reader.readexactly(2), "big")
            self.received = await reader.readexactly(size)
            writer.write(len(self.canned).to_bytes(2, "big") + self.canned)
            await writer.drain()
        else:
            while True:  # echo
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        writer.close()


class TestSocksClient:
    def test_connect_sends_requested_target(self):
        async def run():
            stub = StubSocks()
            port = await stub.start()
            r, w = await redirector.socks_connect(port, "93.184.216.34", 443)
            w.write(b"hello")
            await w.drain()
            echoed = await r.readexactly(5)
            w.close()
            await stub.stop()
            return stub.target, echoed

        target, echoed = asyncio.run(run())
        assert target == ("93.184.216.34", 443)
        assert echoed == b"hello"

    def test_refused_connect_raises(self):
        async def run():
            stub = StubSocks(fail_code=5)  # connection refused
            port = await stub.start()
            try:
                with pytest.raises(redirector.SocksError):
                    await redirector.socks_connect(port, "93.184.216.34", 443)
            finally:
                await stub.stop()

        asyncio.run(run())


class TestDnsForwarding:
    def test_query_is_length_prefixed_and_sent_to_configured_resolver(self):
        """The original destination is a private router address, so the
        forwarder must substitute the configured resolver."""
        answer = b"\xab\xcd" + b"\x81\x80" + b"\x00" * 8

        async def run():
            stub = StubSocks(canned=answer)
            port = await stub.start()
            got = await redirector.dns_query_over_socks(
                port, "1.1.1.1", b"\xab\xcd query-bytes")
            await stub.stop()
            return got, stub.target, stub.received

        got, target, received = asyncio.run(run())
        assert got == answer
        assert target == ("1.1.1.1", 53)
        assert received == b"\xab\xcd query-bytes"


class TestRedirectorLifecycle:
    def test_start_binds_distinct_ports_and_stops_clean(self):
        r = redirector.Redirector(1080, "1.1.1.1")
        redir_port, dns_port = r.start()
        try:
            assert redir_port != dns_port
            assert r.alive()
            # iptables sends both TCP/53 and UDP/53 to dns_port
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                s = socket.socket(socket.AF_INET, kind)
                with pytest.raises(OSError):
                    s.bind(("127.0.0.1", dns_port))
                s.close()
        finally:
            r.stop()
        assert not r.alive()


class FakeStdin:
    def write(self, _):
        pass

    def flush(self):
        pass

    def close(self):
        pass


class FakeHelper:
    """A live-looking netguard whose replies the test controls."""

    def __init__(self):
        self.stdin = FakeStdin()

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class FakeRedirector:
    def alive(self):
        return True

    def stop(self):
        pass


class TestBackendResilience:
    """A crashing health check must not escape: an exception here would kill
    the GLib poll source and silently end all monitoring."""

    def _backend(self, reply):
        from tunly.routing import TransparentBackend
        b = TransparentBackend("example.com", 22, "1.1.1.1")
        b.helper = FakeHelper()
        b.redirector = FakeRedirector()
        b._replies.put(reply)
        return b

    def test_health_false_on_malformed_reply(self):
        assert self._backend("this is not json\n").health() is False

    def test_health_false_when_helper_closed_output(self):
        assert self._backend(None).health() is False

    def test_health_true_only_when_chains_intact(self):
        assert self._backend('{"ok": true, "intact": true}\n').health() is True
        assert self._backend('{"ok": true, "intact": false}\n').health() is False

    def test_down_survives_malformed_reply(self):
        self._backend("garbage\n").down()  # must not raise


class TestConnectivityCheckCommands:
    def test_get_reads_the_networkmanager_property(self):
        joined = " ".join(nmcheck.get_cmd())
        assert "org.freedesktop.DBus.Properties.Get" in joined
        assert nmcheck.IFACE in joined
        assert nmcheck.PROP in joined

    def test_set_wraps_the_value_as_a_variant(self):
        assert "<false>" in nmcheck.set_cmd(False)
        assert "<true>" in nmcheck.set_cmd(True)

    def test_every_call_carries_a_timeout(self):
        """A wedged NetworkManager must never hold up teardown."""
        for cmd in (nmcheck.get_cmd(), nmcheck.set_cmd(True)):
            assert "--timeout" in cmd

    def test_parses_both_states(self):
        assert nmcheck.parse("(<true>,)\n") is True
        assert nmcheck.parse("(<false>,)\n") is False

    def test_rejects_unparsable_reply(self):
        with pytest.raises(ValueError):
            nmcheck.parse("some gdbus error")


class TestConnectivityCheckRestore:
    """The property is runtime-only, so the worst a bug here costs is a
    misleading tray icon until NetworkManager restarts. It still has to be
    right: silently leaving a user's check off is a change they never asked
    for."""

    class Bus(list):
        """Records every argv netguard runs, and answers the Get however the
        test wants."""
        reply = "(<true>,)\n"
        rc = 0

        def run(self, cmd, quiet=False):
            self.append(cmd)
            is_get = "Get" in " ".join(cmd)
            return subprocess.CompletedProcess(
                cmd, self.rc if is_get else 0,
                self.reply if is_get else "", "")

    @pytest.fixture
    def calls(self, monkeypatch):
        bus = self.Bus()
        monkeypatch.setattr(netguard, "_run", bus.run)
        monkeypatch.setattr(netguard.shutil, "which", lambda _: "/usr/bin/gdbus")
        monkeypatch.setattr(netguard, "_nm_prev", None)
        return bus

    def sets(self, calls):
        return [c for c in calls if "Set" in " ".join(c)]

    def test_disable_turns_the_check_off(self, calls):
        netguard.nm_check_disable()
        assert "<false>" in self.sets(calls)[-1]

    def test_restore_puts_the_previous_value_back(self, calls):
        netguard.nm_check_disable()
        netguard.nm_check_restore()
        assert "<true>" in self.sets(calls)[-1]

    def test_restore_respects_a_check_the_user_had_already_disabled(self, calls):
        calls.reply = "(<false>,)\n"
        netguard.nm_check_disable()
        netguard.nm_check_restore()
        assert "<false>" in self.sets(calls)[-1]

    def test_restore_without_a_stash_touches_nothing(self, calls):
        netguard.nm_check_restore()
        assert self.sets(calls) == []

    def test_repair_re_enables_without_a_stash(self, calls):
        netguard.nm_check_restore(force=True)
        assert "<true>" in self.sets(calls)[-1]

    def test_restore_runs_once(self, calls):
        netguard.nm_check_disable()
        netguard.nm_check_restore()
        netguard.nm_check_restore()
        assert len(self.sets(calls)) == 2  # the disable, then one restore

    def test_unreadable_property_is_left_alone(self, calls):
        calls.rc = 1
        netguard.nm_check_disable()
        assert self.sets(calls) == []

    def test_absent_gdbus_is_not_fatal(self, calls, monkeypatch):
        monkeypatch.setattr(netguard.shutil, "which", lambda _: None)
        netguard.nm_check_disable()
        netguard.nm_check_restore()
        assert self.sets(calls) == []

    def test_teardown_restores(self, calls, monkeypatch):
        monkeypatch.setattr(netguard, "_teardown_rules", lambda attempts: True)
        netguard.nm_check_disable()
        netguard.teardown()
        assert "<true>" in self.sets(calls)[-1]

    def test_teardown_restores_even_when_rules_are_stranded(self, calls,
                                                            monkeypatch):
        monkeypatch.setattr(netguard, "_teardown_rules", lambda attempts: False)
        netguard.nm_check_disable()
        assert netguard.teardown() is False
        assert "<true>" in self.sets(calls)[-1]


# ---- real iptables, inside a throwaway network namespace ----

NEEDS_ROOT = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="needs root for a network namespace; run: "
           "sudo .venv/bin/python -m pytest tests/test_transparent.py")


def in_netns(script):
    return subprocess.run(["unshare", "-n", "sh", "-c", script],
                          capture_output=True, text=True)


@NEEDS_ROOT
class TestAgainstRealIptables:
    def _apply_script(self):
        lines = ["ip link set lo up"]
        lines += [" ".join(c) for c in up_commands("203.0.113.7", 22,
                                                   40001, 40002)]
        lines.append("iptables -t nat -S TUNLY")
        lines.append("iptables -S TUNLY_GUARD")
        return "set -e\n" + "\n".join(lines)

    def test_kernel_accepts_every_generated_rule(self):
        r = in_netns(self._apply_script())
        assert r.returncode == 0, r.stderr
        assert "-A TUNLY -o lo -j RETURN" in r.stdout
        assert "--to-ports 40001" in r.stdout

    def test_teardown_removes_everything(self):
        plan = "\n".join(
            f"while {' '.join(s['probe'])} 2>/dev/null; "
            f"do {' '.join(s['delete'])}; done; "
            f"{' '.join(s['flush'])} 2>/dev/null || true; "
            f"{' '.join(s['drop'])} 2>/dev/null || true"
            for s in teardown_plan())
        script = (self._apply_script() + "\n" + plan
                  + "\niptables -S; iptables -t nat -S; ip6tables -S")
        r = in_netns(script)
        assert r.returncode == 0, r.stderr
        tail = r.stdout[r.stdout.index("-P INPUT"):]
        assert "TUNLY" not in tail, f"leftovers:\n{tail}"

    def test_teardown_is_idempotent_on_clean_system(self):
        plan = "\n".join(
            f"{' '.join(s['flush'])} 2>/dev/null || true; "
            f"{' '.join(s['drop'])} 2>/dev/null || true"
            for s in teardown_plan())
        r = in_netns("ip link set lo up\n" + plan + "\necho SURVIVED")
        assert "SURVIVED" in r.stdout

    def test_sigkilled_parent_still_gets_rules_torn_down(self, tmp_path):
        """The headline safety claim: Tunly dying by SIGKILL closes netguard's
        stdin, and netguard removes the ruleset with no help from the corpse."""
        helper = os.path.join(os.path.dirname(__file__), "..", "src",
                              "tunly", "netguard.py")
        ready = tmp_path / "ready"
        parent = tmp_path / "parent.py"
        parent.write_text(f"""
import json, subprocess, sys, time
p = subprocess.Popen([sys.executable, {os.path.abspath(helper)!r}],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                     bufsize=1)
p.stdin.write(json.dumps({{"op": "up", "ssh_ip": "203.0.113.7",
                          "ssh_port": 22, "redir_port": 40001,
                          "dns_port": 40002}}) + "\\n")
p.stdin.flush()
reply = p.stdout.readline()
open({str(ready)!r}, "w").write(reply)
while True:
    time.sleep(1)
""")
        driver = tmp_path / "driver.py"
        driver.write_text(f"""
import json, os, signal, subprocess, sys, time
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
parent = subprocess.Popen([sys.executable, {str(parent)!r}])
for _ in range(100):
    if os.path.exists({str(ready)!r}):
        break
    time.sleep(0.1)
else:
    print("TIMEOUT_WAITING_FOR_UP"); sys.exit(1)
print("UP_REPLY", open({str(ready)!r}).read().strip())
present = subprocess.run(["iptables", "-t", "nat", "-S", "TUNLY"],
                         capture_output=True, text=True)
print("BEFORE_RC", present.returncode)
os.kill(parent.pid, signal.SIGKILL)
for _ in range(100):
    gone = subprocess.run(["iptables", "-t", "nat", "-S", "TUNLY"],
                          capture_output=True, text=True).returncode != 0
    jump = subprocess.run(["iptables", "-t", "nat", "-C", "OUTPUT", "-j",
                           "TUNLY"], capture_output=True).returncode != 0
    if gone and jump:
        print("TORN_DOWN"); sys.exit(0)
    time.sleep(0.1)
print("STILL_PRESENT"); sys.exit(1)
""")
        r = subprocess.run(["unshare", "-n", sys.executable, str(driver)],
                           capture_output=True, text=True, timeout=90)
        assert "UP_REPLY" in r.stdout, r.stdout + r.stderr
        assert '"ok": true' in r.stdout.lower(), r.stdout
        assert "BEFORE_RC 0" in r.stdout, f"rules never applied:\n{r.stdout}"
        assert "TORN_DOWN" in r.stdout, f"leaked after SIGKILL:\n{r.stdout}"

    def test_duplicate_jumps_are_all_unhooked(self):
        """A previous crash can stack jumps; one -D removes only one."""
        script = (self._apply_script()
                  + "\niptables -t nat -A OUTPUT -j TUNLY"
                  + "\nwhile iptables -t nat -C OUTPUT -j TUNLY 2>/dev/null; "
                    "do iptables -t nat -D OUTPUT -j TUNLY; done"
                  + "\niptables -t nat -S OUTPUT")
        r = in_netns(script)
        assert r.returncode == 0, r.stderr
        assert "-j TUNLY" not in r.stdout.split("-S OUTPUT")[-1]
