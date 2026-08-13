"""Routing backends — how a live SOCKS tunnel is actually delivered to apps.

`ProxyBackend` asks apps politely via the GNOME proxy setting; only apps that
read it comply. `TransparentBackend` gives them no say, using iptables.

Both sit on the same unchanged `ssh -D` process, which is what makes swapping
between them possible without reconnecting.
"""

import os
import sys
import json
import queue
import socket
import threading
import subprocess

from gi.repository import GLib, Gio

from . import netguard as netguard_mod
from .redirector import Redirector

HELPER = os.path.abspath(netguard_mod.__file__)
HELPER_LOG = os.path.join(GLib.get_user_cache_dir(), "tunly-netguard.log")


def resolve_v4(host):
    """Pin the SSH host to one IPv4 address. Rules embed it, so re-resolution
    later must not silently break the carrier exemption."""
    return socket.getaddrinfo(host, None, socket.AF_INET,
                              socket.SOCK_STREAM)[0][4][0]


class RoutingBackend:
    name = "base"

    def up(self, socks_port):
        raise NotImplementedError

    def down(self):
        raise NotImplementedError

    def health(self):
        return True


class ProxyBackend(RoutingBackend):
    """GNOME system proxy — today's behaviour, no root."""

    name = "proxy"

    def __init__(self):
        self.proxy = Gio.Settings.new("org.gnome.system.proxy")
        self.proxy_socks = Gio.Settings.new("org.gnome.system.proxy.socks")
        self.proxy_http = Gio.Settings.new("org.gnome.system.proxy.http")
        self.saved_mode = None

    def up(self, socks_port):
        self.saved_mode = self.proxy.get_string("mode")
        self.proxy_socks.set_string("host", "127.0.0.1")
        self.proxy_socks.set_int("port", socks_port)
        self.proxy_http.set_string("host", "")
        self.proxy_http.set_int("port", 0)
        self.proxy.set_string("mode", "manual")

    def down(self):
        self.proxy.set_string("mode", self.saved_mode or "none")
        self.proxy_socks.set_string("host", "")
        self.proxy_socks.set_int("port", 0)

    def health(self):
        return self.proxy.get_string("mode") == "manual"


class TransparentBackend(RoutingBackend):
    """iptables redirect into an in-process SOCKS re-dialer."""

    name = "transparent"

    def __init__(self, ssh_host, ssh_port, dns_server):
        self.ssh_host = ssh_host
        self.ssh_port = int(ssh_port)
        self.dns_server = dns_server
        self.helper = None
        self.redirector = None
        self._replies = queue.Queue()
        self._reader = None
        self._log = None

    def up(self, socks_port):
        ssh_ip = resolve_v4(self.ssh_host)
        self.redirector = Redirector(socks_port, self.dns_server)
        redir_port, dns_port = self.redirector.start()
        try:
            self._spawn_helper()
            reply = self._request({
                "op": "up", "ssh_ip": ssh_ip, "ssh_port": self.ssh_port,
                "redir_port": redir_port, "dns_port": dns_port,
            })
        except Exception:
            self.down()
            raise
        if not reply.get("ok"):
            self.down()
            raise OSError(reply.get("error", "netguard refused to apply rules"))

    def down(self):
        # Closing stdin is the teardown signal; the helper also does this on its
        # own if we die without getting here.
        if self.helper is not None and self.helper.poll() is None:
            try:
                # generous: teardown retries, and each call may wait on the
                # xtables lock
                self._request({"op": "down"}, timeout=45)
            except (OSError, ValueError):
                pass  # ValueError: helper emitted garbage; stdin close still kills it
            try:
                self.helper.stdin.close()
            except OSError:
                pass
            try:
                self.helper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.helper.kill()
        self.helper = None
        if self._log is not None:
            self._log.close()
            self._log = None
        if self.redirector is not None:
            self.redirector.stop()
            self.redirector = None

    def health(self):
        if self.helper is None or self.helper.poll() is not None:
            return False
        if self.redirector is None or not self.redirector.alive():
            return False
        try:
            return bool(self._request({"op": "check"}, timeout=5).get("intact"))
        except (OSError, ValueError):
            # json.loads raises ValueError, not OSError — letting it escape
            # would kill the GLib poll source and silently end all monitoring.
            return False

    # ---- helper plumbing ----
    def _spawn_helper(self):
        # Keep the helper's stderr: discarding it leaves a root process that
        # touches the firewall completely undiagnosable when it misbehaves.
        self._log = open(HELPER_LOG, "a", buffering=1)
        self.helper = subprocess.Popen(
            ["pkexec", sys.executable, HELPER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self._log, text=True, bufsize=1)
        # One long-lived reader: a per-request thread left behind by a timeout
        # would steal the next reply.
        self._replies = queue.Queue()
        self._reader = threading.Thread(target=self._pump_replies, daemon=True,
                                        name="tunly-netguard-reader")
        self._reader.start()

    def _pump_replies(self):
        for line in iter(self.helper.stdout.readline, ""):
            self._replies.put(line)
        self._replies.put(None)  # helper closed its output

    def _request(self, msg, timeout=60):
        """Write one JSON line, read one back. Replies arrive on a thread so a
        wedged helper cannot freeze the GTK main loop."""
        if self.helper is None or self.helper.poll() is not None:
            raise OSError("netguard is not running")
        try:
            self.helper.stdin.write(json.dumps(msg) + "\n")
            self.helper.stdin.flush()
        except OSError as e:
            raise OSError(f"netguard went away: {e}") from e
        try:
            line = self._replies.get(timeout=timeout)
        except queue.Empty:
            raise OSError("netguard did not reply in time") from None
        if line is None:
            raise OSError("netguard closed its output")
        return json.loads(line)


def repair():
    """Standalone teardown for `tunly --repair`, no GUI and no tunnel."""
    return subprocess.call(["pkexec", sys.executable, HELPER, "--teardown"])
