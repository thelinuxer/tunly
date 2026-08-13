"""Unprivileged half of transparent mode: accepts iptables-redirected
connections and re-dials them through the existing SOCKS5 port.

Runs its own asyncio loop on a background thread, because the GTK main loop is
GLib's and the two cannot share one.
"""

import socket
import struct
import asyncio
import threading

SO_ORIGINAL_DST = 80
BUF = 65536
DNS_TIMEOUT = 8
CONNECT_TIMEOUT = 15


def original_dst(sock):
    """Destination the client actually asked for, before REDIRECT rewrote it."""
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _family, port, addr = struct.unpack("!HH4s", raw[:8])
    return socket.inet_ntoa(addr), port


class SocksError(OSError):
    pass


async def socks_connect(socks_port, host, port):
    """SOCKS5 CONNECT to host:port through 127.0.0.1:socks_port (no auth)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise SocksError("SOCKS5 greeting rejected")
        writer.write(b"\x05\x01\x00\x01" + socket.inet_aton(host)
                     + port.to_bytes(2, "big"))
        await writer.drain()
        rep = await reader.readexactly(4)
        if rep[1] != 0:
            raise SocksError(f"SOCKS5 CONNECT to {host}:{port} failed "
                             f"(code {rep[1]})")
        atyp = rep[3]
        if atyp == 1:
            await reader.readexactly(6)
        elif atyp == 3:
            await reader.readexactly((await reader.readexactly(1))[0] + 2)
        elif atyp == 4:
            await reader.readexactly(18)
        else:
            raise SocksError(f"unexpected SOCKS5 address type {atyp}")
        return reader, writer
    except Exception:
        writer.close()
        raise


async def _pump(reader, writer):
    try:
        while True:
            data = await reader.read(BUF)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def _splice(a_r, a_w, b_r, b_w):
    await asyncio.gather(_pump(a_r, b_w), _pump(b_r, a_w),
                         return_exceptions=True)


async def dns_query_over_socks(socks_port, server, payload):
    """Ask `server` over DNS-over-TCP through the tunnel. Deliberately ignores
    the original destination: it is usually a private resolver address that
    means nothing from the exit node."""
    reader, writer = await socks_connect(socks_port, server, 53)
    try:
        writer.write(len(payload).to_bytes(2, "big") + payload)
        await writer.drain()
        size = int.from_bytes(await reader.readexactly(2), "big")
        return await reader.readexactly(size)
    finally:
        writer.close()


class _DnsUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, redirector):
        self.redirector = redirector
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self._answer(data, addr))

    async def _answer(self, data, addr):
        try:
            resp = await asyncio.wait_for(
                dns_query_over_socks(self.redirector.socks_port,
                                     self.redirector.dns_server, data),
                DNS_TIMEOUT)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            return  # resolver retries; a truncated fake reply would be worse
        self.transport.sendto(resp, addr)


def _bind_pair(host="127.0.0.1", attempts=8):
    """One port serving both TCP and UDP — iptables redirects both to it."""
    for _ in range(attempts):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((host, 0))
        port = tcp.getsockname()[1]
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.bind((host, port))
        except OSError:
            tcp.close()
            udp.close()
            continue
        tcp.setblocking(False)
        udp.setblocking(False)
        return tcp, udp, port
    raise OSError("could not bind a free TCP+UDP port pair for DNS")


class Redirector:
    """Owns the two listeners. start() blocks until both are serving."""

    def __init__(self, socks_port, dns_server):
        self.socks_port = socks_port
        self.dns_server = dns_server
        self.redir_port = None
        self.dns_port = None
        self.loop = None
        self._thread = None
        self._ready = threading.Event()
        self._error = None
        self._servers = []
        self._dns_transport = None

    # ---- lifecycle ----
    def start(self, timeout=10):
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="tunly-redirector")
        self._thread.start()
        if not self._ready.wait(timeout):
            raise OSError("redirector did not come up in time")
        if self._error:
            raise self._error
        return self.redir_port, self.dns_port

    def stop(self):
        if self.loop is None:
            return
        self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.loop = None

    def alive(self):
        return self._thread is not None and self._thread.is_alive()

    # ---- internals ----
    def _run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._setup())
        except Exception as e:  # surfaced to start()
            self._error = e
            self._ready.set()
            return
        self._ready.set()
        try:
            self.loop.run_forever()
        finally:
            self._shutdown()

    async def _setup(self):
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_sock.bind(("127.0.0.1", 0))
        tcp_sock.setblocking(False)
        self.redir_port = tcp_sock.getsockname()[1]
        self._servers.append(
            await asyncio.start_server(self._handle_tcp, sock=tcp_sock))

        dns_tcp, dns_udp, self.dns_port = _bind_pair()
        self._servers.append(
            await asyncio.start_server(self._handle_dns_tcp, sock=dns_tcp))
        self._dns_transport, _ = await self.loop.create_datagram_endpoint(
            lambda: _DnsUdpProtocol(self), sock=dns_udp)

    def _shutdown(self):
        for server in self._servers:
            server.close()
        if self._dns_transport is not None:
            self._dns_transport.close()
        self._servers = []
        self.loop.close()

    async def _handle_tcp(self, reader, writer):
        sock = writer.get_extra_info("socket")
        try:
            host, port = original_dst(sock)
        except OSError:
            writer.close()
            return
        try:
            up_r, up_w = await asyncio.wait_for(
                socks_connect(self.socks_port, host, port), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            writer.close()
            return
        await _splice(reader, writer, up_r, up_w)

    async def _handle_dns_tcp(self, reader, writer):
        try:
            size = int.from_bytes(await reader.readexactly(2), "big")
            query = await reader.readexactly(size)
            resp = await asyncio.wait_for(
                dns_query_over_socks(self.socks_port, self.dns_server, query),
                DNS_TIMEOUT)
            writer.write(len(resp).to_bytes(2, "big") + resp)
            await writer.drain()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
