# Tunly — Transparent Routing (iptables)

## Purpose

Today Tunly only writes `org.gnome.system.proxy`. Apps that read that setting
(Firefox, Chrome, GTK) are tunnelled; everything else (yt-dlp, curl, git, apt,
Steam) ignores it and leaves over the real IP. Transparent mode forces **all**
outbound TCP through the existing SOCKS tunnel using iptables, with no per-app
configuration.

## Scope

- **Captured:** local TCP + DNS. This is what `ssh -D` can carry — OpenSSH
  dynamic forwarding is TCP-only, there is no UDP ASSOCIATE.
- **Not captured:** general UDP (rejected, see kill switch), forwarded traffic
  from containers/LAN, per-app selection.
- **iptables only.** No `nft` commands, though on modern systems iptables is
  nft-backed. Consequence: no atomic table delete, so reversal uses dedicated
  custom chains.

## Model

Global toggle, not per-tunnel. Config gains two top-level keys:

```json
{ "poll_seconds": 3, "transparent": false, "dns_server": "1.1.1.1", "tunnels": [...] }
```

`transparent: false` preserves existing behaviour for every install.

Flipping the toggle while a tunnel is up **hot-swaps** the delivery mechanism.
`ssh -D` keeps running untouched and the SOCKS port is unchanged — only the
backend changes, so there is no reconnect and no re-auth.

## Architecture

The seam already exists as `Manager.apply_proxy()` / `revert_proxy()`. It is
formalised as a backend interface:

```python
class RoutingBackend:
    def up(self, socks_port: int) -> None
    def down(self) -> None      # MUST be idempotent
    def health(self) -> bool
```

| Module | Runs as | Responsibility |
|---|---|---|
| `routing.py` | user | `ProxyBackend` (gsettings, today's code) + `TransparentBackend` |
| `netfilter.py` | — | pure functions producing iptables argv lists; no side effects |
| `redirector.py` | user | asyncio SOCKS5 re-dialer + DNS-over-TCP forwarder |
| `netguard.py` | **root** | applies/removes rules; separate process via `pkexec` |

`netfilter.py` holding no side effects is what makes the ruleset unit-testable
without root.

## Ruleset

Three chains. Tunly never writes into a built-in chain except the jumps.

**`nat/TUNLY`** (jumped from `nat/OUTPUT`, unqualified so UDP/53 is seen):

1. `-o lo -j RETURN` — loopback untouched, so systemd-resolved's stub on
   `127.0.0.53` keeps serving and caching normally.
2. `-p udp --dport 53 -j REDIRECT --to-ports <dns_port>`
3. `-p tcp --dport 53 -j REDIRECT --to-ports <dns_port>`
4. `-d <ssh_ip> -p tcp --dport <ssh_port> -j RETURN` — the carrier.
5. private/reserved nets `-j RETURN` — docker0, `br-*`, lxcbr0, virbr0, LAN.
6. `-p tcp -j REDIRECT --to-ports <redir_port>`

Rules 2–3 sit *above* rule 5 deliberately: they must catch resolved forwarding
upstream to a private resolver, which is the actual leak.

**No packet marks or cgroup matching are needed.** The two processes that must
escape the redirect already do so geometrically: `ssh` by rule 4, and the
redirector by rule 1 (it dials `127.0.0.1:<socks_port>`).

The SSH host is resolved to an IP once at `up()` and pinned into rule 4, so a
hostname that later re-resolves cannot silently break the exemption.

**`filter/TUNLY_GUARD`** — the fail-closed half. Redirected packets already have
a loopback destination by this point, so the guard only sees what the redirect
did not catch:

1. `-o lo -j RETURN`
2. `-p icmp -j REJECT --reject-with icmp-admin-prohibited`
3. `-d <ssh_ip> -p tcp --dport <ssh_port> -j RETURN`
4. private/reserved nets `-j RETURN`
5. `-p udp -j REJECT --reject-with icmp-port-unreachable`
6. `-j REJECT --reject-with icmp-admin-prohibited`

Rule 2 outranks the private RETURNs deliberately: ICMP is blocked everywhere,
LAN included. It cannot ride a SOCKS TCP tunnel, so anything escaping would
carry the real source address. The cost is that `ping` — everyone's reflex
connectivity check — always fails while transparent mode is on, so the
"tunnel UP" notification says so explicitly.

`REJECT` not `DROP`: QUIC sees an instant port-unreachable and falls back to TCP
in milliseconds, where `DROP` stalls every page load for a full timeout.

**`filter/TUNLY_GUARD6`** — IPv6 is a wide-open side channel otherwise, since
`iptables` is v4-only and Chrome prefers v6. Reject rather than redirect;
Happy Eyeballs falls back to v4, which is tunnelled.

## Ordering: guard before redirect

Both guard chains are installed **before** the nat redirect. Building the
redirect first leaves a window in which traffic is neither blocked nor
captured, and it leaves over the real IP. Measured on a real machine
2026-08-12: the exit IP stayed the ISP's for roughly 5–10 seconds after the
toggle before flipping to the tunnel. Guard-first converts that window from a
silent leak into a brief, visible block.

Teardown runs the other way — nat first, then the guards — so traffic is never
redirected at a redirector that is already gone.

## Conntrack

Sockets opened before the rules went in keep flowing direct through their
existing conntrack entries, so an already-running browser stays unprotected
while new connections are tunnelled. `up` therefore flushes TCP conntrack.

The ssh carrier survives this: it is nat-exempt, and `nf_conntrack_tcp_loose`
(default `1`) lets its stream be picked up mid-flight when the entry is
recreated. The flush needs the `conntrack` tool; without it the rules still
work and only pre-existing connections stay direct, which is logged.

## DNS

Apps → `127.0.0.53` (untouched, rule 1) → resolved forwards upstream over
UDP/53 → **rules 2–3 catch it**.

The forwarder re-asks a **configured** resolver (`dns_server`) over DNS-over-TCP
through the SOCKS port. It deliberately ignores `SO_ORIGINAL_DST` for port 53,
because the original destination is typically a private router address that is
unreachable from the exit node.

`dns_server` defaults to `1.1.1.1` and is editable in the UI.

Known limitation: split-horizon DNS from a corporate resolver stops resolving
while transparent mode is on. Documented, not worked around.

## Reversal

Teardown is idempotent and order-fixed — jumps out of built-ins first, then
flush, then delete, each step tolerating "already gone":

```
while iptables -t nat -C OUTPUT -j TUNLY; do iptables -t nat -D OUTPUT -j TUNLY; done
iptables -t nat -F TUNLY ; iptables -t nat -X TUNLY
```

The `while` matters: a previous crash can leave two jumps stacked, and one `-D`
removes only one.

**Every invocation carries `-w 5`.** Without it iptables aborts the instant
another process holds the xtables lock, and Docker rewrites its rules
constantly. An unguarded call fails at random — and when the failing call is
part of *teardown*, chains are stranded. This was observed in testing on
2026-08-11: `nat/TUNLY` came off while `filter/TUNLY_GUARD` survived, leaving
ICMP and UDP rejected with no helper left to clean up.

Teardown is also **retried up to four times**, checking both the jump and the
chain itself, and logs `TEARDOWN INCOMPLETE` with the surviving labels if it
still cannot finish. A single sweep losing a lock race is the exact mechanism
that stranded rules.

Three independent guarantees that the network comes back:

1. **`netguard` holds Tunly's stdin pipe.** Tunly dying — SIGKILL, OOM, anything
   — closes the pipe; the helper reads EOF and tears down itself. Survives
   SIGKILL precisely because it needs no signal handler in the dying process.
2. **`tunly --repair`** runs teardown standalone, no GUI, no tunnel.
3. **Reboot**, since nothing persists the rules.

**Hard constraint: Tunly must never invoke `netfilter-persistent save`.** Doing
so would turn crash-leftover chains into permanent ones.

## Privilege

`netguard` is launched once per session via `pkexec` and speaks newline-JSON on
stdin (`{"op":"up",...}` / `{"op":"down"}` / `{"op":"check"}`).

It runs as root against input from a non-root process, so every parameter is
validated before use — addresses through `ipaddress`, ports as ints in range.
Commands are built as argv lists and never passed through a shell.

Its stderr is captured to `~/.cache/tunly-netguard.log`. Discarding it left a
root process that edits the firewall completely undiagnosable when it
misbehaved, which cost real debugging time.

## Error handling

- `up()` is all-or-nothing: any failing rule triggers immediate teardown, falls
  back to `ProxyBackend`, and notifies.
- `health()` folds into the existing `_poll()` loop, which already checks tunnel
  liveness. It verifies the helper is alive and the chains still exist; if they
  vanished, tear down and revert rather than pretend.
- Enabling transparent mode with an empty `dns_server` is refused in the UI.

## Testing

- Rule generation and teardown idempotency are pure-function unit tests, no root.
- Real `iptables` integration runs inside `unshare -rn` network namespaces, so
  tests never touch the host ruleset.
- SOCKS5 handshake and DNS-over-TCP framing tested against a local stub server.

## Packaging

`Depends: iptables` added to the deb control file. New modules added to the
Makefile install list. No new Python runtime dependency.

## Non-goals

UDP transport, IPv6 redirect, forwarded/container traffic, per-app selection,
persisting rules across reboot.
