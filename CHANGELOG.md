# Changelog

All notable changes to Tunly are documented here.

## 0.3.0 — 2026-08-12

### Transparent mode

Tunly could only ask apps politely to use the tunnel, by setting the GNOME
system proxy. Apps that ignore that setting — `curl`, `yt-dlp`, `git`, `apt`,
Steam, most CLI tools — left over your real IP with no indication anything was
wrong.

**Transparent (whole system)** in the tray forces *all* outbound TCP through the
active tunnel using iptables. No per-app configuration, nothing to opt into.

- Off by default. Existing installs keep behaving exactly as before.
- Toggling while a tunnel is up **hot-swaps** the delivery mechanism: `ssh` keeps
  running and the SOCKS port is unchanged, so there is no reconnect and no
  re-auth.
- Needs root for the firewall rules — one polkit prompt per session. Proxy mode
  still needs no privileges at all.

### Fail-closed by design

While transparent mode is on, traffic that cannot go through the tunnel is
**rejected rather than leaked**:

- UDP is rejected, so QUIC falls back to TCP within milliseconds.
- **ICMP is blocked outright, LAN included** — `ping` will not work. This is the
  kill switch, not a broken network.
- IPv6 is rejected, so apps fall back to IPv4, which is tunnelled.

The kill switch is installed **before** the redirect. The reverse order leaves a
window where traffic is neither blocked nor captured; measured on real hardware,
that window leaked the real IP for 5–10 seconds after enabling.

### DNS

Your resolver forwards upstream over UDP/53, which would leave every domain you
visit visible to your ISP even with TCP tunnelled. Transparent mode redirects
DNS into a forwarder that re-asks a configured resolver over DNS-over-TCP
through the tunnel.

- New `dns_server` setting, default `1.1.1.1`, editable in *Manage tunnels…*.
- systemd-resolved keeps working as your local cache; only its upstream leg is
  captured.
- **Known limitation:** split-horizon DNS from a corporate resolver stops
  resolving while transparent mode is on.

### Getting your network back

Three independent guarantees, in order of what acts first:

1. The privileged helper holds Tunly's stdin. Tunly dying — `SIGKILL`, OOM,
   anything — closes that pipe, and the helper removes every rule on its own.
   No cooperation from the dying process is required.
2. `tunly --repair` tears everything down standalone, no GUI and no tunnel.
3. Reboot. Rules are never persisted.

Teardown is idempotent and retried, and every rule lives in a dedicated chain —
Tunly never writes into a built-in chain except for two jumps.

Existing sockets are forced through the tunnel by flushing TCP conntrack on
enable; without the optional `conntrack` tool they simply stay direct, and this
is logged.

### Other

- All `iptables` calls pass `-w`, so a lock collision with Docker can no longer
  strand rules.
- `tunly --repair` added.
- The tray log records why a tunnel went down (stopped, dropped, health failure,
  toggled), and the privileged helper logs to `~/.cache/tunly-netguard.log`.
- `Depends: iptables`; `Recommends: conntrack`.
- Rule generation is pure and unit-tested; the ruleset is also exercised against
  a real kernel inside throwaway network namespaces, including a test that
  `SIGKILL`s the parent and asserts the rules come off.

### Upgrade notes

Nothing to do. `transparent` defaults to `false`, so proxy mode remains the
default behaviour. Enable it from the tray when you want whole-system capture,
and remember that `ping` stops working while it is on.

## 0.1.4 and earlier

Tray applet for named SSH SOCKS5 tunnels: multiple profiles, per-tunnel auth
(agent / key file / password via keyring), exclusive one-at-a-time model,
automatic proxy revert on stop, drop, or quit, and health checks that clean up
when ssh dies underneath.
