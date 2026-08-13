# Tunly User Guide

Tunly is a GNOME tray applet that manages named SSH dynamic (SOCKS5) tunnels and
points your system proxy at the active one. One click up, one click down — and the
proxy is always reverted when a tunnel stops, drops, or the app quits.

- [How it works](#how-it-works)
- [Proxy mode vs transparent mode](#proxy-mode-vs-transparent-mode)
- [Installation](#installation)
- [First run](#first-run)
- [The tray icon](#the-tray-icon)
- [Managing tunnels](#managing-tunnels)
- [SSH authentication](#ssh-authentication)
- [The configuration file](#the-configuration-file)
- [Verifying your traffic is routed](#verifying-your-traffic-is-routed)
- [Troubleshooting](#troubleshooting)
- [Logs](#logs)
- [Uninstalling](#uninstalling)

## How it works

When you start a tunnel, Tunly:

1. Saves your current GNOME proxy mode so it can restore it later.
2. Spawns `ssh -nN -D <socks_port>` to the tunnel's host — a standard SSH dynamic
   port forward. SSH listens on `127.0.0.1:<socks_port>` as a SOCKS5 proxy and
   relays everything through the remote server.
3. Waits until the SOCKS port actually accepts connections.
4. Sets the GNOME system proxy: mode `manual`, SOCKS host `127.0.0.1`, SOCKS port
   `<socks_port>` (and clears the HTTP proxy fields so nothing conflicts).

When you stop it (or it drops, or you quit), Tunly kills the ssh process, restores
the saved proxy mode, and clears the SOCKS fields. Your desktop never stays pointed
at a dead proxy.

**Exclusive model.** At most one tunnel is active at a time. Starting tunnel B while
tunnel A is up stops A first (with a full proxy revert), then starts B. The system
proxy always reflects exactly one tunnel — or none.

## Proxy mode vs transparent mode

The steps above describe **proxy mode**, the default. It only covers apps that
read the system proxy setting — Firefox, Chrome, GTK apps. `curl`, `yt-dlp`,
`git`, `apt`, Steam and most CLI tools ignore it entirely and go out over your
real IP.

Tick **Transparent (whole system)** in the tray to force *all* outbound TCP
through the tunnel with iptables instead. Apps get no say and need no config.

|  | Proxy mode (default) | Transparent mode |
|---|---|---|
| Covers | apps that read the proxy setting | everything (TCP) |
| Root | not needed | one polkit prompt per session |
| DNS | app-dependent | forced through the tunnel |
| UDP | direct | rejected (QUIC falls back to TCP) |
| ICMP (`ping`) | works | blocked outright, LAN included |
| IPv6 | direct | rejected (apps fall back to tunnelled v4) |

Both modes run on the same `ssh -D` process, so you can flip the toggle while a
tunnel is up: the tunnel is not restarted and you are not re-prompted for SSH
credentials. Only the delivery mechanism changes.

> **`ping` does not work in transparent mode.** ICMP cannot travel through a
> SOCKS5 TCP tunnel, so it is rejected rather than allowed out over your real
> IP. Use `curl` to check connectivity instead. Expect a few seconds after
> enabling where traffic is blocked while the rules settle — that is the kill
> switch, and it is deliberately blocking rather than leaking.

### Transparent mode needs a DNS server

Your local resolver forwards queries upstream to your router, which is
unreachable from the tunnel exit — so transparent mode redirects DNS to a
resolver you choose and asks it over TCP through the tunnel. Set it in
**Manage tunnels…** (`dns_server`, default `1.1.1.1`).

Split-horizon DNS from a corporate resolver will not resolve while transparent
mode is on.

### If something goes wrong

Rules live in dedicated chains and are removed when you stop the tunnel, quit,
or if Tunly is killed. To clean up by hand:

```bash
tunly --repair
```

Rules are never persisted, so a reboot also clears them.

## Installation

### Debian / Ubuntu (recommended)

```bash
make deb
sudo apt install ./tunly_*.deb
```

The package declares all GTK/AppIndicator dependencies, so `apt` pulls anything
missing. The app appears in your application menu as **Tunly**.

### pipx (any distro)

The GTK bindings are system packages (GObject-Introspection typelibs), not PyPI
wheels, so the pipx venv must see them:

```bash
sudo apt install python3-gi gir1.2-gtk-3.0 \
     gir1.2-ayatanaappindicator3-0.1 openssh-client
pipx install --system-site-packages tunly    # or "." from a checkout
tunly --install-desktop --autostart          # app menu entry + start on login
```

### From source

```bash
sudo make install PREFIX=/usr/local
```

Installs the launcher, `.desktop` entry, and icon system-wide.

## First run

Launch **Tunly** from the application menu (or run `tunly`). With no tunnels
configured, the manager window opens automatically. Click **+ Add tunnel** and fill
in:

| Field | Meaning | Example |
|---|---|---|
| Name | Unique label for this tunnel | `home-vps` |
| Host | SSH server (IP or hostname) | `vps.example.com` |
| SSH port | The server's SSH port | `22` |
| User | SSH login user | `alice` |
| SOCKS port | Local port for the SOCKS5 proxy — unique per tunnel | `1080` |
| Connect timeout | Seconds to wait for the SSH connection | `5` |
| Auth | `agent`, `key`, or `password` — see below | `agent` |

Save, then click **Start** on the row. The dot turns green, the tray icon lights
up, and your system proxy now routes through the tunnel.

## The tray icon

The top-bar icon shows the global state: **green** when a tunnel is active,
**grey** when none is. Clicking it opens a menu:

- One entry per tunnel — `●` (active) or `○` (inactive). Click to toggle that
  tunnel: starting one stops whichever was running.
- **Transparent (whole system)** — routes everything through the tunnel with
  iptables instead of the proxy setting. Applies immediately, even mid-tunnel.
- **Manage tunnels…** — opens the manager window.
- **Quit** — stops the active tunnel (reverting the proxy and removing any
  firewall rules) and exits.

Desktop notifications announce state changes: tunnel up, tunnel down, tunnel
dropped, connection failures.

## Managing tunnels

**Manage tunnels…** lists every tunnel with:

- a status dot (green = active),
- name, `host:socks_port`, and auth method,
- **Start** / **Stop** — toggles the tunnel,
- **Edit** — change any field (validation enforces unique names and unique SOCKS
  ports),
- **Delete** — removes the tunnel (stopping it first if active),
- **+ Add tunnel** at the bottom.

Closing the window only hides it; the app keeps running in the tray.

## SSH authentication

Set per tunnel in the Add/Edit dialog:

### `agent` (default)

Uses your running ssh-agent and default keys (`~/.ssh/id_*`), exactly like a plain
`ssh host` from your shell. If `ssh user@host` works from a terminal, `agent` works
in Tunly. Best choice when you have key access.

### `key`

Uses one specific private key file: Tunly passes `-i <key_path>` together with
`IdentitiesOnly=yes`, so only that key is offered. Pick the key file in the dialog.
Note: if the key has a passphrase it must already be loaded in your agent, since
the tunnel process cannot prompt for it.

### `password`

For servers that only accept password login:

- If the password is stored in the GNOME keyring, it is used directly.
- Otherwise a prompt appears at connect time, with a **Remember in keyring**
  checkbox (requires `secret-tool` from `libsecret-tools`; without it you are
  prompted on every connect).

The password is never written to the config file or any other file. It is handed
to ssh through `sshpass -e` if installed, or an `SSH_ASKPASS` helper otherwise —
both keep it out of the command line and off the disk.

**Host keys:** Tunly uses `StrictHostKeyChecking=accept-new` — an unknown server
key is trusted on first connect, but a *changed* key is refused. To verify a host
key manually before first use, ssh to the server once from a terminal.

## The configuration file

`~/.config/tunly/tunnels.json`:

```json
{
  "poll_seconds": 3,
  "transparent": false,
  "dns_server": "1.1.1.1",
  "tunnels": [
    {
      "name": "home-vps",
      "host": "vps.example.com",
      "ssh_port": 22,
      "user": "alice",
      "socks_port": 1080,
      "connect_timeout": 5,
      "auth": "agent",
      "key_path": ""
    }
  ]
}
```

- Edit it by hand if you prefer — Tunly reads it on startup.
- `poll_seconds` controls how often Tunly health-checks the active tunnel.
- `transparent` is the whole-system iptables mode; it is global, not per-tunnel,
  since only one tunnel runs at a time.
- `dns_server` is the resolver transparent mode asks over TCP through the tunnel.
- Passwords are never stored here.
- Configs from the app's earlier name (`~/.config/ssh-socks-tray/`) are migrated
  automatically on first run.

## Verifying your traffic is routed

With a tunnel active:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me   # via the tunnel
curl https://ifconfig.me                                     # apps honoring the proxy
```

The first must print the tunnel server's IP. In **proxy mode** the second prints
your real IP — `curl` ignores the system proxy, and that is exactly the gap
transparent mode closes. If a browser still shows your real IP, see the browser
notes below.

In **transparent mode** both commands must print the tunnel server's IP:

```bash
curl https://ifconfig.me            # no proxy flags at all — must show the tunnel IP
getent hosts example.com            # must still resolve
```

Give it a few seconds after enabling. During the settling window connections are
blocked, not leaked, so a timeout there is expected rather than alarming.

To confirm DNS is not leaking, ask what resolver the authoritative side sees:

```bash
dig +short o-o.myaddr.l.google.com TXT
```

It should report an address belonging to your configured `dns_server`'s
operator, not your ISP.

## Troubleshooting

### "Tunnel failed — ssh exited before SOCKS came up"

SSH could not connect or authenticate. Test the same login from a terminal:
`ssh -p <port> <user>@<host>`. Typical causes: wrong host/port/user, key not in
the agent, or the server rejects the auth method (e.g. password login to a
pubkey-only server).

### "Tunnel timeout — SOCKS port never opened"

The port is likely in use by something else (Tunly passes
`ExitOnForwardFailure=yes`, so a failed bind kills the connection). Check with
`ss -tlnp | grep <socks_port>` and either free the port or give the tunnel a
different SOCKS port.

### Browser still shows my real IP

- **Firefox** manages its own proxy: Settings → Network Settings → either "Use
  system proxy settings" or manual SOCKS5 `127.0.0.1:<port>`, and enable
  **Proxy DNS when using SOCKS v5**.
- **Chrome/Chromium** honors the GNOME proxy on most setups; if not, launch with
  `--proxy-server="socks5://127.0.0.1:<port>"`.
- Terminal tools need explicit flags (e.g. `curl --socks5-hostname ...`) or
  `ALL_PROXY=socks5h://127.0.0.1:<port>`.
- WebRTC can leak your real IP in browsers even with a proxy; disable it if that
  matters to you.

### Tunnel drops shortly after starting

Tunly health-checks the ssh process and SOCKS port every `poll_seconds`; when the
connection dies it reverts the proxy and notifies you. Frequent drops usually mean
an unstable network path or an aggressive NAT — Tunly already sends
`ServerAliveInterval=15` keepalives; consider also setting `ClientAliveInterval`
on the server.

### `ping` says "Operation not permitted" / "Packet filtered"

Working as designed, in transparent mode only. ICMP cannot travel through a
SOCKS5 TCP tunnel, so letting it out would reveal your real IP. It is blocked
everywhere, LAN included. Test connectivity with `curl` instead, or turn
transparent mode off.

### Everything is blocked right after enabling transparent mode

Expected for a few seconds. The kill switch is installed before the redirect, so
the gap between "no longer direct" and "now tunnelled" blocks rather than leaks.
If it lasts more than ~15 seconds, check `~/.cache/tunly-netguard.log`.

### My traffic is still direct in transparent mode

Connections opened *before* you enabled it keep flowing over their existing
paths. Tunly flushes TCP conntrack on enable to force them to re-establish, but
that needs the optional `conntrack` tool — install it (`sudo apt install
conntrack`) or restart the app in question. `~/.cache/tunly-netguard.log` says
which happened.

### Nothing resolves in transparent mode

`dns_server` is unreachable or unset. It must be a public resolver reachable
from your tunnel server — your router's address will not work, since the exit
node cannot reach it. Corporate split-horizon names will not resolve either.

### Firewall rules were left behind

```bash
tunly --repair
```

This removes every Tunly chain and is safe to run at any time, including when no
tunnel is running. Rules are never persisted, so rebooting also clears them.
If you suspect leftovers, check for them with:

```bash
sudo iptables -S | grep TUNLY ; sudo iptables -t nat -S | grep TUNLY
```

### Password prompt appears every time

Install `libsecret-tools` (provides `secret-tool`) and tick **Remember in
keyring** at the next prompt.

### The proxy was left on after a crash

Kill leftovers and reset in one go:

```bash
pkill -f 'ssh -nN' ; gsettings set org.gnome.system.proxy mode 'none' ; tunly --repair
```

(Normal stop/quit paths always revert this automatically, and the privileged
helper removes firewall rules by itself if Tunly is killed.)

## Logs

| File | Contents |
|---|---|
| `~/.cache/tunly-netguard.log` | every firewall command that failed, teardown results, conntrack flush |
| tray stdout | why a tunnel went down: stopped, dropped, health failure, or toggled |

To capture the tray's own output, start it as
`tunly > ~/.cache/tunly.log 2>&1` — ssh's stderr lands there too.

## Uninstalling

| Installed via | Remove with |
|---|---|
| deb | `sudo apt remove tunly` |
| pipx | `tunly --uninstall-desktop && pipx uninstall tunly` |
| make | `sudo make uninstall` |

Config lives in `~/.config/tunly/` — delete it manually if you want a clean
slate. Stored passwords can be removed with
`secret-tool clear service tunly name <tunnel-name>`.
