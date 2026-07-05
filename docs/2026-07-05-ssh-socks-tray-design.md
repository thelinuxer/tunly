# SSH SOCKS Tray — Design

## Purpose
GNOME top-bar tray applet to manage multiple named SSH dynamic (SOCKS5) tunnels and
toggle the system proxy in one click. Exclusive model: at most one tunnel active at a
time; it drives the system proxy and is reverted on stop/drop/quit so nothing is left
pointing at a dead port.

## Multi-tunnel model
- Config is a list of named tunnels; each name is unique and owns a distinct SOCKS port.
- **Exclusive**: starting a tunnel while another is up auto-stops the first (reverts
  proxy), then starts the new one. The system proxy always points at the one active
  tunnel or nothing.
- Manager tracks `active_name`, `proc`, `saved_mode`.

## SSH auth (per tunnel)
- `agent` — ssh-agent + default keys.
- `key` — `-i <key_path> -o IdentitiesOnly=yes` (path from a file-chooser).
- `password` — password from GNOME keyring (`secret-tool`) or a GTK prompt at connect.
  Delivered to ssh with no plaintext on disk: `sshpass -e` if present, else an
  `SSH_ASKPASS` helper (`SSH_ASKPASS_REQUIRE=force`, ssh spawned with
  `start_new_session=True`). Never written to `tunnels.json`.

## UI
- **Tray icon**: green if a tunnel is active, grey otherwise. Menu lists tunnels
  (`●`/`○` + click to toggle), `Manage tunnels…`, `Quit`.
- **Manager window**: one row per tunnel — status dot, name, host:port, auth,
  `Start`/`Stop`, `Edit`, `Delete`; `+ Add tunnel`. Add/Edit dialog validates unique
  name and unique SOCKS port; auth dropdown reveals key-chooser or password entry.

## Stack
Python 3 + GTK3 + AppIndicator3 (Ayatana fallback). All present on host; no install.

## Config
`~/.config/ssh-socks-tray/tunnels.json` — created on first run. A legacy `config.ini`
(single-tunnel INI) is auto-migrated to a tunnel named `default`. No hardcoded values in
code. Passwords are never written here.

```json
{
  "poll_seconds": 3,
  "tunnels": [
    {"name": "example", "host": "vps.example.com", "ssh_port": 22, "user": "alice",
     "socks_port": 1234, "connect_timeout": 5, "auth": "agent", "key_path": ""}
  ]
}
```

## Behavior

### Start(name)
1. If another tunnel is active, Stop it first (exclusive).
2. Read current `org.gnome.system.proxy mode` and save it (for revert).
3. Build the ssh command for the tunnel's auth method; spawn as a tracked subprocess
   (`start_new_session=True`).
4. Poll until `127.0.0.1:<socks_port>` accepts a TCP connect (up to connect_timeout+2s).
   Fail → kill proc, notify, stay DOWN.
5. Set `proxy.socks host=127.0.0.1 port=<socks_port>`, clear `proxy.http host/port`,
   `proxy mode=manual`. Icon green.

### Stop
1. Terminate ssh subprocess (SIGTERM, then SIGKILL after grace).
2. Restore `proxy mode` to saved value; clear `proxy.socks host/port`. Icon grey.

### Status poll (every poll_seconds)
Active tunnel UP iff its subprocess alive AND its socks port listening. Otherwise revert
proxy and clear active (handles ssh dying on its own). Keeps icon truthful.

### Quit
If a tunnel is active → Stop (revert proxy) first, then exit. Never leaves a stale proxy.

## Files
- `ssh_socks_tray.py` — the applet (single file).
- `tunnels.json` — generated under `~/.config/ssh-socks-tray/`.
- `askpass.sh` — generated helper for password auth (mode 0700; reads pw from env).
- `ssh-socks-tray.desktop` — app-menu launcher (autostart optional, not enabled by default).

## Non-goals (v1)
Non-exclusive concurrent proxies, per-app proxy, live IP readout in menu.
