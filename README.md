<p align="center">
  <img src="https://raw.githubusercontent.com/thelinuxer/tunly/master/src/tunly/data/tunly.svg" alt="Tunly logo" width="160">
</p>

<h1 align="center">Tunly</h1>

<p align="center"><em>Quick SSH tunnels, tidy tray.</em></p>

<p align="center">
  <a href="https://github.com/thelinuxer/tunly/releases/latest"><img src="https://img.shields.io/github/v/release/thelinuxer/tunly" alt="Latest release"></a>
  <a href="https://pypi.org/project/tunly/"><img src="https://img.shields.io/pypi/v/tunly?cacheSeconds=300" alt="PyPI"></a>
  <a href="https://github.com/thelinuxer/tunly/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/thelinuxer/tunly/ci.yml?branch=master&label=ci" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/thelinuxer/tunly" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/GNOME-GTK3-4A86CF" alt="GNOME GTK3">
</p>

GNOME tray applet to manage multiple named SSH dynamic (SOCKS5) tunnels and toggle
the system proxy in one click. Exclusive model: at most one tunnel active at a time —
it drives the system proxy and is reverted on stop, drop, or quit.

- **One click** — pick a tunnel in the tray, ssh comes up, system proxy follows.
- **Always reverted** — stop, crash, drop, or quit: your proxy never stays pointed
  at a dead port.
- **Multiple tunnels** — named profiles, each with its own host, port, and auth.
- **Any auth** — ssh-agent, a specific key file, or password (GNOME keyring / prompt;
  never written to disk).
- **Self-healing** — health-checks the tunnel and cleans up if ssh dies underneath.
- **No daemons, no root** — a single Python/GTK process running as you.

**[📖 Full user guide](docs/GUIDE.md)** — first run, auth setup, troubleshooting.

<p align="center">
  <img src="https://raw.githubusercontent.com/thelinuxer/tunly/master/docs/screenshots/manager.png" alt="Tunnel manager window" width="520">
  &nbsp;
  <img src="https://raw.githubusercontent.com/thelinuxer/tunly/master/docs/screenshots/add-tunnel.png" alt="Add tunnel dialog" width="250">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/thelinuxer/tunly/master/docs/screenshots/tray-menu.png" alt="Tray menu" width="260">
</p>

### Quick install (Debian/Ubuntu)

```bash
wget https://github.com/thelinuxer/tunly/releases/latest/download/tunly_0.1.4_all.deb
sudo apt install ./tunly_0.1.4_all.deb
```

## Requirements

System packages (all preinstalled on a standard GNOME desktop; no pip):

- `python3` + `python3-gi` (GTK 3 introspection)
- `gir1.2-appindicator3-0.1` **or** `gir1.2-ayatanaappindicator3-0.1`
- `gir1.2-notify-0.7` (optional — desktop notifications)
- `ssh`, `curl`

Optional, per auth method:

- **Password auth** works out of the box via an `SSH_ASKPASS` helper (no extra deps).
  If `sshpass` is installed it is used instead.
- **Remember password in keyring** needs `secret-tool` (`libsecret-tools`). Without it,
  password-auth tunnels prompt on each connect.

## Install

The GTK/AppIndicator bindings are **system** packages (GObject-Introspection typelibs),
not PyPI wheels — so sandboxed formats (Flatpak/Snap) can't drive the host proxy and are
not used. Pick one:

### A. Debian / Ubuntu (`.deb`) — recommended for clean system integration

```bash
make deb                 # produces tunly_<ver>_all.deb (needs dpkg-deb)
sudo apt install ./tunly_*.deb   # pulls gir1.2-* deps automatically
```

### B. pipx (any distro)

Because AppIndicator has no PyPI package, the venv must see the system bindings:

```bash
sudo apt install python3-gi gir1.2-gtk-3.0 \
     gir1.2-ayatanaappindicator3-0.1 openssh-client
pipx install --system-site-packages tunly   # from PyPI (or "." from a checkout)
# then, for the app menu + icon:
tunly --install-desktop --autostart
```

### C. Arch Linux

A `PKGBUILD` ships in `packaging/aur/`:

```bash
cd packaging/aur && makepkg -si
```

### D. From source (`make install`)

```bash
sudo make install PREFIX=/usr/local          # installs launcher + .desktop + icon
```

## Run

After install, launch `tunly` (from the app menu or the shell). An icon appears
in the top-bar tray (green = a tunnel is active, grey = none). Click it → per-tunnel
start/stop, `Manage tunnels…`, `Quit`.

Run in place without installing:

```bash
PYTHONPATH=src python3 -m tunly &
```

Menu/autostart integration for a pipx or in-place run:

```bash
tunly --install-desktop            # add --autostart to launch on login
tunly --uninstall-desktop          # remove it
```

## Managing tunnels

`Manage tunnels…` opens a window listing every tunnel with a status dot and
`Start`/`Stop`, `Edit`, `Delete` buttons, plus `+ Add tunnel`. Each tunnel has a
unique name and its own SOCKS port.

### SSH auth methods (per tunnel)

| auth | behaviour |
|------|-----------|
| `agent` | ssh-agent + default keys (default) |
| `key` | private key file (`-i <path> -o IdentitiesOnly=yes`) |
| `password` | GTK prompt at connect (or keyring); fed to ssh with no plaintext on disk |

## Config

`~/.config/tunly/tunnels.json` — created on first run. A legacy
`config.ini` (single-tunnel format) is auto-migrated to tunnel `default`.
Passwords are never written here (keyring or prompt-only).

## Self-test

Real end-to-end check (spawns ssh, sets + reverts proxy, prints exit IP). Point it at
your own reachable SSH server via env vars — nothing is hardcoded:

```bash
SSTRAY_TEST_HOST=vps.example.com SSTRAY_TEST_USER=alice \
  PYTHONPATH=src python3 -m tunly --selftest   # or: tunly --selftest
```

## Security notes

- **Passwords** are never written to `tunnels.json`. They come from the GNOME keyring
  (`secret-tool`) or a prompt, and reach `ssh` via `sshpass -e` or an `SSH_ASKPASS`
  helper — no plaintext on disk. The password does transit the ssh child's environment
  (as with `sshpass`), readable only by the same user via `/proc/<pid>/environ`.
- **Host-key policy** is `StrictHostKeyChecking=accept-new`: unknown host keys are
  trusted on first connect (TOFU) so the non-interactive tunnel can come up; a *changed*
  key is still refused. If you need strict first-connect verification, pre-populate
  `~/.ssh/known_hosts`.
- Runs entirely as your user; it changes only your GNOME proxy settings and spawns
  `ssh`. No privileged operations, no shell interpolation of user input.

## Releasing

Versions are tag-driven; `pyproject.toml` is the single source of truth
(the `.deb` version derives from it at build time). To cut a release:

```bash
# 1. bump `version` in pyproject.toml (and the Quick install URL above), commit
# 2. tag and push — CI builds wheel/sdist + .deb and attaches them to a GitHub Release
git tag v0.2.0 && git push origin v0.2.0
```

CI fails the release if the tag and `pyproject.toml` version disagree.
Unit tests run on every push (`.github/workflows/ci.yml`); live SSH integration
tests run locally with `SSTRAY_TEST_HOST=<server> pytest tests/`.

**Enabling PyPI publishing** (one-time): on pypi.org → *Publishing* → add a trusted
publisher with repository `thelinuxer/tunly`, workflow `release.yml`, environment
`pypi`; create a matching `pypi` environment in the GitHub repo settings; then
uncomment the `pypi` job in `.github/workflows/release.yml`. After that every tagged
release also lands on PyPI (`pipx install tunly`).

## Design

See `docs/2026-07-05-tunly-design.md`.
