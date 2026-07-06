<p align="center">
  <img src="src/tunly/data/tunly.svg" alt="Tunly logo" width="160">
</p>

<h1 align="center">Tunly</h1>

<p align="center"><em>Quick SSH tunnels, tidy tray.</em></p>

GNOME tray applet to manage multiple named SSH dynamic (SOCKS5) tunnels and toggle
the system proxy in one click. Exclusive model: at most one tunnel active at a time —
it drives the system proxy and is reverted on stop, drop, or quit.

**[📖 Full user guide](docs/GUIDE.md)** — first run, auth setup, troubleshooting.

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
pipx install --system-site-packages .        # from a checkout
# then, for the app menu + icon:
tunly --install-desktop --autostart
```

### C. From source (`make install`)

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
# 1. bump `version` in pyproject.toml, commit
# 2. tag and push — CI builds wheel/sdist + .deb and attaches them to a GitHub Release
git tag v0.2.0 && git push origin v0.2.0
```

CI fails the release if the tag and `pyproject.toml` version disagree.
PyPI publishing is prepared in `.github/workflows/release.yml` (commented) — enable
by configuring a trusted publisher on pypi.org and uncommenting the `pypi` job.

## Design

See `docs/2026-07-05-tunly-design.md`.
