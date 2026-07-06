#!/usr/bin/env python3
"""Tunly — manage multiple named SSH dynamic (SOCKS5) tunnels from the
GNOME tray. Exclusive model: at most one tunnel active at a time; it drives the
system proxy and is reverted on stop/drop/quit. Per-tunnel SSH auth: agent, key
file, or password (keyring or prompt)."""

import os
import json
import signal
import socket
import shutil
import subprocess

import gi
gi.require_version("Gtk", "3.0")
try:
    gi.require_version("AppIndicator3", "0.1")
    from gi.repository import AppIndicator3 as AppIndicator
except (ValueError, ImportError):
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as AppIndicator
try:
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify
except (ValueError, ImportError):
    Notify = None
from gi.repository import Gtk, GLib, Gio

CONFIG_DIR = os.path.join(GLib.get_user_config_dir(), "tunly")
TUNNELS_PATH = os.path.join(CONFIG_DIR, "tunnels.json")
LEGACY_INI = os.path.join(CONFIG_DIR, "config.ini")
# pre-rename config location (app was "ssh-socks-tray")
OLD_CONFIG_DIR = os.path.join(GLib.get_user_config_dir(), "ssh-socks-tray")

ICON_UP = "network-transmit-receive-symbolic"
ICON_DOWN = "network-offline-symbolic"
KEYRING_SERVICE = "tunly"

TUNNEL_DEFAULTS = {
    "name": "", "host": "", "ssh_port": 22, "user": "",
    "socks_port": 1080, "connect_timeout": 5, "auth": "agent", "key_path": "",
}


# ---------------- config ----------------
def _migrate_old_dir():
    """Copy config from the pre-rename ssh-socks-tray dir on first run."""
    if os.path.exists(TUNNELS_PATH) or os.path.exists(LEGACY_INI):
        return
    for fn in ("tunnels.json", "config.ini"):
        src = os.path.join(OLD_CONFIG_DIR, fn)
        if os.path.exists(src):
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(src) as f:
                data = f.read()
            with open(os.path.join(CONFIG_DIR, fn), "w") as f:
                f.write(data)


def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    _migrate_old_dir()
    if os.path.exists(TUNNELS_PATH):
        with open(TUNNELS_PATH) as f:
            cfg = json.load(f)
    elif os.path.exists(LEGACY_INI):
        import configparser
        ini = configparser.ConfigParser()
        ini.read(LEGACY_INI)
        t = ini["tunnel"]
        cfg = {"poll_seconds": int(t.get("poll_seconds", 3)), "tunnels": [{
            **TUNNEL_DEFAULTS, "name": "default", "host": t["host"],
            "ssh_port": int(t["ssh_port"]), "user": t["user"],
            "socks_port": int(t["socks_port"]),
            "connect_timeout": int(t.get("connect_timeout", 5)),
        }]}
        save_config(cfg)
    else:
        cfg = {"poll_seconds": 3, "tunnels": []}
    cfg.setdefault("poll_seconds", 3)
    cfg.setdefault("tunnels", [])
    for t in cfg["tunnels"]:
        for k, v in TUNNEL_DEFAULTS.items():
            t.setdefault(k, v)
    return cfg


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = TUNNELS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, TUNNELS_PATH)


def port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------- keyring (secret-tool) ----------------
def keyring_get(name):
    if not shutil.which("secret-tool"):
        return None
    try:
        r = subprocess.run(
            ["secret-tool", "lookup", "service", KEYRING_SERVICE, "name", name],
            capture_output=True, text=True)
        return r.stdout if r.returncode == 0 and r.stdout else None
    except OSError:
        return None


def keyring_set(name, pw):
    if not shutil.which("secret-tool"):
        return False
    try:
        subprocess.run(
            ["secret-tool", "store", "--label", f"{KEYRING_SERVICE}:{name}",
             "service", KEYRING_SERVICE, "name", name],
            input=pw, text=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


# ---------------- manager ----------------
class Manager:
    def __init__(self, headless=False):
        self.headless = headless
        if Notify and not headless:
            Notify.init("Tunly")
        self.cfg = load_config()
        self.proc = None
        self.active_name = None
        self.connecting = False
        self.saved_mode = None

        self.proxy = Gio.Settings.new("org.gnome.system.proxy")
        self.proxy_socks = Gio.Settings.new("org.gnome.system.proxy.socks")
        self.proxy_http = Gio.Settings.new("org.gnome.system.proxy.http")

        self.window = None
        self.rows_box = None
        if headless:
            self.ind = self.menu = None
            return

        self.ind = AppIndicator.Indicator.new(
            "tunly", ICON_DOWN,
            AppIndicator.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.ind.set_title("SSH SOCKS Tunnel")
        self.menu = Gtk.Menu()
        self.ind.set_menu(self.menu)
        self.refresh()
        GLib.timeout_add_seconds(int(self.cfg["poll_seconds"]), self._poll)

    # ---- lookups ----
    def tunnels(self):
        return self.cfg["tunnels"]

    def by_name(self, name):
        return next((t for t in self.tunnels() if t["name"] == name), None)

    def is_active(self, name):
        return self.active_name == name and self.proc is not None \
            and self.proc.poll() is None

    # ---- ssh command ----
    def _build(self, t):
        """Return (cmd, env) or (None, None) if password aborted."""
        env = os.environ.copy()
        base = [
            "ssh", "-nN",
            "-o", "ExitOnForwardFailure=yes",
            "-o", f"ConnectTimeout={t['connect_timeout']}",
            "-o", "ServerAliveInterval=15",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", str(t["ssh_port"]),
            "-l", t["user"],
        ]
        auth = t.get("auth", "agent")
        if auth == "key":
            base += ["-i", os.path.expanduser(t["key_path"]),
                     "-o", "IdentitiesOnly=yes"]
        elif auth == "password":
            pw = keyring_get(t["name"])
            if pw is None:
                pw, remember = self._prompt_password(t["name"])
                if pw is None:
                    return None, None
                if remember:
                    keyring_set(t["name"], pw)
            base += ["-o", "PubkeyAuthentication=no",
                     "-o", "PreferredAuthentications=password",
                     "-o", "NumberOfPasswordPrompts=1"]
            if shutil.which("sshpass"):
                env["SSHPASS"] = pw
                base = ["sshpass", "-e"] + base
            else:
                # no external dep: feed password via SSH_ASKPASS helper
                env["SSH_ASKPASS"] = self._ensure_askpass()
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env.setdefault("DISPLAY", ":0")
                env["SSH_SOCKS_PW"] = pw
        cmd = base + [t["host"], f"-D{t['socks_port']}"]
        return cmd, env

    def _ensure_askpass(self):
        path = os.path.join(CONFIG_DIR, "askpass.sh")
        if not os.path.exists(path):
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(path, "w") as f:
                f.write('#!/bin/sh\nprintf \'%s\\n\' "$SSH_SOCKS_PW"\n')
            os.chmod(path, 0o700)
        return path

    # ---- start/stop ----
    def start(self, name):
        t = self.by_name(name)
        if t is None:
            return
        if self.proc is not None and self.proc.poll() is None:
            self.stop()  # exclusive: drop current first
        cmd, env = self._build(t)
        if cmd is None:
            return
        self.saved_mode = self.proxy.get_string("mode")
        self.active_name = name
        self.connecting = True
        try:
            self.proc = subprocess.Popen(cmd, env=env, start_new_session=True)
        except OSError as e:
            self.notify("Tunnel failed to launch", str(e))
            self.active_name = None
            self.connecting = False
            self.refresh()
            return
        deadline = int(t["connect_timeout"]) + 2
        if self.headless:
            return
        GLib.timeout_add(400, self._await_listener, name, deadline * 1000)
        self.refresh()

    def _await_listener(self, name, remaining_ms):
        t = self.by_name(name)
        if t is None or self.active_name != name:
            self.connecting = False
            return False
        if self.proc.poll() is not None:
            self.notify(f"{name}: failed", "ssh exited before SOCKS came up.")
            self.proc = None
            self.active_name = None
            self.connecting = False
            self.refresh()
            return False
        if port_open("127.0.0.1", t["socks_port"]):
            self.apply_proxy(t["socks_port"])
            self.connecting = False
            self.notify(f"{name}: UP", f"SOCKS5 127.0.0.1:{t['socks_port']}")
            self.refresh()
            return False
        remaining_ms -= 400
        if remaining_ms <= 0:
            self.kill_proc()
            self.active_name = None
            self.connecting = False
            self.notify(f"{name}: timeout", "SOCKS port never opened.")
            self.refresh()
            return False
        GLib.timeout_add(400, self._await_listener, name, remaining_ms)
        return False

    def stop(self):
        self.kill_proc()
        self.revert_proxy()
        self.active_name = None
        self.connecting = False
        self.refresh()

    def kill_proc(self):
        if self.proc is None:
            return
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        except Exception:
            pass
        self.proc = None

    def apply_proxy(self, port):
        self.proxy_socks.set_string("host", "127.0.0.1")
        self.proxy_socks.set_int("port", port)
        self.proxy_http.set_string("host", "")
        self.proxy_http.set_int("port", 0)
        self.proxy.set_string("mode", "manual")

    def revert_proxy(self):
        self.proxy.set_string("mode", self.saved_mode or "none")
        self.proxy_socks.set_string("host", "")
        self.proxy_socks.set_int("port", 0)

    def _poll(self):
        # active ssh died on its own -> clean up + revert
        if self.connecting:
            return True  # _await_listener owns the connecting phase
        if self.active_name is not None:
            t = self.by_name(self.active_name)
            alive = self.proc is not None and self.proc.poll() is None \
                and (t is not None and port_open("127.0.0.1", t["socks_port"]))
            if not alive:
                self.kill_proc()
                self.revert_proxy()
                dropped, self.active_name = self.active_name, None
                self.notify(f"{dropped}: dropped", "ssh died; proxy reverted.")
                self.refresh()
        return True

    def notify(self, summary, body=""):
        if not Notify or self.headless:
            return
        try:
            Notify.Notification.new(summary, body, ICON_UP).show()
        except Exception:
            pass

    # ---- UI: tray menu ----
    def refresh(self):
        if self.headless:
            return
        any_up = self.active_name is not None and self.is_active(self.active_name)
        self.ind.set_icon_full(ICON_UP if any_up else ICON_DOWN, "status")
        for c in self.menu.get_children():
            self.menu.remove(c)
        if not self.tunnels():
            mi = Gtk.MenuItem(label="(no tunnels — Manage…)")
            mi.set_sensitive(False)
            self.menu.append(mi)
        for t in self.tunnels():
            up = self.is_active(t["name"])
            mi = Gtk.MenuItem(label=f"{'●' if up else '○'} {t['name']}")
            mi.connect("activate", self._on_tray_toggle, t["name"])
            self.menu.append(mi)
        self.menu.append(Gtk.SeparatorMenuItem())
        mgr = Gtk.MenuItem(label="Manage tunnels…")
        mgr.connect("activate", lambda _: self.show_window())
        self.menu.append(mgr)
        self.menu.append(Gtk.SeparatorMenuItem())
        q = Gtk.MenuItem(label="Quit")
        q.connect("activate", self.on_quit)
        self.menu.append(q)
        self.menu.show_all()
        self._refresh_window()

    def _on_tray_toggle(self, _, name):
        self.stop() if self.is_active(name) else self.start(name)

    # ---- UI: manager window ----
    def show_window(self):
        if self.window is None:
            self._build_window()
        self.window.show_all()
        self.window.present()
        self._refresh_window()

    def _build_window(self):
        self.window = Gtk.Window(title="SSH SOCKS Tunnels")
        self.window.set_default_size(620, 320)
        self.window.set_border_width(8)
        self.window.connect("delete-event", lambda *a: self.window.hide() or True)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self.rows_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        scroll.add(self.rows_box)
        outer.pack_start(scroll, True, True, 0)
        add = Gtk.Button(label="+ Add tunnel")
        add.connect("clicked", lambda _: self._edit_dialog(None))
        outer.pack_start(add, False, False, 0)
        self.window.add(outer)

    def _refresh_window(self):
        if self.rows_box is None:
            return
        for c in self.rows_box.get_children():
            self.rows_box.remove(c)
        for t in self.tunnels():
            self.rows_box.add(self._make_row(t))
        self.rows_box.show_all()

    def _make_row(self, t):
        up = self.is_active(t["name"])
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        dot = Gtk.Image.new_from_icon_name(
            "media-record-symbolic", Gtk.IconSize.MENU)
        dot.set_opacity(1.0 if up else 0.25)
        row.pack_start(dot, False, False, 0)
        name = Gtk.Label(label=t["name"], xalign=0)
        name.set_width_chars(14)
        row.pack_start(name, False, False, 0)
        info = Gtk.Label(
            label=f"{t['host']}:{t['socks_port']}  ({t['auth']})", xalign=0)
        row.pack_start(info, True, True, 0)
        btn = Gtk.Button(label="Stop" if up else "Start")
        btn.connect("clicked", self._on_row_toggle, t["name"])
        row.pack_start(btn, False, False, 0)
        edit = Gtk.Button(label="Edit")
        edit.connect("clicked", lambda _, n=t["name"]: self._edit_dialog(n))
        row.pack_start(edit, False, False, 0)
        dele = Gtk.Button(label="Delete")
        dele.connect("clicked", lambda _, n=t["name"]: self._delete(n))
        row.pack_start(dele, False, False, 0)
        return row

    def _on_row_toggle(self, _, name):
        self.stop() if self.is_active(name) else self.start(name)

    def _delete(self, name):
        if self.is_active(name):
            self.stop()
        self.cfg["tunnels"] = [t for t in self.tunnels() if t["name"] != name]
        save_config(self.cfg)
        self.refresh()

    def _edit_dialog(self, name):
        editing = self.by_name(name) if name else None
        d = Gtk.Dialog(title="Edit tunnel" if editing else "Add tunnel",
                       transient_for=self.window, modal=True)
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                      "Save", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        grid = Gtk.Grid(row_spacing=6, column_spacing=8, border_width=10)

        def field(row, label, default):
            grid.attach(Gtk.Label(label=label, xalign=1), 0, row, 1, 1)
            e = Gtk.Entry()
            e.set_text(str(default))
            grid.attach(e, 1, row, 2, 1)
            return e

        base = editing or TUNNEL_DEFAULTS
        e_name = field(0, "Name", base["name"])
        e_host = field(1, "Host", base["host"])
        e_sshport = field(2, "SSH port", base["ssh_port"])
        e_user = field(3, "User", base["user"])
        e_socks = field(4, "SOCKS port", base["socks_port"])
        e_timeout = field(5, "Connect timeout", base["connect_timeout"])

        grid.attach(Gtk.Label(label="Auth", xalign=1), 0, 6, 1, 1)
        combo = Gtk.ComboBoxText()
        for a in ("agent", "key", "password"):
            combo.append_text(a)
        combo.set_active(("agent", "key", "password").index(base.get("auth", "agent")))
        grid.attach(combo, 1, 6, 2, 1)

        key_lbl = Gtk.Label(label="Key file", xalign=1)
        key_chooser = Gtk.FileChooserButton(title="Select private key")
        if base.get("key_path"):
            key_chooser.set_filename(os.path.expanduser(base["key_path"]))
        grid.attach(key_lbl, 0, 7, 1, 1)
        grid.attach(key_chooser, 1, 7, 2, 1)

        pw_lbl = Gtk.Label(label="Password", xalign=1)
        pw_entry = Gtk.Entry()
        pw_entry.set_visibility(False)
        pw_entry.set_placeholder_text("blank = prompt / keep stored")
        grid.attach(pw_lbl, 0, 8, 1, 1)
        grid.attach(pw_entry, 1, 8, 2, 1)

        def sync_auth(*_):
            a = combo.get_active_text()
            key_lbl.set_visible(a == "key")
            key_chooser.set_visible(a == "key")
            pw_lbl.set_visible(a == "password")
            pw_entry.set_visible(a == "password")
        combo.connect("changed", sync_auth)

        d.get_content_area().add(grid)
        grid.show_all()
        sync_auth()

        while True:
            resp = d.run()
            if resp != Gtk.ResponseType.OK:
                d.destroy()
                return
            new_name = e_name.get_text().strip()
            err = self._validate(new_name, e_sshport, e_socks, e_timeout,
                                  editing)
            if err:
                self._error(err)
                continue
            auth = combo.get_active_text()
            rec = {
                "name": new_name, "host": e_host.get_text().strip(),
                "ssh_port": int(e_sshport.get_text()),
                "user": e_user.get_text().strip(),
                "socks_port": int(e_socks.get_text()),
                "connect_timeout": int(e_timeout.get_text()),
                "auth": auth,
                "key_path": key_chooser.get_filename() or "" if auth == "key" else "",
            }
            if editing:
                # rename: drop stale keyring under old name if changed
                idx = self.tunnels().index(editing)
                self.tunnels()[idx] = rec
            else:
                self.tunnels().append(rec)
            if auth == "password" and pw_entry.get_text():
                keyring_set(new_name, pw_entry.get_text())
            save_config(self.cfg)
            d.destroy()
            self.refresh()
            return

    def _validate(self, name, e_sshport, e_socks, e_timeout, editing):
        if not name:
            return "Name required."
        dup = self.by_name(name)
        if dup is not None and dup is not editing:
            return f"Name '{name}' already exists."
        for e, label in ((e_sshport, "SSH port"), (e_socks, "SOCKS port"),
                         (e_timeout, "Connect timeout")):
            try:
                int(e.get_text())
            except ValueError:
                return f"{label} must be a number."
        for t in self.tunnels():
            if t is editing:
                continue
            if str(t["socks_port"]) == e_socks.get_text().strip():
                return f"SOCKS port {e_socks.get_text()} used by '{t['name']}'."
        return None

    def _error(self, msg):
        d = Gtk.MessageDialog(transient_for=self.window, modal=True,
                              message_type=Gtk.MessageType.ERROR,
                              buttons=Gtk.ButtonsType.OK, text=msg)
        d.run()
        d.destroy()

    def _prompt_password(self, name):
        d = Gtk.Dialog(title=f"SSH password: {name}",
                       transient_for=self.window, modal=True)
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                      "OK", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        box = d.get_content_area()
        box.set_border_width(10)
        box.add(Gtk.Label(label=f"Password for {name}:"))
        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_activates_default(True)
        box.add(entry)
        remember = Gtk.CheckButton(label="Remember in keyring")
        box.add(remember)
        box.show_all()
        resp = d.run()
        pw = entry.get_text() if resp == Gtk.ResponseType.OK else None
        rem = remember.get_active()
        d.destroy()
        return pw, rem

    def on_quit(self, *_):
        if self.proc is not None and self.proc.poll() is None:
            self.stop()
        Gtk.main_quit()


# ---------------- selftest ----------------
def selftest():
    import time
    # Real end-to-end check needs a reachable SSH host. Configure via env:
    #   SSTRAY_TEST_HOST, SSTRAY_TEST_USER, SSTRAY_TEST_PORT, SSTRAY_TEST_SOCKS
    host = os.environ.get("SSTRAY_TEST_HOST")
    if not host:
        print("Set SSTRAY_TEST_HOST (and optionally SSTRAY_TEST_USER/PORT/SOCKS) "
              "to a reachable SSH server to run the self-test.")
        return 2
    m = Manager(headless=True)
    snap = {"mode": m.proxy.get_string("mode"),
            "sh": m.proxy_socks.get_string("host"),
            "sp": m.proxy_socks.get_int("port")}
    print(f"[snap] {snap}")
    t = {**TUNNEL_DEFAULTS, "name": "selftest", "host": host,
         "ssh_port": int(os.environ.get("SSTRAY_TEST_PORT", 22)),
         "user": os.environ.get("SSTRAY_TEST_USER", os.environ.get("USER", "")),
         "socks_port": int(os.environ.get("SSTRAY_TEST_SOCKS", 1080)),
         "connect_timeout": 5, "auth": "agent"}
    m.cfg["tunnels"] = [t]
    ok = True
    try:
        cmd, env = m._build(t)
        print(f"[cmd] {' '.join(cmd)}")
        m.saved_mode = snap["mode"]
        m.active_name = "selftest"
        m.proc = subprocess.Popen(cmd, env=env, start_new_session=True)
        deadline = time.time() + t["connect_timeout"] + 3
        while time.time() < deadline:
            if m.proc.poll() is not None:
                print("[FAIL] ssh exited early"); ok = False; break
            if port_open("127.0.0.1", t["socks_port"]):
                break
            time.sleep(0.3)
        else:
            print("[FAIL] SOCKS port never opened"); ok = False
        if ok:
            m.apply_proxy(t["socks_port"])
            mode = m.proxy.get_string("mode")
            sh = m.proxy_socks.get_string("host")
            sp = m.proxy_socks.get_int("port")
            print(f"[proxy] mode={mode} socks={sh}:{sp}")
            ok = (mode == "manual" and sh == "127.0.0.1" and sp == t["socks_port"])
            try:
                out = subprocess.check_output(
                    ["curl", "-s", "--max-time", "12", "--socks5-hostname",
                     f"127.0.0.1:{t['socks_port']}", "https://ifconfig.me"],
                    text=True).strip()
                print(f"[exit IP] {out}")
            except Exception as e:
                print(f"[exit IP skipped] {e}")
    finally:
        m.kill_proc()
        m.revert_proxy()
        m.proxy_socks.set_string("host", snap["sh"])
        m.proxy_socks.set_int("port", snap["sp"])
        m.proxy.set_string("mode", snap["mode"])
        Gio.Settings.sync()
        print(f"[restored] mode={m.proxy.get_string('mode')} "
              f"socks={m.proxy_socks.get_string('host')}:"
              f"{m.proxy_socks.get_int('port')}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


APP_ID = "tunly"


def _data_dir():
    from importlib import resources
    return resources.files(__package__).joinpath("data")


def install_desktop(autostart=False):
    apps = os.path.join(GLib.get_user_data_dir(), "applications")
    icons = os.path.join(GLib.get_user_data_dir(),
                         "icons", "hicolor", "scalable", "apps")
    os.makedirs(apps, exist_ok=True)
    os.makedirs(icons, exist_ok=True)
    data = _data_dir()
    desktop = os.path.join(apps, f"{APP_ID}.desktop")
    with open(desktop, "w") as f:
        f.write(data.joinpath(f"{APP_ID}.desktop").read_text())
    icon = os.path.join(icons, f"{APP_ID}.svg")
    with open(icon, "w") as f:
        f.write(data.joinpath(f"{APP_ID}.svg").read_text())
    print(f"installed {desktop}")
    print(f"installed {icon}")
    if autostart:
        adir = os.path.join(GLib.get_user_config_dir(), "autostart")
        os.makedirs(adir, exist_ok=True)
        dst = os.path.join(adir, f"{APP_ID}.desktop")
        with open(dst, "w") as f:
            f.write(data.joinpath(f"{APP_ID}.desktop").read_text())
        print(f"installed {dst}")


def uninstall_desktop():
    for p in (
        os.path.join(GLib.get_user_data_dir(), "applications", f"{APP_ID}.desktop"),
        os.path.join(GLib.get_user_data_dir(), "icons", "hicolor",
                     "scalable", "apps", f"{APP_ID}.svg"),
        os.path.join(GLib.get_user_config_dir(), "autostart", f"{APP_ID}.desktop"),
    ):
        if os.path.exists(p):
            os.remove(p)
            print(f"removed {p}")


def main():
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    if "--install-desktop" in sys.argv:
        install_desktop(autostart="--autostart" in sys.argv)
        return
    if "--uninstall-desktop" in sys.argv:
        uninstall_desktop()
        return
    m = Manager()
    if not m.tunnels():
        m.show_window()
    for sig in (signal.SIGINT, signal.SIGTERM):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig,
                             lambda: (m.on_quit(), True)[1])
    Gtk.main()


if __name__ == "__main__":
    main()
