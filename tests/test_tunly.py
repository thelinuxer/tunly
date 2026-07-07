import json
import os
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import tunly  # noqa: E402


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "tunly"
    monkeypatch.setattr(tunly, "CONFIG_DIR", str(cfg_dir))
    monkeypatch.setattr(tunly, "TUNNELS_PATH", str(cfg_dir / "tunnels.json"))
    monkeypatch.setattr(tunly, "LEGACY_INI", str(cfg_dir / "config.ini"))
    monkeypatch.setattr(tunly, "OLD_CONFIG_DIR", str(tmp_path / "ssh-socks-tray"))
    return tmp_path


def make_tunnel(**kw):
    t = {**tunly.TUNNEL_DEFAULTS, "name": "t1", "host": "example.com",
         "user": "alice", "socks_port": 1080}
    t.update(kw)
    return t


class TestConfig:
    def test_empty_start(self, isolated_config):
        cfg = tunly.load_config()
        assert cfg["tunnels"] == []
        assert cfg["poll_seconds"] == 3

    def test_save_and_reload(self, isolated_config):
        cfg = tunly.load_config()
        cfg["tunnels"].append(make_tunnel())
        tunly.save_config(cfg)
        again = tunly.load_config()
        assert again["tunnels"][0]["name"] == "t1"
        assert again["tunnels"][0]["socks_port"] == 1080

    def test_defaults_backfilled(self, isolated_config):
        os.makedirs(tunly.CONFIG_DIR, exist_ok=True)
        with open(tunly.TUNNELS_PATH, "w") as f:
            json.dump({"tunnels": [{"name": "bare", "host": "h"}]}, f)
        cfg = tunly.load_config()
        t = cfg["tunnels"][0]
        assert t["ssh_port"] == 22
        assert t["auth"] == "agent"

    def test_legacy_ini_migration(self, isolated_config):
        os.makedirs(tunly.CONFIG_DIR, exist_ok=True)
        with open(tunly.LEGACY_INI, "w") as f:
            f.write("[tunnel]\nhost = h1\nssh_port = 2222\nuser = u\n"
                    "socks_port = 1099\nconnect_timeout = 7\n")
        cfg = tunly.load_config()
        t = cfg["tunnels"][0]
        assert (t["name"], t["host"], t["ssh_port"], t["socks_port"]) == \
            ("default", "h1", 2222, 1099)

    def test_old_dir_migration(self, isolated_config):
        os.makedirs(tunly.OLD_CONFIG_DIR, exist_ok=True)
        with open(os.path.join(tunly.OLD_CONFIG_DIR, "tunnels.json"), "w") as f:
            json.dump({"poll_seconds": 3, "tunnels": [make_tunnel(name="old")]}, f)
        cfg = tunly.load_config()
        assert cfg["tunnels"][0]["name"] == "old"


class TestBuildCommand:
    def test_agent(self, isolated_config):
        m = tunly.Manager(headless=True)
        cmd, env = m._build(make_tunnel(ssh_port=2222))
        assert cmd[0] == "ssh" and "-nN" in cmd
        assert cmd[cmd.index("-p") + 1] == "2222"
        assert cmd[cmd.index("-l") + 1] == "alice"
        assert cmd[-1] == "-D1080" and cmd[-2] == "example.com"
        assert "ExitOnForwardFailure=yes" in cmd

    def test_key(self, isolated_config):
        m = tunly.Manager(headless=True)
        cmd, env = m._build(make_tunnel(auth="key", key_path="~/.ssh/k"))
        assert cmd[cmd.index("-i") + 1] == os.path.expanduser("~/.ssh/k")
        assert "IdentitiesOnly=yes" in cmd

    def test_password_via_askpass(self, isolated_config, monkeypatch):
        monkeypatch.setattr(tunly, "keyring_get", lambda n: "sekret")
        monkeypatch.setattr(tunly.shutil, "which", lambda n: None)
        m = tunly.Manager(headless=True)
        cmd, env = m._build(make_tunnel(auth="password"))
        assert "PreferredAuthentications=password" in cmd
        assert env["SSH_SOCKS_PW"] == "sekret"
        assert env["SSH_ASKPASS_REQUIRE"] == "force"
        helper = env["SSH_ASKPASS"]
        out = subprocess.check_output([helper], env={"SSH_SOCKS_PW": "sekret"},
                                      text=True)
        assert out.strip() == "sekret"

    def test_password_via_sshpass(self, isolated_config, monkeypatch):
        monkeypatch.setattr(tunly, "keyring_get", lambda n: "sekret")
        monkeypatch.setattr(tunly.shutil, "which",
                            lambda n: "/usr/bin/sshpass" if n == "sshpass" else None)
        m = tunly.Manager(headless=True)
        cmd, env = m._build(make_tunnel(auth="password"))
        assert cmd[:2] == ["sshpass", "-e"]
        assert env["SSHPASS"] == "sekret"


class TestStartGuards:
    def test_port_busy_refused(self, isolated_config):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            m = tunly.Manager(headless=True)
            m.cfg["tunnels"] = [make_tunnel(socks_port=port)]
            m.start("t1")
            assert m.proc is None
            assert m.active_name is None
        finally:
            srv.close()


needs_host = pytest.mark.skipif(
    not os.environ.get("SSTRAY_TEST_HOST"),
    reason="set SSTRAY_TEST_HOST for live SSH integration tests")


@needs_host
class TestLiveTunnel:
    def test_poll_during_connect_does_not_kill(self, isolated_config):
        m = tunly.Manager(headless=True)
        t = make_tunnel(host=os.environ["SSTRAY_TEST_HOST"],
                        user=os.environ.get("SSTRAY_TEST_USER", os.environ["USER"]),
                        socks_port=int(os.environ.get("SSTRAY_TEST_SOCKS", 1080)))
        m.cfg["tunnels"] = [t]
        cmd, env = m._build(t)
        m.saved_mode = m.proxy.get_string("mode")
        m.active_name = "t1"
        m.connecting = True
        m.proc = subprocess.Popen(cmd, env=env, start_new_session=True)
        try:
            time.sleep(0.4)
            m._poll()
            assert m.proc is not None and m.proc.poll() is None
            deadline = time.time() + 10
            while time.time() < deadline:
                if tunly.port_open("127.0.0.1", t["socks_port"]):
                    break
                time.sleep(0.1)
            m.connecting = False
            m._poll()
            assert m.proc is not None and m.proc.poll() is None
        finally:
            m.kill_proc()
            m.revert_proxy()
