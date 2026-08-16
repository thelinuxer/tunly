"""Pure command generation for NetworkManager's connectivity check.

Transparent mode breaks that check and no setting can repair it: NetworkManager
binds its probe socket to the device with SO_BINDTODEVICE, while REDIRECT
rewrites the destination to 127.0.0.1 — a loopback delivery the forced oif can
never make, so every probe times out and the desktop reports no internet.
Pointing NetworkManager at a different probe URL changes nothing; the socket is
what fails. Tunly turns the check off for as long as the tunnel is up.

The property is runtime state, not config, so nothing is written to /etc and a
restore Tunly never got to make heals on the next NetworkManager restart.

No side effects: every function returns argv for the caller to run, so the
whole thing is unit-testable without root or a bus.
"""

GDBUS = "gdbus"
BUS_NAME = "org.freedesktop.NetworkManager"
OBJ_PATH = "/org/freedesktop/NetworkManager"
IFACE = "org.freedesktop.NetworkManager"
PROP = "ConnectivityCheckEnabled"
PROPERTIES = "org.freedesktop.DBus.Properties"

# A wedged NetworkManager must never hold up teardown.
TIMEOUT = ["--timeout", "5"]


def _call(method, *args):
    return [GDBUS, "call", "--system", *TIMEOUT, "--dest", BUS_NAME,
            "--object-path", OBJ_PATH, "--method", f"{PROPERTIES}.{method}",
            IFACE, PROP, *args]


def get_cmd():
    return _call("Get")


def set_cmd(enabled):
    return _call("Set", f"<{'true' if enabled else 'false'}>")


def parse(stdout):
    """gdbus prints the reply as GVariant text, a variant inside a tuple."""
    if "<true>" in stdout:
        return True
    if "<false>" in stdout:
        return False
    raise ValueError(f"unreadable connectivity-check reply: {stdout.strip()!r}")
