"""Pure iptables rule generation for Tunly's transparent mode.

No side effects: every function returns argv lists for the caller to run. That
keeps the whole ruleset unit-testable without root.
"""

import ipaddress

IPTABLES = "iptables"
IP6TABLES = "ip6tables"

# Without -w, iptables aborts the moment another process holds the xtables
# lock. Docker rewrites its rules constantly, so an unguarded call fails at
# random — and a teardown that fails this way strands chains behind.
LOCK_WAIT = ["-w", "5"]


def cmd(binary, table, *args):
    return [binary, *LOCK_WAIT, *(["-t", table] if table else []), *args]

NAT_CHAIN = "TUNLY"
GUARD_CHAIN = "TUNLY_GUARD"
GUARD6_CHAIN = "TUNLY_GUARD6"

# RETURNed so LAN, docker0, br-*, lxcbr0 and virbr0 keep working untouched.
PRIVATE_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
)
LOCAL_V6 = ("::1/128", "fe80::/10", "fc00::/7", "ff00::/8")


class RuleError(ValueError):
    """Rejected parameter — raised before anything is handed to iptables."""


def validate(ssh_ip, ssh_port, redir_port, dns_port):
    """Validate helper input. netguard runs as root against an unprivileged
    caller, so nothing reaches iptables unchecked."""
    try:
        addr = ipaddress.IPv4Address(ssh_ip)
    except ipaddress.AddressValueError as e:
        raise RuleError(f"ssh_ip is not an IPv4 address: {ssh_ip!r}") from e
    ports = {"ssh_port": ssh_port, "redir_port": redir_port, "dns_port": dns_port}
    for label, p in ports.items():
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            raise RuleError(f"{label} must be an int in 1..65535, got {p!r}")
    if len({redir_port, dns_port}) != 2:
        raise RuleError("redir_port and dns_port must differ")
    return str(addr), ssh_port, redir_port, dns_port


def up_commands(ssh_ip, ssh_port, redir_port, dns_port):
    """Rules that install transparent routing. Order is load-bearing.

    The kill switch goes in FIRST, before the redirect. Building the redirect
    first leaves a window where traffic is neither blocked nor captured, and it
    escapes over the real IP — measured at 5-10s on a real machine, which is a
    leak, not a hiccup. Guard-first turns that window into a brief block.
    """
    ssh_ip, ssh_port, redir_port, dns_port = validate(
        ssh_ip, ssh_port, redir_port, dns_port)
    cmds = []

    # --- filter/TUNLY_GUARD: fail-closed, and installed FIRST. Redirected
    # packets carry a loopback destination by the time they reach here, so this
    # only ever sees what escaped the redirect. ---
    cmds.append(cmd(IPTABLES, None, "-N", GUARD_CHAIN))
    guard = lambda *a: cmds.append(cmd(IPTABLES, None, "-A", GUARD_CHAIN, *a))
    guard("-o", "lo", "-j", "RETURN")
    # Above the private RETURNs: ICMP is blocked outright, LAN included. It
    # cannot traverse a SOCKS TCP tunnel, so anything that escapes here would
    # carry the real source address.
    guard("-p", "icmp", "-j", "REJECT", "--reject-with", "icmp-admin-prohibited")
    guard("-d", ssh_ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "RETURN")
    for net in PRIVATE_V4:
        guard("-d", net, "-j", "RETURN")
    # REJECT not DROP: QUIC falls back to TCP in ms instead of stalling.
    guard("-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
    guard("-j", "REJECT", "--reject-with", "icmp-admin-prohibited")
    cmds.append(cmd(IPTABLES, None, "-A", "OUTPUT", "-j", GUARD_CHAIN))

    # --- filter/TUNLY_GUARD6: v4-only rules would leave v6 wide open. ---
    cmds.append(cmd(IP6TABLES, None, "-N", GUARD6_CHAIN))
    guard6 = lambda *a: cmds.append(cmd(IP6TABLES, None, "-A", GUARD6_CHAIN, *a))
    guard6("-o", "lo", "-j", "RETURN")
    for net in LOCAL_V6:
        guard6("-d", net, "-j", "RETURN")
    guard6("-j", "REJECT", "--reject-with", "adm-prohibited")
    cmds.append(cmd(IP6TABLES, None, "-A", "OUTPUT", "-j", GUARD6_CHAIN))

    # --- nat/TUNLY: bend outbound TCP (and DNS) into the local listeners.
    # Last, so nothing is ever merely-unguarded. ---
    cmds.append(cmd(IPTABLES, "nat", "-N", NAT_CHAIN))
    nat = lambda *a: cmds.append(cmd(IPTABLES, "nat", "-A", NAT_CHAIN, *a))
    nat("-o", "lo", "-j", "RETURN")
    # Above the private RETURNs on purpose: resolved forwards upstream to a
    # private resolver, and that leg is the actual DNS leak.
    nat("-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(dns_port))
    nat("-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(dns_port))
    # The carrier itself, or the redirect eats its own tunnel.
    nat("-d", ssh_ip, "-p", "tcp", "--dport", str(ssh_port), "-j", "RETURN")
    for net in PRIVATE_V4:
        nat("-d", net, "-j", "RETURN")
    nat("-p", "tcp", "-j", "REDIRECT", "--to-ports", str(redir_port))
    # Unqualified jump: the chain must see UDP/53 too.
    cmds.append(cmd(IPTABLES, "nat", "-A", "OUTPUT", "-j", NAT_CHAIN))
    return cmds


# Existing sockets keep flowing direct via their conntrack entries, so apps
# opened before the rules went in stay unprotected. Dropping the entries forces
# them to re-establish through the tunnel. The ssh carrier survives: it is
# nat-exempt, and nf_conntrack_tcp_loose lets its stream be picked up mid-flight.
CONNTRACK_FLUSH = ["conntrack", "-D", "-p", "tcp"]


def _drop_chain(binary, table, parent, chain):
    """Probe/delete the jump, then flush and drop the chain itself."""
    return {
        "probe": cmd(binary, table, "-C", parent, "-j", chain),
        "delete": cmd(binary, table, "-D", parent, "-j", chain),
        "flush": cmd(binary, table, "-F", chain),
        "drop": cmd(binary, table, "-X", chain),
        "exists": cmd(binary, table, "-S", chain),
        "label": f"{binary}{'/' + table if table else ''}:{chain}",
    }


def teardown_plan():
    """Chains to unhook, in order. Every step is idempotent; running this on a
    clean system is a no-op."""
    return [
        _drop_chain(IPTABLES, "nat", "OUTPUT", NAT_CHAIN),
        _drop_chain(IPTABLES, None, "OUTPUT", GUARD_CHAIN),
        _drop_chain(IP6TABLES, None, "OUTPUT", GUARD6_CHAIN),
    ]


def check_plan():
    """Probes that confirm every chain is still installed and jumped."""
    return [step["probe"] for step in teardown_plan()]
