import subprocess


def rule_exists(ip=None, port=None, allow=True):
    args = ["sudo", "iptables", "-C", "INPUT"]
    if ip:
        args.extend(["-s", ip])
    if port:
        args.extend(["-p", "tcp", "--dport", str(port)])
    if allow:
        args.extend(["-j", "ACCEPT"])
    else:
        args.extend(["-j", "DROP"])

    result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def allow_traffic_from_ip(ip):
    if rule_exists(ip=ip):
        return

    subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def allow_traffic_on_port(port):
    if rule_exists(port=port):
        return

    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-j",
            "ACCEPT",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def allow_traffic_from_ip_and_port(ip, port):
    if rule_exists(ip=ip, port=port):
        return

    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-j",
            "ACCEPT",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def deny_traffic_from_ip(ip):
    if rule_exists(ip=ip, allow=False):
        return

    subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def deny_traffic_on_port(port):
    if rule_exists(port=port, allow=False):
        return

    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-j",
            "DROP",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def deny_traffic_from_ip_and_port(ip, port):
    if rule_exists(ip=ip, port=port, allow=False):
        return

    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-j",
            "DROP",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def remove_deny_traffic_from_ip_and_port(ip, port):
    if not rule_exists(ip=ip, port=port, allow=False):
        return

    subprocess.run(
        [
            "sudo",
            "iptables",
            "-D",
            "INPUT",
            "-s",
            ip,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-j",
            "DROP",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
