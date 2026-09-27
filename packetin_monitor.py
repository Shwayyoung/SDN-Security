#!/usr/bin/env python3

import argparse
import threading
import time
import subprocess

from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, Raw


OFPT_PACKET_IN = 10

CONTROLLER_IP = "10.0.2.15"
CONTROLLER_PORT = 6653

packetin_counts = defaultdict(int)
packetin_history = defaultdict(deque)
last_alert_time = defaultdict(float)

# Sources that have already been blocked
blocked_sources = set()

lock = threading.Lock()


def block_attacker(source_ip, source_port):
    """
    Add an iptables rule blocking the attacker's
    source IP:port from reaching Floodlight.
    """

    key = (source_ip, source_port)

    if key in blocked_sources:
        return

    rule = [
        "iptables",
        "-I", "INPUT",
        "-p", "tcp",
        "-s", source_ip,
        "--sport", str(source_port),
        "-d", CONTROLLER_IP,
        "--dport", str(CONTROLLER_PORT),
        "-j", "DROP"
    ]

    check_rule = [
        "iptables",
        "-C", "INPUT",
        "-p", "tcp",
        "-s", source_ip,
        "--sport", str(source_port),
        "-d", CONTROLLER_IP,
        "--dport", str(CONTROLLER_PORT),
        "-j", "DROP"
    ]

    try:
        # Check whether the rule already exists
        result = subprocess.run(
            check_rule,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if result.returncode == 0:
            blocked_sources.add(key)
            return

        # Add the blocking rule
        subprocess.run(
            rule,
            check=True
        )

        blocked_sources.add(key)

        print()
        print("=" * 60)
        print("MITIGATION APPLIED")
        print(
            f"Blocked source : "
            f"{source_ip}:{source_port}"
        )
        print(
            f"Destination    : "
            f"{CONTROLLER_IP}:{CONTROLLER_PORT}"
        )
        print("Action         : DROP")
        print("=" * 60)
        print()

    except subprocess.CalledProcessError as e:
        print()
        print("[ERROR] Failed to add iptables rule")
        print(e)


def process_packet(pkt):

    if IP not in pkt or TCP not in pkt or Raw not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    if ip.dst != CONTROLLER_IP:
        return

    if tcp.dport != CONTROLLER_PORT:
        return

    payload = bytes(pkt[Raw].load)

    offset = 0

    while offset + 8 <= len(payload):

        msg_type = payload[offset + 1]

        msg_length = int.from_bytes(
            payload[offset + 2:offset + 4],
            byteorder="big"
        )

        if msg_length < 8:
            break

        if offset + msg_length > len(payload):
            break

        if msg_type == OFPT_PACKET_IN:

            key = (ip.src, tcp.sport)
            now = time.time()

            with lock:
                packetin_counts[key] += 1
                packetin_history[key].append(now)

        offset += msg_length


def detect_attacks(window, threshold, cooldown):

    while True:

        time.sleep(1)

        now = time.time()

        attackers_to_block = []

        with lock:

            for key, timestamps in packetin_history.items():

                cutoff = now - window

                while timestamps and timestamps[0] < cutoff:
                    timestamps.popleft()

                recent_count = len(timestamps)

                if recent_count >= threshold:

                    if now - last_alert_time[key] >= cooldown:

                        ip, port = key

                        rate = recent_count / window

                        print()
                        print("!" * 60)
                        print("!!! PACKETIN FLOOD ALERT !!!")
                        print(
                            f"Attacking source : "
                            f"{ip}:{port}"
                        )
                        print(
                            f"PacketIn count    : "
                            f"{recent_count}"
                        )
                        print(
                            f"Time window       : "
                            f"{window:.1f} seconds"
                        )
                        print(
                            f"Average rate      : "
                            f"{rate:.1f} PacketIn/sec"
                        )
                        print(
                            f"Threshold         : "
                            f"{threshold}"
                        )
                        print("!" * 60)

                        last_alert_time[key] = now

                        if key not in blocked_sources:
                            attackers_to_block.append(key)

        # Run iptables outside of lock
        for ip, port in attackers_to_block:
            block_attacker(ip, port)


def print_counts(interval, window):

    while True:

        time.sleep(interval)

        now = time.time()

        with lock:

            print("\n========== PacketIn Monitor ==========")

            print(
                f"{'Source IP':<18}"
                f"{'Port':<10}"
                f"{'Total':<10}"
                f"{'Recent':<10}"
                f"{'Blocked':<10}"
            )

            print("-" * 58)

            if not packetin_counts:
                print("No PacketIn messages observed yet.")

            for key, total in sorted(
                packetin_counts.items()
            ):

                ip, port = key

                timestamps = packetin_history[key]

                cutoff = now - window

                recent = sum(
                    1
                    for timestamp in timestamps
                    if timestamp >= cutoff
                )

                blocked = (
                    "YES"
                    if key in blocked_sources
                    else "NO"
                )

                print(
                    f"{ip:<18}"
                    f"{port:<10}"
                    f"{total:<10}"
                    f"{recent:<10}"
                    f"{blocked:<10}"
                )

            print("======================================\n")


def main():

    parser = argparse.ArgumentParser(
        description=(
            "OpenFlow PacketIn monitor "
            "with automatic mitigation"
        )
    )

    parser.add_argument(
        "-i",
        "--interface",
        default="any"
    )

    parser.add_argument(
        "-t",
        "--interval",
        type=float,
        default=5.0
    )

    parser.add_argument(
        "--window",
        type=float,
        default=10.0
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=100
    )

    parser.add_argument(
        "--cooldown",
        type=float,
        default=10.0
    )

    args = parser.parse_args()

    print("OpenFlow PacketIn Monitor + Mitigation")
    print(
        f"Controller : "
        f"{CONTROLLER_IP}:{CONTROLLER_PORT}"
    )
    print(f"Window     : {args.window} sec")
    print(f"Threshold  : {args.threshold}")
    print()

    printer = threading.Thread(
        target=print_counts,
        args=(args.interval, args.window),
        daemon=True
    )

    detector = threading.Thread(
        target=detect_attacks,
        args=(
            args.window,
            args.threshold,
            args.cooldown
        ),
        daemon=True
    )

    printer.start()
    detector.start()

    sniff(
        iface=args.interface,
        filter=(
            f"tcp and dst host {CONTROLLER_IP} "
            f"and dst port {CONTROLLER_PORT}"
        ),
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()