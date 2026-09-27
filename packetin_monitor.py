#!/usr/bin/env python3

import argparse
import threading
import time
from collections import defaultdict

from scapy.all import sniff, IP, TCP, Raw


# OpenFlow message type
OFPT_PACKET_IN = 10

packetin_counts = defaultdict(int)
lock = threading.Lock()


def process_packet(pkt):
    """
    Process TCP packets sent by OpenFlow switches to Floodlight.
    """

    if IP not in pkt or TCP not in pkt or Raw not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    # Only traffic going TO Floodlight OpenFlow port
    if tcp.dport != 6653:
        return

    payload = bytes(pkt[Raw].load)

    offset = 0

    # One TCP packet may contain multiple OpenFlow messages
    while offset + 8 <= len(payload):

        # OpenFlow header:
        # byte 0     version
        # byte 1     type
        # byte 2-3   length
        # byte 4-7   transaction ID

        version = payload[offset]
        msg_type = payload[offset + 1]
        msg_length = int.from_bytes(
            payload[offset + 2:offset + 4],
            byteorder="big"
        )

        # Invalid OpenFlow message length
        if msg_length < 8:
            break

        # Message extends beyond this TCP payload
        if offset + msg_length > len(payload):
            break

        if msg_type == OFPT_PACKET_IN:

            switch_ip = ip.src
            switch_port = tcp.sport

            key = (switch_ip, switch_port)

            with lock:
                packetin_counts[key] += 1

        offset += msg_length


def print_counts(interval):
    """
    Periodically print PacketIn statistics.
    """

    while True:

        time.sleep(interval)

        with lock:

            print("\n========== PacketIn Monitor ==========")
            print(
                f"{'Switch IP':<18}"
                f"{'TCP Port':<12}"
                f"{'PacketIn Count':<15}"
            )

            print("-" * 45)

            if not packetin_counts:
                print("No PacketIn messages observed yet.")

            for (ip, port), count in sorted(packetin_counts.items()):
                print(
                    f"{ip:<18}"
                    f"{port:<12}"
                    f"{count:<15}"
                )

            print("======================================\n")


def main():

    parser = argparse.ArgumentParser(
        description="Monitor OpenFlow PacketIn messages"
    )

    parser.add_argument(
        "-i",
        "--interface",
        default="any",
        help="Interface to sniff on (default: any)"
    )

    parser.add_argument(
        "-t",
        "--interval",
        type=float,
        default=5.0,
        help="Display refresh interval in seconds (default: 5)"
    )

    args = parser.parse_args()

    print("OpenFlow PacketIn Monitor")
    print("Controller: 10.0.2.15:6653")
    print(f"Interface : {args.interface}")
    print(f"Interval  : {args.interval} seconds")
    print()
    print("Waiting for PacketIn messages...")
    print("Press Ctrl+C to stop.")

    printer = threading.Thread(
        target=print_counts,
        args=(args.interval,),
        daemon=True
    )

    printer.start()

    sniff(
        iface=args.interface,
        filter="tcp dst port 6653",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()