from flask import Flask, render_template, request
import requests
import uuid

app = Flask(__name__)

FLOODLIGHT_STATIC_FLOW_URL = (
    "http://10.0.2.15:8080/wm/staticflowpusher/json"
)

FLOODLIGHT_LIST_URL = (
    "http://10.0.2.15:8080/wm/staticflowpusher/list/all/json"
)

FULL_CONNECTIVITY_FLOWS = [
    # s1
    {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "s1-arp-flood",
        "priority": "100",
        "eth_type": "0x0806",
        "active": "true",
        "actions": "output=flood"
    },
    {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "s1-to-h1s1",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.1/32",
        "active": "true",
        "actions": "output=1"
    },
    {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "s1-to-h2s1",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.3/32",
        "active": "true",
        "actions": "output=2"
    },
    {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "s1-to-h1s2",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.2/32",
        "active": "true",
        "actions": "output=3"
    },
    {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "s1-to-h2s2",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.4/32",
        "active": "true",
        "actions": "output=3"
    },

    # s2
    {
        "switch": "00:00:00:00:00:00:00:02",
        "name": "s2-arp-flood",
        "priority": "100",
        "eth_type": "0x0806",
        "active": "true",
        "actions": "output=flood"
    },
    {
        "switch": "00:00:00:00:00:00:00:02",
        "name": "s2-to-h1s2",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.2/32",
        "active": "true",
        "actions": "output=1"
    },
    {
        "switch": "00:00:00:00:00:00:00:02",
        "name": "s2-to-h2s2",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.4/32",
        "active": "true",
        "actions": "output=2"
    },
    {
        "switch": "00:00:00:00:00:00:00:02",
        "name": "s2-to-h1s1",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.1/32",
        "active": "true",
        "actions": "output=3"
    },
    {
        "switch": "00:00:00:00:00:00:00:02",
        "name": "s2-to-h2s1",
        "priority": "200",
        "eth_type": "0x0800",
        "ipv4_dst": "10.0.0.3/32",
        "active": "true",
        "actions": "output=3"
    }
]

S1 = "00:00:00:00:00:00:00:01"
S2 = "00:00:00:00:00:00:00:02"

HOST_SWITCH = {
    "10.0.0.1": S1,
    "10.0.0.3": S1,
    "10.0.0.2": S2,
    "10.0.0.4": S2
}

PORT_MAP = {
    S1: {
        "10.0.0.1": "1",
        "10.0.0.3": "2",
        "10.0.0.2": "3",
        "10.0.0.4": "3"
    },
    S2: {
        "10.0.0.2": "1",
        "10.0.0.4": "2",
        "10.0.0.1": "3",
        "10.0.0.3": "3"
    }
}

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/routing", methods=["GET", "POST"])
def routing():

    message = None
    success = False

    if request.method == "POST":

        dpid = request.form.get("dpid")
        priority = request.form.get("priority")
        in_port = request.form.get("in_port")
        eth_type = request.form.get("eth_type")
        dst_ip = request.form.get("dst_ip")

        action_type = request.form.get("action_type")
        output_port = request.form.get("output_port")

        # Build action
        if action_type == "flood":
            actions = "output=flood"
        else:
            actions = f"output={output_port}"

        # Generate unique rule name
        flow_name = f"web-routing-{uuid.uuid4().hex[:8]}"

        flow = {
            "switch": dpid,
            "name": flow_name,
            "priority": priority,
            "active": "true",
            "actions": actions
        }

        # Optional match fields
        if in_port:
            flow["in_port"] = in_port

        if eth_type:
            flow["eth_type"] = eth_type

        if dst_ip:
            flow["ipv4_dst"] = dst_ip

        try:
            response = requests.post(
                FLOODLIGHT_STATIC_FLOW_URL,
                json=flow,
                timeout=5
            )

            if response.ok:
                success = True
                message = (
                    f"Flow {flow_name} added successfully."
                )
            else:
                message = (
                    f"Floodlight returned HTTP "
                    f"{response.status_code}: "
                    f"{response.text}"
                )

        except requests.RequestException as e:
            message = f"Error contacting Floodlight: {e}"

    flows = get_static_flows()

    return render_template(
        "routing.html",
        message=message,
        success=success,
        flows=flows
    )

@app.route("/routing/install-full", methods=["POST"])
def install_full_connectivity():

    try:
        for flow in FULL_CONNECTIVITY_FLOWS:

            response = requests.post(
                FLOODLIGHT_STATIC_FLOW_URL,
                json=flow,
                timeout=5
            )

            if not response.ok:
                return (
                    f"Failed to install {flow['name']}: "
                    f"{response.status_code} "
                    f"{response.text}"
                ), 500

        return render_template(
            "routing.html",
            message="Full connectivity flows installed successfully.",
            success=True,
            flows=get_static_flows()
        )

    except requests.RequestException as e:

        return render_template(
            "routing.html",
            message=f"Error contacting Floodlight: {e}",
            success=False,
            flows=get_static_flows()
        )

def install_default_drop():

    flows = [
        {
            "switch": "00:00:00:00:00:00:00:01",
            "name": "firewall-default-drop-s1",
            "priority": "300",
            "active": "true",
            "actions": ""
        },
        {
            "switch": "00:00:00:00:00:00:00:02",
            "name": "firewall-default-drop-s2",
            "priority": "300",
            "active": "true",
            "actions": ""
        },
        {
            "switch": "00:00:00:00:00:00:00:01",
            "name": "firewall-arp-s1",
            "priority": "350",
            "eth_type": "0x0806",
            "active": "true",
            "actions": "output=flood"
        },
        {
            "switch": "00:00:00:00:00:00:00:02",
            "name": "firewall-arp-s2",
            "priority": "350",
            "eth_type": "0x0806",
            "active": "true",
            "actions": "output=flood"
        }
    ]

    for flow in flows:

        response = requests.post(
            FLOODLIGHT_STATIC_FLOW_URL,
            json=flow,
            timeout=5
        )

        response.raise_for_status()


@app.route("/firewall", methods=["GET", "POST"])
def firewall():

    message = None
    success = False

    try:
        install_default_drop()

    except requests.RequestException as e:
        return render_template(
            "firewall.html",
            message=f"Could not install default DROP: {e}",
            success=False,
            flows=get_static_flows()
        )

    if request.method == "POST":

        dpid = request.form.get("dpid")
        priority = int(request.form.get("priority"))
        in_port = request.form.get("in_port")
        eth_type = request.form.get("eth_type")
        src_ip = request.form.get("src_ip")
        dst_ip = request.form.get("dst_ip")
        protocol = request.form.get("protocol")

        if priority <= 300:
            return render_template(
                "firewall.html",
                message="ALLOW priority must be greater than 300.",
                success=False,
                flows=get_static_flows()
            )

        if src_ip not in HOST_SWITCH or dst_ip not in HOST_SWITCH:
            return render_template(
                "firewall.html",
                message="Unknown source or destination host.",
                success=False,
                flows=get_static_flows()
            )

        # Operator-selected DPID should be the source-side switch
        if dpid != HOST_SWITCH[src_ip]:
            return render_template(
                "firewall.html",
                message=(
                    "Selected DPID does not match the source host's "
                    "ingress switch."
                ),
                success=False,
                flows=get_static_flows()
            )

#May need to move out.
        def make_allow_flow(
            switch,
            name,
            priority,
            eth_type,
            src_ip,
            dst_ip,
            ip_proto,
            in_port=None
        ):
            flow = {
                "switch": switch,
                "name": name,
                "priority": str(priority),
                "eth_type": eth_type,
                "ipv4_src": f"{src_ip}/32",
                "ipv4_dst": f"{dst_ip}/32",
                "ip_proto": ip_proto,
                "active": "true",
                "actions": f"output={PORT_MAP[switch][dst_ip]}"
            }

            if in_port:
                flow["in_port"] = in_port

            return flow

        protocol_numbers = {
            "icmp": "1",
            "tcp": "6",
            "udp": "17"
        }

        ip_proto = protocol_numbers[protocol]

        src_switch = HOST_SWITCH[src_ip]
        dst_switch = HOST_SWITCH[dst_ip]

        uid = uuid.uuid4().hex[:6]

        flows = []

        # Forward direction
        flows.append(
            make_allow_flow(
                src_switch,
                f"fw-{uid}-forward-ingress",
                priority,
                eth_type,
                src_ip,
                dst_ip,
                ip_proto,
                in_port
            )
        )

        # Cross-switch traffic needs a rule on the second switch
        if src_switch != dst_switch:
            flows.append(
                make_allow_flow(
                    dst_switch,
                    f"fw-{uid}-forward-egress",
                    priority,
                    eth_type,
                    src_ip,
                    dst_ip,
                    ip_proto
                )
            )

        # Return direction starts at destination-side switch
        flows.append(
            make_allow_flow(
                dst_switch,
                f"fw-{uid}-return-ingress",
                priority,
                eth_type,
                dst_ip,
                src_ip,
                ip_proto
            )
        )

        if src_switch != dst_switch:
            flows.append(
                make_allow_flow(
                    src_switch,
                    f"fw-{uid}-return-egress",
                    priority,
                    eth_type,
                    dst_ip,
                    src_ip,
                    ip_proto
                )
            )
        try:

            for flow in flows:

                response = requests.post(
                    FLOODLIGHT_STATIC_FLOW_URL,
                    json=flow,
                    timeout=5
                )

                if not response.ok:
                    raise Exception(
                        f"Failed to install {flow['name']}"
                    )

            success = True

            message = (
                f"Firewall rule installed: "
                f"{src_ip} <-> {dst_ip} "
                f"({protocol.upper()})"
            )

        except Exception as e:

            message = str(e)

    flows = get_static_flows()

    return render_template(
        "firewall.html",
        message=message,
        success=success,
        flows=flows
    )

def get_static_flows():
    try:
        response = requests.get(
            FLOODLIGHT_LIST_URL,
            timeout=5
        )

        if response.ok:
            return response.json()

    except requests.RequestException:
        pass

    return {}

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )