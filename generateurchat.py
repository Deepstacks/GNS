import json

# =========================
# BLOCS DE CONFIG
# =========================

def creer_entete(hostname):
    return f"""!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
hostname {hostname}
!
"""


def configurer_loopback(router_id):
    return f"""interface Loopback0
 ip address {router_id} 255.255.255.255
!
"""


def configurer_interfaces(interfaces):
    config = ""
    for iface in interfaces:
        config += f"""interface {iface['name']}
 ip address {iface['ip']} {iface['mask']}
 no shutdown
!
"""
    return config


def configurer_igp(as_data, interfaces, router_id, redistribute=False):
    igp = as_data["igp"]["protocol"]

    if igp == "RIP":
        config = """router rip
 version 2
 no auto-summary
"""
        for iface in interfaces:
            config += f" network {iface['ip']}\n"

        if redistribute:
            config += " redistribute bgp\n"

        return config + "!\n"

    elif igp == "OSPF":
        process_id = as_data["igp"]["process_id"]
        area = as_data["igp"]["area"]

        config = f"""router ospf {process_id}
 router-id {router_id}
"""
        for iface in interfaces:
            config += f" network {iface['ip']} 0.0.0.0 area {area}\n"

        if redistribute:
            config += " redistribute bgp subnets\n"

        return config + "!\n"

    return ""


def configurer_bgp(asn, router_id, ibgp_neighbors, ebgp_neighbors, redistribute=False, bgp_settings=None):
    if not ibgp_neighbors and not ebgp_neighbors:
        return ""

    config = configurer_bgp_policies(bgp_settings)

    config += f"""router bgp {asn}
 bgp router-id {router_id}
 bgp log-neighbor-changes
"""

    # iBGP neighbors
    for neighbor in ibgp_neighbors:
        config += f""" neighbor {neighbor} remote-as {asn}
 neighbor {neighbor} update-source Loopback0
 neighbor {neighbor} next-hop-self
 neighbor {neighbor} send-community
"""

    # eBGP neighbors with policies
    for neighbor in ebgp_neighbors:
        relation = neighbor["relationship"]
        policy = RELATION_POLICY[relation]

        config += f""" neighbor {neighbor['ip']} remote-as {neighbor['remote_as']}
 neighbor {neighbor['ip']} route-map {policy['rm_in']} in
"""

        if policy["rm_out"]:
            config += f" neighbor {neighbor['ip']} route-map {policy['rm_out']} out\n"

    if redistribute:
        config += " redistribute connected\n"

    return config + "!\n"


# Policies mapping for relationships
RELATION_POLICY = {
    "customer": {"rm_in": "SET_LOCALPREF_200", "rm_out": None},
    "peer": {"rm_in": "SET_LOCALPREF_150", "rm_out": None},
    "provider": {"rm_in": "SET_LOCALPREF_50", "rm_out": None}
}


def configurer_bgp_policies(bgp_settings=None):
    """Génère des route-maps simples pour régler local-preference based on relationship or bgp_settings."""
    config = ""
    if bgp_settings and "local_preference" in bgp_settings:
        # Generate route-maps from provided local_preference mapping
        for rel, lp in bgp_settings["local_preference"].items():
            rm_name = f"SET_LOCALPREF_{lp}"
            config += f"""route-map {rm_name} permit 10
 set local-preference {lp}
!
"""
    else:
        # Defaults
        config += """route-map SET_LOCALPREF_200 permit 10
 set local-preference 200
!
route-map SET_LOCALPREF_150 permit 10
 set local-preference 150
!
route-map SET_LOCALPREF_50 permit 10
 set local-preference 50
!
"""
    return config


# =========================
# LOGIQUE INTENT
# =========================

def assembler_configuration(router_name, intent):
    """Assemble la configuration complète pour un routeur donné en s'appuyant sur le fichier d'intent."""
    as_data = get_router_as(router_name, intent)
    if not as_data:
        raise ValueError(f"Router {router_name} not found in intent")

    router_id = get_router_loopback(router_name, intent)
    interfaces = get_router_interfaces(router_name, intent)

    cfg = ""
    cfg += creer_entete(router_name)
    cfg += configurer_loopback(router_id)
    cfg += configurer_interfaces(interfaces)

    # IGP
    redistribute_igp = False
    cfg += configurer_igp(as_data, interfaces, router_id, redistribute=redistribute_igp)

    # BGP
    asn = as_data.get("asn")

    # iBGP neighbors (full-mesh using loopbacks)
    ibgp_neighbors = []
    ibgp = as_data.get("ibgp", {})
    if ibgp.get("type") == "full-mesh":
        for r in as_data.get("routers", []):
            if r["name"] != router_name:
                ibgp_neighbors.append(get_router_loopback(r["name"], intent))

    # eBGP neighbors: scan intent['bgp']['ebgp_peers'] where local_router == router_name
    ebgp_neighbors = []
    for peer in intent.get("bgp", {}).get("ebgp_peers", []):
        if peer.get("local_router") == router_name:
            nbr = {
                "ip": get_router_loopback(peer.get("remote_router"), intent),
                "remote_as": peer.get("remote_as"),
                "relationship": peer.get("relationship")
            }
            ebgp_neighbors.append(nbr)
        elif peer.get("remote_router") == router_name:
            # Peer defined from the other side
            nbr = {
                "ip": get_router_loopback(peer.get("local_router"), intent),
                "remote_as": peer.get("local_as"),
                "relationship": peer.get("relationship")
            }
            ebgp_neighbors.append(nbr)

    cfg += configurer_bgp(asn, router_id, ibgp_neighbors, ebgp_neighbors, redistribute=False, bgp_settings=intent.get("bgp"))

    return cfg

def get_router_as(router_name, intent):
    for as_data in intent["autonomous_systems"]:
        if router_name in [r["name"] for r in as_data["routers"]]:
            return as_data
    return None


def get_router_loopback(router_name, intent):
    for as_data in intent["autonomous_systems"]:
        for r in as_data["routers"]:
            if r["name"] == router_name:
                return r["loopback"].split("/")[0]
    return None


def get_router_interfaces(router_name, intent):
    interfaces = []
    for link in intent["links"]:
        for ep in link["endpoints"]:
            if ep["device"] == router_name:
                ip, mask = ep["ip"].split("/")
                interfaces.append({
                    "name": ep["interface"],
                    "ip": ip,
                    "mask": mask_to_dotted(mask)
                })
    return interfaces

def mask_to_dotted(mask):
    mask = int(mask)
    bits = (0xffffffff >> (32 - mask)) << (32 - mask)
    return ".".join(str((bits >> i) & 0xff) for i in [24,16,8,0])
