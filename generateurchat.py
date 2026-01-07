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


def configurer_bgp(asn, router_id, ibgp_neighbors, ebgp_neighbors, redistribute=False):
    if not ibgp_neighbors and not ebgp_neighbors:
        return ""

    config = f"""router bgp {asn}
 bgp router-id {router_id}
 bgp log-neighbor-changes
"""

    for neighbor in ibgp_neighbors:
        config += f""" neighbor {neighbor} remote-as {asn}
 neighbor {neighbor} update-source Loopback0
 neighbor {neighbor} next-hop-self
"""

    for neighbor in ebgp_neighbors:
        config += f""" neighbor {neighbor['ip']} remote-as {neighbor['remote_as']}
"""

    if redistribute:
        config += " redistribute connected\n"

    return config + "!\n"


# =========================
# LOGIQUE INTENT
# =========================

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
