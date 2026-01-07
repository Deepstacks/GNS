import json

# =========================================================
# OUTILS
# =========================================================

def mask_to_dotted(mask):
    """Convertit un /XX en masque décimal pointé"""
    mask = int(mask)
    bits = (0xffffffff >> (32 - mask)) << (32 - mask)
    return ".".join(str((bits >> i) & 0xff) for i in [24, 16, 8, 0])


# =========================================================
# BLOCS DE CONFIGURATION DE BASE
# =========================================================

def creer_entete(hostname):
    return f"""!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
hostname {hostname}
!
"""


def configurer_loopback(loopback_ip):
    return f"""interface Loopback0
 ip address {loopback_ip} 255.255.255.255
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


# =========================================================
# IGP
# =========================================================

def configurer_igp(as_data, interfaces, router_id):
    igp = as_data["igp"]["protocol"]

    if igp == "RIP":
        config = """router rip
 version 2
 no auto-summary
"""
        for iface in interfaces:
            config += f" network {iface['ip']}\n"
        return config + "!\n"

    elif igp == "OSPF":
        process_id = as_data["igp"]["process_id"]
        area = as_data["igp"]["area"]
        config = f"""router ospf {process_id}
 router-id {router_id}
"""
        for iface in interfaces:
            config += f" network {iface['ip']} 0.0.0.0 area {area}\n"
        return config + "!\n"

    return ""


# =========================================================
# BGP POLICIES (DEPUIS L’INTENT FILE)
# =========================================================

def configurer_bgp_policies(intent):
    bgp = intent["bgp"]
    config = ""

    # Community-list CUSTOMER
    customer_community = bgp["communities"]["customer"]
    config += f"ip community-list standard CUSTOMER permit {customer_community}\n\n"

    # Route-maps IN (tag + local-pref)
    for role, community in bgp["communities"].items():
        local_pref = bgp["local_preference"][role]
        config += f"""route-map RM-IN-{role.upper()} permit 10
 set community {community} additive
 set local-preference {local_pref}
!
"""

    # Route-map OUT (customer-only)
    config += """route-map RM-OUT-CUSTOMER-ONLY permit 10
 match community CUSTOMER
route-map RM-OUT-CUSTOMER-ONLY deny 20
!
"""
    return config


def configurer_bgp(asn, router_id, ibgp_neighbors, ebgp_neighbors, intent):
    if not ibgp_neighbors and not ebgp_neighbors:
        return ""

    config = configurer_bgp_policies(intent)

    config += f"""router bgp {asn}
 bgp router-id {router_id}
 bgp log-neighbor-changes
"""

    # iBGP
    for neighbor in ibgp_neighbors:
        config += f""" neighbor {neighbor} remote-as {asn}
 neighbor {neighbor} update-source Loopback0
 neighbor {neighbor} next-hop-self
 neighbor {neighbor} send-community
"""

    # eBGP
    for neighbor in ebgp_neighbors:
        role = neighbor["relationship"]
        config += f""" neighbor {neighbor['ip']} remote-as {neighbor['remote_as']}
 neighbor {neighbor['ip']} route-map RM-IN-{role.upper()} in
"""
        if role in ["peer", "provider"]:
            config += f" neighbor {neighbor['ip']} route-map RM-OUT-CUSTOMER-ONLY out\n"

    return config + "!\n"


# =========================================================
# LOGIQUE INTENT
# =========================================================

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


# =========================================================
# NOUVELLE FONCTION : ASSEMBLER CONFIGURATION COMPLÈTE
# =========================================================

def assembler_configuration(router_name, intent):
    """
    Génère la configuration complète pour un routeur :
    - entête
    - loopback
    - interfaces
    - IGP
    - BGP (iBGP + eBGP + policies)
    """
    as_data = get_router_as(router_name, intent)
    router_id = get_router_loopback(router_name, intent)
    interfaces = get_router_interfaces(router_name, intent)

    # iBGP neighbors
    ibgp_neighbors = []
    for r in as_data["routers"]:
        if r["name"] != router_name:
            ibgp_neighbors.append(get_router_loopback(r["name"], intent))

    # eBGP neighbors
    ebgp_neighbors = []
    for peer in intent["bgp"]["ebgp_peers"]:
        if peer["local_router"] == router_name:
            ebgp_neighbors.append({
                "ip": get_router_loopback(peer["remote_router"], intent),
                "remote_as": peer["remote_as"],
                "relationship": peer["relationship"]
            })

    # Génération de la configuration complète
    config = ""
    config += creer_entete(router_name)
    config += configurer_loopback(router_id)
    config += configurer_interfaces(interfaces)
    config += configurer_igp(as_data, interfaces, router_id)
    config += configurer_bgp(as_data["asn"], router_id, ibgp_neighbors, ebgp_neighbors, intent)

    return config
