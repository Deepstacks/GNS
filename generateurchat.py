import ipaddress

# =========================================================
# OUTILS
# =========================================================

def mask_to_dotted(mask):
    """Convertit un /XX en masque décimal pointé"""
    mask = int(mask)
    bits = (0xffffffff >> (32 - mask)) << (32 - mask)
    return ".".join(str((bits >> i) & 0xff) for i in [24, 16, 8, 0])

def wildcard_from_prefixlen(prefixlen: int) -> str:
    """Ex: /30 -> 0.0.0.3"""
    host_bits = 32 - int(prefixlen)
    wildcard_int = (1 << host_bits) - 1 if host_bits > 0 else 0
    return ".".join(str((wildcard_int >> i) & 0xff) for i in [24, 16, 8, 0])

def network_from_ip_prefix(ip_cidr: str):
    """Retourne (network_address, prefixlen) à partir de '10.0.0.9/30'."""
    net = ipaddress.ip_interface(ip_cidr).network
    return str(net.network_address), int(net.prefixlen)

def classful_major_network(ip: str) -> str:
    """
    Pour RIP: IOS active RIP par 'network' classful.
    - A: 1-126 -> x.0.0.0
    - B: 128-191 -> x.y.0.0
    - C: 192-223 -> x.y.z.0
    """
    o = [int(x) for x in ip.split(".")]
    first = o[0]
    if 1 <= first <= 126:
        return f"{o[0]}.0.0.0"
    elif 128 <= first <= 191:
        return f"{o[0]}.{o[1]}.0.0"
    elif 192 <= first <= 223:
        return f"{o[0]}.{o[1]}.{o[2]}.0"
    # fallback
    return f"{o[0]}.0.0.0"

def find_link_peer_ip(local_router: str, remote_router: str, intent: dict):
    """
    Cherche dans intent['links'] un lien entre local_router et remote_router
    et renvoie l'IP (sans /mask) du remote_router sur ce lien.
    """
    for link in intent.get("links", []):
        eps = link.get("endpoints", [])
        devs = {ep.get("device") for ep in eps}
        if local_router in devs and remote_router in devs:
            for ep in eps:
                if ep.get("device") == remote_router:
                    return ep["ip"].split("/")[0]
    return None


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
    igp = as_data["igp"]["protocol"].upper()

    if igp == "RIP":
        # RIP v2: IOS attend des "network" classful (souvent 10.0.0.0)
        config = """router rip
 version 2
 no auto-summary
"""
        majors = set()
        for iface in interfaces:
            majors.add(classful_major_network(iface["ip"]))
        for net in sorted(majors):
            config += f" network {net}\n"
        return config + "!\n"

    if igp == "OSPF":
        process_id = as_data["igp"]["process_id"]
        area = as_data["igp"]["area"]
        config = f"""router ospf {process_id}
 router-id {router_id}
"""
        # OSPF: network <network> <wildcard> area <area>
        # On calcule network + wildcard depuis chaque IP/prefix
        for iface in interfaces:
            # Ici, interfaces a déjà ip + mask dotted. On a besoin du prefixlen -> on ne l'a plus.
            # Donc on reconstruit un prefixlen à partir du masque dotted.
            # (Alternative plus propre: conserver le /XX dans interfaces.)
            mask = iface["mask"]
            prefixlen = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            # calculer le network
            net = ipaddress.IPv4Interface(f"{iface['ip']}/{prefixlen}").network
            wildcard = wildcard_from_prefixlen(prefixlen)
            config += f" network {net.network_address} {wildcard} area {area}\n"

        return config + "!\n"

    return ""


# =========================================================
# BGP POLICIES (PARTIE 3.4) : communities + local-pref + propagation
# =========================================================

def configurer_bgp_policies(intent):
    """
    Génère:
    - community-lists pour les rôles (CUSTOMER/PEER/PROVIDER)
    - route-maps IN (tag community + local-pref)
    - community-lists TO_<ROLE> basées sur propagation_policy
    - route-maps OUT-TO-<ROLE> qui filtrent selon propagation_policy
    """
    bgp = intent["bgp"]
    communities = bgp["communities"]
    local_pref = bgp["local_preference"]
    policy = bgp.get("propagation_policy", {})

    cfg = ""

    # 1) Community-lists pour identifier le rôle du voisin (en inbound tagging)
    # (On s'en sert aussi en outbound filtering)
    for role, comm in communities.items():
        cfg += f"ip community-list standard {role.upper()} permit {comm}\n"
    cfg += "\n"

    # 2) Route-maps IN: tag + local-pref selon relationship
    for role, comm in communities.items():
        lp = local_pref[role]
        cfg += f"""route-map RM-IN-{role.upper()} permit 10
 set community {comm} additive
 set local-preference {lp}
!
"""

    # 3) OUT filtering basé sur propagation_policy:
    # policy keys : to_customer / to_peer / to_provider
    # valeurs: liste des rôles autorisés à être propagés
    # On crée TO_CUSTOMER / TO_PEER / TO_PROVIDER comme community-list.
    for to_key, allowed_roles in policy.items():
        # to_key = "to_customer" -> listname = "TO_CUSTOMER"
        target = to_key.replace("to_", "").upper()
        listname = f"TO_{target}"
        for r in allowed_roles:
            cfg += f"ip community-list standard {listname} permit {communities[r]}\n"
        cfg += "\n"

        cfg += f"""route-map RM-OUT-TO-{target} permit 10
 match community {listname}
route-map RM-OUT-TO-{target} deny 20
!
"""

    return cfg


def configurer_bgp(asn, router_id, ibgp_neighbors, ebgp_neighbors, intent):
    if not ibgp_neighbors and not ebgp_neighbors:
        return ""

    cfg = configurer_bgp_policies(intent)

    cfg += f"""router bgp {asn}
 bgp router-id {router_id}
 bgp log-neighbor-changes
"""

    # iBGP full-mesh (loopbacks)
    for neighbor in ibgp_neighbors:
        cfg += f""" neighbor {neighbor} remote-as {asn}
 neighbor {neighbor} update-source Loopback0
 neighbor {neighbor} next-hop-self
 neighbor {neighbor} send-community
"""

    # eBGP (IP de lien) + policies IN/OUT
    for n in ebgp_neighbors:
        role = n["relationship"]  # customer/peer/provider
        peer_ip = n["ip"]
        cfg += f""" neighbor {peer_ip} remote-as {n['remote_as']}
 neighbor {peer_ip} send-community
 neighbor {peer_ip} route-map RM-IN-{role.upper()} in
"""

        # OUT : appliquer propagation_policy selon la relation du voisin
        # - vers un customer: RM-OUT-TO-CUSTOMER
        # - vers un peer:     RM-OUT-TO-PEER
        # - vers un provider: RM-OUT-TO-PROVIDER
        cfg += f" neighbor {peer_ip} route-map RM-OUT-TO-{role.upper()} out\n"

    return cfg + "!\n"


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
    for link in intent.get("links", []):
        for ep in link.get("endpoints", []):
            if ep.get("device") == router_name:
                ip, mask = ep["ip"].split("/")
                interfaces.append({
                    "name": ep["interface"],
                    "ip": ip,
                    "mask": mask_to_dotted(mask)
                })
    return interfaces


# =========================================================
# ASSEMBLER CONFIGURATION COMPLÈTE
# =========================================================

def assembler_configuration(router_name, intent):
    as_data = get_router_as(router_name, intent)
    router_id = get_router_loopback(router_name, intent)
    interfaces = get_router_interfaces(router_name, intent)

    # iBGP neighbors: loopbacks des routeurs du même AS (full-mesh)
    ibgp_neighbors = []
    ibgp_cfg = as_data.get("ibgp", {})
    if ibgp_cfg.get("type") == "full-mesh":
        for r in as_data["routers"]:
            if r["name"] != router_name:
                ibgp_neighbors.append(get_router_loopback(r["name"], intent))

    # eBGP neighbors: on récupère l'IP de lien du routeur distant via intent['links']
    ebgp_neighbors = []
    for peer in intent.get("bgp", {}).get("ebgp_peers", []):
        if peer["local_router"] == router_name:
            remote_router = peer["remote_router"]
            remote_ip = find_link_peer_ip(router_name, remote_router, intent)
            if remote_ip is None:
                raise ValueError(
                    f"Impossible de trouver le lien entre {router_name} et {remote_router} dans 'links'."
                )
            ebgp_neighbors.append({
                "ip": remote_ip,
                "remote_as": peer["remote_as"],
                "relationship": peer["relationship"]
            })

    cfg = ""
    cfg += creer_entete(router_name)
    cfg += configurer_loopback(router_id)
    cfg += configurer_interfaces(interfaces)
    cfg += configurer_igp(as_data, interfaces, router_id)
    cfg += configurer_bgp(as_data["asn"], router_id, ibgp_neighbors, ebgp_neighbors, intent)
    return cfg
