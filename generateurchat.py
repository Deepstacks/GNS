import ipaddress

# =========================================================
# OUTILS
# =========================================================

def mask_to_dotted(mask):
    """Convertit un /XX en masque décimal pointé"""
    mask = int(mask)
    bits = (0xffffffff >> (32 - mask)) << (32 - mask)
    return ".".join(str((bits >> i) & 0xff) for i in [24, 16, 8, 0])

def dotted_to_prefixlen(mask_dotted: str) -> int:
    """Convertit un masque décimal pointé en prefixlen."""
    return ipaddress.IPv4Network(f"0.0.0.0/{mask_dotted}").prefixlen

def wildcard_from_prefixlen(prefixlen: int) -> str:
    """Ex: /30 -> 0.0.0.3"""
    host_bits = 32 - int(prefixlen)
    wildcard_int = (1 << host_bits) - 1 if host_bits > 0 else 0
    return ".".join(str((wildcard_int >> i) & 0xff) for i in [24, 16, 8, 0])

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

def get_router_asn(router_name: str, intent: dict):
    """Retourne l'ASN du routeur (via l'AS qui le contient)."""
    as_data = get_router_as(router_name, intent)
    return as_data["asn"] if as_data else None

def infer_reverse_relationship(rel: str) -> str:
    """
    Si A voit B comme 'customer', B voit A comme 'provider' (et inversement).
    'peer' reste 'peer'.
    """
    rel = rel.lower()
    if rel == "customer":
        return "provider"
    if rel == "provider":
        return "customer"
    return "peer"

def validate_intent_minimal(intent: dict):
    """
    Vérifications utiles :
    - Tous les routeurs ont au moins 1 interface dans links
    - Chaque ebgp_peers a bien un lien correspondant dans links
    - Les AS ont un champ 'igp' OU bien on tolère les AS terminaux (1 routeur) avec OSPF minimal
    """
    routers = []
    for a in intent.get("autonomous_systems", []):
        routers += [r["name"] for r in a.get("routers", [])]

    seen = {r: 0 for r in routers}
    for link in intent.get("links", []):
        for ep in link.get("endpoints", []):
            dev = ep.get("device")
            if dev in seen:
                seen[dev] += 1

    isolated = [r for r, n in seen.items() if n == 0]
    if isolated:
        raise ValueError(
            "Topo incomplète: ces routeurs n'ont aucune interface dans 'links' : "
            + ", ".join(isolated)
        )

    for p in intent.get("bgp", {}).get("ebgp_peers", []):
        lr = p["local_router"]
        rr = p["remote_router"]
        if find_link_peer_ip(lr, rr, intent) is None:
            raise ValueError(
                f"Topo incomplète: ebgp_peers {lr}->{rr} mais aucun lien {lr}<->{rr} dans 'links'."
            )

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

# Ajout de protocol_igp pour savoir si on applique le coût OSPF
def configurer_interfaces(interfaces, protocol_igp):
    cfg = ""
    for iface in interfaces:
        cfg += f"""interface {iface['name']}
 ip address {iface['ip']} {iface['mask']}
"""
        #  Application de la métrique si présente et si OSPF
        metric = iface.get("ospf_metric")
        if protocol_igp == "OSPF" and metric:
            cfg += f" ip ospf cost {metric}\n"

        cfg += " no shutdown\n!\n"
    return cfg

# =========================================================
# IGP
# =========================================================

def configurer_igp(as_data, interfaces, loopback_ip):
    """
    - RIP  : network classful + redistribute connected (pour loopback)
    - OSPF : annonce toutes les interfaces + loopback /32
    - AS terminaux: si 'igp' absent, on ne met pas d'IGP (OK si 1 routeur)
    """
    igp_data = as_data.get("igp")
    if not igp_data:
        # AS terminal typique (1 routeur) : pas besoin d’IGP
        return ""

    igp = igp_data["protocol"].upper()

    if igp == "RIP":
        cfg = """router rip
 version 2
 no auto-summary
"""
        majors = set()
        for iface in interfaces:
            majors.add(classful_major_network(iface["ip"]))
        for net in sorted(majors):
            cfg += f" network {net}\n"
        cfg += " redistribute connected\n"
        return cfg + "!\n"

    if igp == "OSPF":
        process_id = igp_data["process_id"]
        area = igp_data["area"]
        cfg = f"""router ospf {process_id}
 router-id {loopback_ip}
"""
        for iface in interfaces:
            mask = iface["mask"]
            prefixlen = dotted_to_prefixlen(mask)
            net = ipaddress.IPv4Interface(f"{iface['ip']}/{prefixlen}").network
            wildcard = wildcard_from_prefixlen(prefixlen)
            cfg += f" network {net.network_address} {wildcard} area {area}\n"

        cfg += f" network {loopback_ip} 0.0.0.0 area {area}\n"
        return cfg + "!\n"

    return ""

# =========================================================
# BGP POLICIES (PARTIE 3.4)
# =========================================================

def configurer_bgp_policies(intent):
    bgp = intent["bgp"]
    communities = bgp["communities"]
    local_pref = bgp["local_preference"]
    policy = bgp.get("propagation_policy", {})

    cfg = ""

    # community-lists roles
    for role, comm in communities.items():
        cfg += f"ip community-list standard {role.upper()} permit {comm}\n"
    cfg += "\n"

    # IN policies
    for role, comm in communities.items():
        lp = local_pref[role]
        cfg += f"""route-map RM-IN-{role.upper()} permit 10
 set community {comm} additive
 set local-preference {lp}
!
"""

    # OUT policies from propagation_policy
    for to_key, allowed_roles in policy.items():
        target = to_key.replace("to_", "").upper()  # CUSTOMER/PEER/PROVIDER
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

# =========================================================
# BGP ORIGINATION (FIX PRINCIPAL)
# =========================================================

def collect_bgp_origins(router_name: str, intent: dict, loopback_ip: str) -> list:
    """
    Retourne la liste des préfixes à ORIGINATE en BGP sur CE routeur.
    - Toujours: loopback /32 (pour avoir des routes à propager)
    - Optionnel: intent["bgp"]["origins"][router_name] = ["X.X.X.X/YY", ...]
    """
    origins = [f"{loopback_ip}/32"]

    extra = intent.get("bgp", {}).get("origins", {}).get(router_name, [])
    for cidr in extra:
        origins.append(cidr)

    # dédup
    return sorted(set(origins))

def render_bgp_network_statements(origins: list) -> str:
    """
    Rend des 'network A.B.C.D mask W.X.Y.Z'
    """
    lines = ""
    for cidr in origins:
        net = ipaddress.IPv4Network(cidr, strict=False)
        lines += f" network {net.network_address} mask {net.netmask}\n"
    return lines

def configurer_bgp(asn, router_id, router_name, loopback_ip, ibgp_neighbors, ebgp_neighbors, intent):
    if not ibgp_neighbors and not ebgp_neighbors:
        return ""

    cfg = configurer_bgp_policies(intent)

    cfg += f"""router bgp {asn}
 bgp router-id {router_id}
 bgp log-neighbor-changes
"""

    # ✅ ORIGINATION : on annonce au moins la loopback /32 (et éventuellement des LANs)
    origins = collect_bgp_origins(router_name, intent, loopback_ip)
    cfg += render_bgp_network_statements(origins)

    # iBGP full mesh
    for n in ibgp_neighbors:
        cfg += f""" neighbor {n} remote-as {asn}
 neighbor {n} update-source Loopback0
 neighbor {n} next-hop-self
 neighbor {n} send-community
"""

    # eBGP neighbors with policies
    for n in ebgp_neighbors:
        role = n["relationship"].lower()
        peer_ip = n["ip"]
        cfg += f""" neighbor {peer_ip} remote-as {n['remote_as']}
 neighbor {peer_ip} send-community
 neighbor {peer_ip} route-map RM-IN-{role.upper()} in
 neighbor {peer_ip} route-map RM-OUT-TO-{role.upper()} out
"""
    return cfg + "!\n"

# =========================================================
# LOGIQUE INTENT
# =========================================================

def get_router_as(router_name, intent):
    for as_data in intent.get("autonomous_systems", []):
        if router_name in [r["name"] for r in as_data.get("routers", [])]:
            return as_data
    return None

def get_router_loopback(router_name, intent):
    for as_data in intent.get("autonomous_systems", []):
        for r in as_data.get("routers", []):
            if r["name"] == router_name:
                return r["loopback"].split("/")[0]
    return None

# Extraction de la métrique OSPF depuis le lien (si possible)
def get_router_interfaces(router_name, intent):
    interfaces = []
    for link in intent.get("links", []):
        # On récupère la métrique du lien si elle existe
        metric = link.get("ospf_metric")

        for ep in link.get("endpoints", []):
            if ep.get("device") == router_name:
                ip, mask = ep["ip"].split("/")
                iface_data = {
                    "name": ep["interface"],
                    "ip": ip,
                    "mask": mask_to_dotted(mask)
                }
                # Si une métrique est définie sur le lien, on l'ajoute à l'interface
                if metric:
                    iface_data["ospf_metric"] = metric
                interfaces.append(iface_data)
    return interfaces

def collect_ebgp_neighbors(router_name: str, intent: dict):
    neighbors = []
    peers = intent.get("bgp", {}).get("ebgp_peers", [])
    declared = {(p["local_router"], p["remote_router"]) for p in peers}

    for p in peers:
        lr = p["local_router"]
        rr = p["remote_router"]

        if lr == router_name:
            remote_ip = find_link_peer_ip(lr, rr, intent)
            if remote_ip is None:
                raise ValueError(f"Impossible de trouver le lien {lr}<->{rr} dans 'links'.")
            neighbors.append({
                "ip": remote_ip,
                "remote_as": p["remote_as"],
                "relationship": p["relationship"]
            })

        if rr == router_name and (rr, lr) not in declared:
            remote_ip = find_link_peer_ip(rr, lr, intent)
            if remote_ip is None:
                raise ValueError(f"Impossible de trouver le lien {rr}<->{lr} dans 'links'.")
            remote_as = get_router_asn(lr, intent)
            if remote_as is None:
                raise ValueError(f"Impossible de déduire l'ASN de {lr}.")
            neighbors.append({
                "ip": remote_ip,
                "remote_as": remote_as,
                "relationship": infer_reverse_relationship(p["relationship"])
            })

    return neighbors

# =========================================================
# ASSEMBLER CONFIGURATION COMPLÈTE
# =========================================================

def assembler_configuration(router_name, intent):
    validate_intent_minimal(intent)

    as_data = get_router_as(router_name, intent)
    if as_data is None:
        raise ValueError(f"Routeur {router_name} introuvable dans autonomous_systems.")

    loopback_ip = get_router_loopback(router_name, intent)
    if loopback_ip is None:
        raise ValueError(f"Loopback non définie pour {router_name}.")

    interfaces = get_router_interfaces(router_name, intent)

    ibgp_neighbors = []
    if as_data.get("ibgp", {}).get("type") == "full-mesh":
        for r in as_data.get("routers", []):
            if r["name"] != router_name:
                ibgp_neighbors.append(get_router_loopback(r["name"], intent))

    ebgp_neighbors = collect_ebgp_neighbors(router_name, intent)

    # Extract IGP protocol for interface configuration
    protocol_igp = as_data["igp"]["protocol"].upper()

    cfg = ""
    cfg += creer_entete(router_name)
    cfg += configurer_loopback(loopback_ip)
    cfg += configurer_interfaces(interfaces)
    cfg += configurer_igp(as_data, interfaces, loopback_ip)
    cfg += configurer_bgp(as_data["asn"], loopback_ip, router_name, loopback_ip, ibgp_neighbors, ebgp_neighbors, intent)
    return cfg
