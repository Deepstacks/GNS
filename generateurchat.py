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
    Vérifications utiles pour valider parties 2–3 :
    - Tous les routeurs ont au moins 1 interface dans links (sinon IGP/BGP impossibles)
    - Chaque ebgp_peers a bien un lien correspondant dans links
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
            "Topo incomplète: ces routeurs n'ont aucune interface dans 'links' "
            f"(donc IGP/iBGP impossibles) : {', '.join(isolated)}"
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

def configurer_interfaces(interfaces):
    cfg = ""
    for iface in interfaces:
        cfg += f"""interface {iface['name']}
 ip address {iface['ip']} {iface['mask']}
 no shutdown
!
"""
    return cfg

# =========================================================
# IGP
# =========================================================

def configurer_igp(as_data, interfaces, loopback_ip):
    """
    Configuration OSPF avec la possibilité de définir des métriques (coûts) OSPF.
    """
    igp = as_data["igp"]["protocol"].upper()

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
        process_id = as_data["igp"]["process_id"]
        area = as_data["igp"]["area"]
        cfg = f"""router ospf {process_id}
 router-id {loopback_ip}
"""
        for iface in interfaces:
            mask = iface["mask"]
            prefixlen = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            net = ipaddress.IPv4Interface(f"{iface['ip']}/{prefixlen}").network
            wildcard = wildcard_from_prefixlen(prefixlen)
            cost = iface.get("cost", 10)
            cfg += f" network {net.network_address} {wildcard} area {area}\n"
        
        # Loopback en dernier
        cfg += f" network {loopback_ip} 0.0.0.0 area {area}\n"
        
        # Coûts OSPF par interface (si définis)
        for iface in interfaces:
            if "cost" in iface:
                cfg += f"!\ninterface {iface['name']}\n ip ospf cost {iface['cost']}\n"
        
        return cfg + "!\n"

    return ""

# =========================================================
# BGP POLICIES (PARTIE 3.4) - VERSION AMÉLIORÉE
# =========================================================

def configurer_bgp_policies(intent):
    """
    Configure les filtres BGP avec:
    - Communities pour tagging
    - Local preference
    - Filtres de propagation
    - Filtres anti-bogon (sécurité de base)
    """
    bgp = intent["bgp"]
    communities = bgp["communities"]
    local_pref = bgp["local_preference"]
    policy = bgp.get("propagation_policy", {})

    cfg = ""

    # ============================================
    # SÉCURITÉ: Filtres anti-bogon/privés
    # ============================================
    cfg += """! Filtres de sécurité - Bloquer routes privées/bogon
ip prefix-list BOGONS deny 0.0.0.0/8 le 32
ip prefix-list BOGONS deny 10.0.0.0/8 le 32
ip prefix-list BOGONS deny 172.16.0.0/12 le 32
ip prefix-list BOGONS deny 192.168.0.0/16 le 32
ip prefix-list BOGONS deny 224.0.0.0/4 le 32
ip prefix-list BOGONS permit 0.0.0.0/0 le 32
!
"""

    # ============================================
    # Définir les community-lists
    # ============================================
    for role, comm in communities.items():
        cfg += f"ip community-list standard {role.upper()} permit {comm}\n"
    cfg += "!\n"

    # ============================================
    # Route-maps IN: Tagging + Local Preference
    # ============================================
    for role, comm in communities.items():
        lp = local_pref[role]
        cfg += f"""route-map RM-IN-{role.upper()} permit 10
 match ip address prefix-list BOGONS
 set community {comm} additive
 set local-preference {lp}
!
"""

    # ============================================
    # Route-map pour routes locales (AMÉLIORÉ)
    # ============================================
    cfg += f"""route-map RM-SET-LOCAL permit 10
 set local-preference {local_pref['customer']}
 set community {communities['customer']} additive
!
"""

    # ============================================
    # Route-maps OUT: Filtrage par propagation policy
    # ============================================
    for to_key, allowed_roles in policy.items():
        target = to_key.replace("to_", "").upper()
        listname = f"TO_{target}"
        
        # Créer community-list pour ce target
        for r in allowed_roles:
            cfg += f"ip community-list standard {listname} permit {communities[r]}\n"
        cfg += "\n"

        # Route-map simplifié (pas de deny explicite - implicit deny suffit)
        cfg += f"""route-map RM-OUT-TO-{target} permit 10
 match community {listname}
!
"""

    return cfg

def configurer_bgp(as_data, asn, router_id, ibgp_neighbors, ebgp_neighbors, intent):
    """
    Configuration complète de BGP avec gestion des route-maps et des politiques de propagation.
    VERSION AMÉLIORÉE avec meilleure gestion des routes locales.
    """
    if not ibgp_neighbors and not ebgp_neighbors:
        return ""

    # Générer les policies en premier
    cfg = configurer_bgp_policies(intent)

    cfg += f"""router bgp {asn}
 bgp router-id {router_id}
 bgp log-neighbor-changes
"""

    # ============================================
    # Configuration iBGP en full-mesh
    # ============================================
    for n in ibgp_neighbors:
        cfg += f""" neighbor {n} remote-as {asn}
 neighbor {n} update-source Loopback0
 neighbor {n} next-hop-self
 neighbor {n} send-community
 neighbor {n} soft-reconfiguration inbound
"""

    # ============================================
    # Configuration des voisins eBGP
    # ============================================
    for n in ebgp_neighbors:
        role = n["relationship"].lower()
        peer_ip = n["ip"]
        cfg += f""" neighbor {peer_ip} remote-as {n['remote_as']}
 neighbor {peer_ip} send-community
 neighbor {peer_ip} route-map RM-IN-{role.upper()} in
 neighbor {peer_ip} route-map RM-OUT-TO-{role.upper()} out
 neighbor {peer_ip} soft-reconfiguration inbound
"""

    # ============================================
    # Annonces locales (AMÉLIORÉ)
    # ============================================
    # Annoncer la loopback avec le tag LOCAL
    if as_data.get("advertise_loopback"):
        cfg += f" network {router_id} mask 255.255.255.255 route-map RM-SET-LOCAL\n"
    
    # Note: Si vous avez d'autres réseaux à annoncer, ajoutez-les ici
    # avec route-map RM-SET-LOCAL pour qu'ils soient aussi tagués comme "customer"
    
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

def get_router_interfaces(router_name, intent):
    interfaces = []
    for link in intent.get("links", []):
        for ep in link.get("endpoints", []):
            if ep.get("device") == router_name:
                ip, mask = ep["ip"].split("/")
                iface_data = {
                    "name": ep["interface"],
                    "ip": ip,
                    "mask": mask_to_dotted(mask)
                }
                # Ajouter le coût OSPF si défini dans l'intent
                if "cost" in ep:
                    iface_data["cost"] = ep["cost"]
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
                raise ValueError(f"Impossible de déduire l'ASN de {lr} (routeur introuvable).")
            neighbors.append({
                "ip": remote_ip,
                "remote_as": remote_as,
                "relationship": infer_reverse_relationship(p["relationship"])
            })

    return neighbors

# =========================================================
# ASSEMBLER CONFIGURATION COMPLETE
# =========================================================

def assembler_configuration(router_name, intent):
    """
    Assemble la configuration complète d'un routeur basée sur l'intent file.
    """
    validate_intent_minimal(intent)

    as_data = get_router_as(router_name, intent)
    if as_data is None:
        raise ValueError(f"Routeur {router_name} introuvable dans autonomous_systems.")

    loopback_ip = get_router_loopback(router_name, intent)
    if loopback_ip is None:
        raise ValueError(f"Loopback non définie pour {router_name}.")

    interfaces = get_router_interfaces(router_name, intent)

    # iBGP neighbors
    ibgp_neighbors = []
    if as_data.get("ibgp", {}).get("type") == "full-mesh":
        for r in as_data.get("routers", []):
            if r["name"] != router_name:
                ibgp_neighbors.append(get_router_loopback(r["name"], intent))

    # eBGP neighbors
    ebgp_neighbors = collect_ebgp_neighbors(router_name, intent)

    # Assembler la configuration
    cfg = ""
    cfg += creer_entete(router_name)
    cfg += configurer_loopback(loopback_ip)
    cfg += configurer_interfaces(interfaces)
    cfg += configurer_igp(as_data, interfaces, loopback_ip)
    cfg += configurer_bgp(as_data, as_data["asn"], loopback_ip, ibgp_neighbors, ebgp_neighbors, intent)
    
    cfg += "!\nend\n"
    
    return cfg


# =========================================================
# UTILISATION EXEMPLE
# =========================================================
if __name__ == "__main__":
    import json
    
    # Charger l'intent file
    with open('Intent_file.json', 'r') as f:
        intent = json.load(f)
    
    # Générer la config pour tous les routeurs
    all_routers = []
    for as_data in intent.get("autonomous_systems", []):
        for r in as_data.get("routers", []):
            all_routers.append(r["name"])
    
    # Générer et sauvegarder les configs
    import os
    output_dir = intent.get("project_settings", {}).get("output_folder", "output")
    os.makedirs(output_dir, exist_ok=True)
    
    for router in all_routers:
        try:
            config = assembler_configuration(router, intent)
            output_file = os.path.join(output_dir, f"{router}_config.txt")
            with open(output_file, 'w') as f:
                f.write(config)
            print(f"✅ Configuration générée pour {router} -> {output_file}")
        except Exception as e:
            print(f"❌ Erreur pour {router}: {e}")