"""
Ce script permet de scanner un réseau local, de récupérer les informations de chaque hôte actif, de générer un fichier XML
et de sauvegarder les informations dans le fichier.

Usage: python scanner.py

"""
import subprocess
import os
import sys
import socket


def install_packages():
    try:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_dir)
        subprocess.check_call(['pip', 'install', '-r', 'requirements.txt'])
    except subprocess.CalledProcessError as e:
        print(f'Erreur lors de l\'installation des packages: {e}')
        exit()
def arp_request(ip: str) -> str:
    """Effectue une requête ARP pour une adresse IP donnée.

    Args:
        ip (str): Adresse IP à requêter.

    Returns:
        str: Adresse IP de la réponse ARP, None si aucune réponse.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(packet, timeout=0.08, verbose=0)
    if ans:
        return ans[0][1].psrc

def chunked(iterable, size: int):
    """Divise un itérable en morceaux de taille donnée.

    Args:
        iterable: Itérable à diviser.
        size (int): Taille des morceaux.

    Yields:
        Morceau de l'itérable.
    """
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]

def func_chunk(func, items):
    """Applique une fonction à une liste d'éléments en utilisant un ThreadPoolExecutor.

    Args:
        func: Fonction à appliquer.
        items: Liste d'éléments sur lesquels appliquer la fonction.

    Returns:
        list: Liste des résultats non nuls.
    """
    with ThreadPoolExecutor() as executor:
        results = executor.map(func, items)
    return [item for item in results if item]

def call_func_chunk(args):
    """Appelle la fonction 'func_chunk' avec les arguments fournis.

    Args:
        args: Tuple contenant la fonction à appeler et la liste d'éléments à traiter.

    Returns:
        list: Liste des résultats non nuls après l'application de la fonction.
    """
    func, chunk = args
    return func_chunk(func, chunk)

def go_process(func, items, processes=None, chunk_size=10):
    """Applique une fonction à une liste d'éléments en utilisant un ProcessPoolExecutor.

    Args:
        func: Fonction à appliquer.
        items: Liste d'éléments sur lesquels appliquer la fonction.
        processes (int, optional): Nombre de processus à utiliser. Par défaut, cpu_count().
        chunk_size (int, optional): Taille des morceaux pour la division. Par défaut 10.

    Returns:
        results: Liste des résultats.
    """
    processes = cpu_count() if processes is None else processes
    chunk_size = 10 if chunk_size <= 0 else chunk_size
    chunks = list(chunked(items, chunk_size))
    with ProcessPoolExecutor(max_workers=processes) as executor:
        results = executor.map(call_func_chunk, [(func, chunk) for chunk in chunks])

    return results

def get_active_ips(network_ranges):
    """Récupère la liste des adresses IP actives pour une liste de plages réseau.

    Args:
        network_ranges: Liste des plages réseau.

    Returns:
        list: Liste des adresses IP actives.
    """
    ips = []
    for network_range in network_ranges:
        ips.extend([str(ip) for ip in network_range.hosts()])

    my_results = go_process(arp_request, ips)
    return [ip for chunk in my_results for ip in chunk]


def get_current_networks(interface: str = 'eth0'):
    """Récupère les réseaux actuels pour une interface donnée.

    Args:
        interface (str, optional): Nom de l'interface réseau. Par défaut 'eth0'.

    Returns:
        list: Liste des réseaux actuels pour l'interface.
    """
    my_current_networks = []
    for iface_data in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
        if iface_data['addr'] != '127.0.0.1':
            my_ip = iface_data['addr']
            netmask = iface_data['netmask']
            my_current_network = ipaddress.ip_interface(f"{my_ip}/{netmask}").network
            my_current_networks.append(my_current_network)
    return my_current_networks


def get_my_interfaces():
    """Récupère la liste des interfaces réseau de la machine.

    Returns:
        list: Liste des interfaces réseau.
    """
    interfaces = []
    for interface in netifaces.interfaces():
        if netifaces.AF_INET in netifaces.ifaddresses(interface):
            interfaces.append(interface)
    return interfaces

def get_my_network_ranges(interfaces):
    """Récupère les plages réseau pour une liste d'interfaces.

    Args:
        interfaces: Liste des interfaces réseau.

    Returns:
        list: Liste des plages réseau pour les interfaces.
    """
    network_ranges = []
    for my_interface in interfaces:
        my_networks = get_current_networks(my_interface)
        network_ranges.extend(my_networks)
    return network_ranges

def get_host_info(ip, open_port_range):
    """Récupère les informations détaillées d'un hôte pour une adresse IP et une liste de ports.

    Args:
        ip: Adresse IP de l'hôte.
        open_port_range: Liste des ports à vérifier.

    Returns:
        dict: Dictionnaire contenant les informations de l'hôte.
    """
    nm = nmap.PortScanner()
    nm.scan(ip, ','.join(map(str, open_port_range)))
    host_data = nm[ip]
    open_ports = [(port, host_data['tcp'][port]) for port in host_data['tcp'].keys() if host_data['tcp'][port]['state'] == 'open']
    hostname = socket.getfqdn(ip)
    mac_address = host_data['addresses'].get('mac', 'Inconnu')
    manufacturer = host_data['vendor'].get(mac_address, 'Inconnu')
    datas = {
        'ip': ip,
        'hostname': hostname,
        'mac_address': mac_address,
        'manufacturer': manufacturer,
        'open_ports': open_ports
    }
    return datas


def create_xml_file(host_info):
    """Crée un fichier XML avec les informations de l'hôte.

    Args:
        host_info: Dictionnaire contenant les informations de l'hôte.
    """
    root = ET.Element("host_info")

    for key, value in host_info.items():
        key_element = ET.SubElement(root, key)
        if key == "open_ports":
            for port in value:
                port_element = ET.SubElement(key_element, "port")
                for attr_key, attr_value in port[1].items():
                    port_element.set(attr_key, attr_value)
                port_element.text = str(port[0])
        else:
            key_element.text = value

    ip = host_info['ip']
    tree = ET.ElementTree(root)
    tree.write(f"{ip}.xml", encoding="utf-8", xml_declaration=True)
    # Ouverture et reformatage du fichier XML
    with open(f"{ip}.xml", "r") as xml_file:
        xml_string = xml_file.read()
    dom = xml.dom.minidom.parseString(xml_string)
    with open(f"{ip}.xml", "w") as xml_file:
        xml_file.write(dom.toprettyxml())


def display_in_prompt(host_info):
    """Affiche les informations de l'hôte.

    Args:
        host_info: Dictionnaire contenant les informations de l'hôte.
    """

    print("Host information for IP address:", host_info['ip'])
    for key, value in host_info.items():
        if key == "open_ports":
            for port in value:
                attrs = []
                for attr_key, attr_value in port[1].items():
                    attrs.append(f"{attr_key}: {attr_value}")
                print(f" - Port {port[0]}: " + ", ".join(attrs))
        else:
            print(f" - {key}: {value}")


if __name__ == "__main__":
    install_packages()

    import struct
    import ipaddress
    import xml.etree.ElementTree as ET
    import xml.dom.minidom

    from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
    from multiprocessing import cpu_count
    from scapy.all import ARP, Ether, srp
    import netifaces
    import nmap

    open_port_range = [21, 22, 80, 443]
    my_interfaces = get_my_interfaces()
    print(f"Interfaces: {my_interfaces}")
    my_network_ranges = get_my_network_ranges(my_interfaces)
    print(f"Network Ranges: {my_network_ranges}")
    active_ips = get_active_ips(my_network_ranges)
    print("Active IPs:", active_ips)
    for ip in active_ips:
        host_info = get_host_info(ip, open_port_range)
        display_in_prompt(host_info)
        create_xml_file(host_info)