from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Network
from manuf import manuf
import asyncio
from scapy.all import ARP, Ether, srp
from scapy.sendrecv import AsyncSniffer
from . import device
from . import scanner
from . import renderer
import socket
import xml.etree.ElementTree as ET
import traceback

parser = manuf.MacParser()


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception as e:
        print(f'Error getting hostname for IP {ip}: {e}')
        return 'N/A'

async def process_packet(packet):
    packet.sprintf("%Ether.src% %ARP.psrc%")

async def arp_request(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    loop = asyncio.get_running_loop()
    sniffer = AsyncSniffer(prn=lambda x: x.sprintf("%Ether.src% %ARP.psrc%"), count=1)
    sniffer.start()
    transport, _ = await loop.create_datagram_endpoint(lambda: asyncio.Protocol(), sock=None, family=socket.AF_INET)
    transport.sendto(pkt)
    await asyncio.sleep(0.1)
    sniffer.stop()
    return sniffer.results[0].split()[0] if sniffer.results else None


def is_host_up(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1) # timeout de 1 seconde
        result = sock.connect_ex((host, port))
        if result == 0:
            return True
        else:
            return False
    except socket.error as e:
        print("Erreur lors de la connexion au serveur : %s" % e)
        return False


async def process_ip(ip):
    try:
        print(f"Start process_ip : {ip}")
        is_up = await is_host_up(ip)
        if is_up:
            ans = await arp_request(str(ip))
        else:
            ans = None
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        traceback.print_exc()
    print(f"End process_ip : {ip}")
    return None

    #ans = await arp_request(str(ip))
    # if ans:
    #     mac = ans[0][1].src
    #     manufacturer = parser.get_manuf_long(mac)
    #     hostname = get_hostname(str(ip))
    #     open_ports = []#await scanner.scan_ports(str(ip), range(1, 20))
    #     device_element = device.create_device_element(str(ip), mac, manufacturer, hostname, open_ports)
    #     renderer.display_device(device_element)
    #     return device_element
    # return None


async def scan_network(subnet, num_threads=16):
    network = IPv4Network(subnet, strict=False)
    
    devices = []
    root = ET.Element('devices')
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        coros = [process_ip(ip) for ip in network]
        for coro in asyncio.as_completed(coros):
            device_element = await coro
            if device_element:
                root.append(device_element)
                exit()
    return root







