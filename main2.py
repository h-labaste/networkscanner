import os
import socket
import struct
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import cpu_count
from scapy.all import ARP, Ether, srp
import ipaddress
import netifaces
import nmap
import xml.etree.ElementTree as ET


def arp_request(ip):
    # print(f" arp IP: {ip}")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(packet, timeout=0.08, verbose=0)
    if ans:
        return ans[0][1].psrc


def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]


def func_chunk(func, items):
    with ThreadPoolExecutor() as executor:
        results = executor.map(func, items)
    return [item for item in results if item]


def call_func_chunk(args):
    func, chunk = args
    return func_chunk(func, chunk)


def go_process(func, items, processes=None, chunk_size=10):
    processes = cpu_count() if processes is None else processes
    chunk_size = 10 if chunk_size <= 0 else chunk_size
    chunks = list(chunked(items, chunk_size))
    with ProcessPoolExecutor(max_workers=processes) as executor:
        results = executor.map(call_func_chunk, [(func, chunk) for chunk in chunks])

    return results


def get_active_ips(network_ranges):
    ips = []
    for network_range in network_ranges:
        ips.extend([str(ip) for ip in network_range.hosts()])

    my_results = go_process(arp_request, ips)
    return [ip for chunk in my_results for ip in chunk]


def get_current_networks(interface: str = 'eth0'):
    my_current_networks = []
    for iface_data in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
        if iface_data['addr'] != '127.0.0.1':
            print(f"Interface: {interface}, IP: {iface_data['addr']}, Netmask: {iface_data['netmask']}")
            my_ip = iface_data['addr']
            netmask = iface_data['netmask']
            my_current_network = ipaddress.ip_interface(f"{my_ip}/{netmask}").network
            my_current_networks.append(my_current_network)
    return my_current_networks


def get_my_interfaces():
    interfaces = []
    for interface in netifaces.interfaces():
        if netifaces.AF_INET in netifaces.ifaddresses(interface):
            interfaces.append(interface)
    return interfaces


def get_my_network_ranges(interfaces):
    network_ranges = []
    for my_interface in interfaces:
        my_networks = get_current_networks(my_interface)
        network_ranges.extend(my_networks)
    return network_ranges


def get_host_info(ip, open_port_range):
    print("PortScanner initializing...")
    nm = nmap.PortScanner()
    print("Scanning port initializing...")
    nm.scan(ip, ','.join(map(str, open_port_range)))
    print("host_data initializing...")
    host_data = nm[ip]
    for key, value in host_data.items():
        print(f"host_data[{key}]={value}")
    print("port list loading...")
    open_ports = [(port, host_data['tcp'][port]) for port in host_data['tcp'].keys() if host_data['tcp'][port]['state'] == 'open']
    print("getfqdn initializing...")
    hostname = socket.getfqdn(ip)
    print("getfqdn initializing...")
    mac_address = host_data['addresses'].get('mac', 'Inconnu')
    print("vendor initializing...")
    manufacturer = host_data['vendor'].get(mac_address, 'Inconnu')
    print("datas initializing...")
    datas = {
        'ip': ip,
        'hostname': hostname,
        'mac_address': mac_address,
        'manufacturer': manufacturer,
        'open_ports': open_ports
    }
    print("return datas", datas)
    return datas


def create_xml_file(host_info):
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
    tree.write(f"{ip}.xml")


if __name__ == "__main__":
    open_port_range = [21, 22, 80, 443]
    my_interfaces = get_my_interfaces()
    print(f"Interfaces: {my_interfaces}")
    my_network_ranges = get_my_network_ranges(my_interfaces)
    print(f"Network Ranges: {my_network_ranges}")
    active_ips = get_active_ips(my_network_ranges)
    print("Active IPs:", active_ips)
    for ip in active_ips:
        print("get_host_info:", ip, open_port_range)
        host_info = get_host_info(ip, open_port_range)
        print("create_xml_file IPs:", host_info)
        create_xml_file(host_info)