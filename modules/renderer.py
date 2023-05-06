# renderer.py
__name__ = 'renderer'
import os

def display_device(device):
    ip = device.find('ip').text
    mac = device.find('mac').text
    manufacturer = device.find('manufacturer').text
    hostname = device.find('hostname').text
    open_ports = device.find('open_ports').text
    print(f'IP: {ip} | MAC: {mac} | Manufacturer: {manufacturer} | Hostname: {hostname} | Open Ports: {open_ports}')

def write_devices_to_xml(datas, filename):
    try:
        ET.ElementTree(datas).write('devices.xml')
    except Exception as e:
        print(f'Erreur lors de l\'écriture dans le fichier : {e}')

