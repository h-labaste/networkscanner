# device.py
__name__ = 'device'

import xml.etree.ElementTree as ET


def create_device_element(ip, mac, manufacturer, hostname, open_ports):
    device = ET.Element('device')

    ip_element = ET.SubElement(device, 'ip')
    ip_element.text = ip

    mac_element = ET.SubElement(device, 'mac')
    mac_element.text = mac

    manufacturer_element = ET.SubElement(device, 'manufacturer')
    manufacturer_element.text = manufacturer

    hostname_element = ET.SubElement(device, 'hostname')
    hostname_element.text = hostname

    open_ports_element = ET.SubElement(device, 'open_ports')
    open_ports_element.text = ', '.join(map(str, open_ports))

    return device
