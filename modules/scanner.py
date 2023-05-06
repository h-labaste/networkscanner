# scanner.py
__name__ = 'scanner'

import socket

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f'IP: {ip} | Open Port: {port}')
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports
