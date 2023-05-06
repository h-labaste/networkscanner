import subprocess
import os
import sys
import asyncio


## CONFIG

# Définition du sous-réseau à analyser et création d'un objet IPv4Network
subnet = "192.168.1.0/24"
# Nombre de threads pour le ThreadPoolExecutor
num_threads = 16 # MAX = NbCPUCore x 2

def install_packages():
    try:
        subprocess.check_call(['pip', 'install', '-r', 'requirements.txt'])
    except subprocess.CalledProcessError as e:
        print(f'Erreur lors de l\'installation des packages: {e}')
        exit()

async def StartScanner():
    # Récupération de l'élément XML racine devices
    root = await scan_network(subnet, num_threads=num_threads)

    # Écriture du fichier XML avec les informations collectées
    try:
        ET.ElementTree(root).write('devices.xml')
    except Exception as e:
        print(f'Erreur lors de l\'écriture dans le fichier : {e}')
        exit()

if __name__ == '__main__':
    try:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_dir)

        install_packages()

        # Importer les fonctions des différents modules
        from modules.network import  scan_network
        import xml.etree.ElementTree as ET
        asyncio.run(StartScanner())
    except Exception as e:
        print(f'Erreur lors de StartScanner : {e}')
        exit()
