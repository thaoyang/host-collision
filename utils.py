import subprocess,re
import json, requests
from loguru import logger


def hostwhois(domain:str, FULL_TXT=False):
    """
    Input a root_domain, output a string composed of all information starting with Registrant
    :param domain:
    :param FULL_TXT:
    :return:
    """
    try:
        result = subprocess.run(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            res = result.stdout
            if not FULL_TXT:
                pattern = r'Registrant\s+\w[\w\s/]*:\s*(.*?)(?=\n[A-Z]|$)'
                matches = re.findall(pattern, res)
                # print(res)
                results = [match.strip() for match in matches if match.strip()]
                return ', '.join(results)
            return res
        else:
            return 'ERROR'
    except Exception as e:
        return 'ERROR'

def ipwhpois(ip:str):
    result = subprocess.run(['whois', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout


import socket
from loguru import logger
def resolve_domain_to_ips(domain):
    try:
        host_info = socket.gethostbyname_ex(domain)
        ip_addresses = host_info[2]  # Get IP address list
        return ip_addresses
    except socket.gaierror as e:
        logger.warning(f"Error resolving domain {domain}: {e}")
        return []

import ipaddress
def is_private_ipv4(ip_address: str) -> bool:
    # Check if it's a private IP
    try:
        ip = ipaddress.ip_address(ip_address)
        P1 = ip.is_private
        P2 = ip in ipaddress.ip_network('100.64.0.0/10')
        return P1 or P2
    except ValueError:
        logger.warning(f"Invalid IP address: {ip_address}")
        return False


