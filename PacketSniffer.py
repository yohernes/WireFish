import platform
import subprocess
from scapy.all import sniff
import socket
import ipaddress
import MemoryManager


def get_domain_name(memory, ip: str) -> str:
    """
    Perform a reverse DNS lookup for the given IP address.
    Uses a cache to store previous lookups for efficiency.
    """
    domain_name = ""
    address = ipaddress.ip_address(ip)
    if address.is_private:
        if ip in memory.local_dns_cache:
            return memory.local_dns_cache[ip]
        try:
            domain_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            domain_name = "unknown local"
        memory.local_dns_cache[ip] = domain_name
    elif address.is_global:
        if ip in memory.global_dns_cache:
            return memory.global_dns_cache[ip]
        try:
            domain_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            domain_name = "unknown"
        memory.global_dns_cache[ip] = domain_name

    return domain_name


def sniff_packets(master) -> None:
    sniff(prn=master.packet_callback, store=0, stop_filter=lambda x: not master.is_sniffing)


def get_current_ssid():
    current_os = platform.system()

    try:
        if current_os == 'Windows':
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'SSID' in line:
                    return line.split(':')[1].strip()

        elif current_os == 'Darwin':  # macOS
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ' SSID' in line:
                    return line.split(': ')[1].strip()

        elif current_os == 'Linux':
            result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
            return result.stdout.strip()

    except Exception as e:
        print(f"Error getting SSID: {e}")
        return None
