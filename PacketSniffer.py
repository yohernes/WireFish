import platform
import subprocess
from scapy.all import sniff
import socket
import ipaddress
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, \
    ICMPv6DestUnreach


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


def dissect_packet(packet, memory) -> tuple[str, str, str, str]:
    ip_layer = IP if IP in packet else (IPv6 if IPv6 in packet else None)
    source = ""
    destination = ""
    if ip_layer:
        try:
            source = packet[ip_layer].src
            destination = packet[ip_layer].dst

            # Resolve domain names
            src_domain = get_domain_name(memory, source)
            dst_domain = get_domain_name(memory, destination)
            source = f"{source} ({src_domain})" if src_domain else source
            destination = f"{destination} ({dst_domain})" if dst_domain else destination

            # Handle TCP, UDP, ICMP, and other IP protocols
            if TCP in packet:
                protocol, info = handle_tcp(packet)
            elif UDP in packet:
                protocol, info = handle_udp(packet)
            elif ICMP in packet:
                protocol, info = handle_icmp(packet)
            elif IPv6 in packet and (
                    ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet or ICMPv6ND_NS in packet or ICMPv6ND_NA in packet):
                protocol, info = handle_icmpv6(packet)
            elif IGMP in packet or IGMPv3 in packet:
                protocol, info = handle_igmp(packet)
            else:
                protocol, info = handle_other_ip(packet, ip_layer)

        except AttributeError:
            protocol, info = "Unknown IP Protocol", "Error extracting packet details"

    # Non-IP packets (e.g., ARP)
    elif ARP in packet:
        protocol, source, destination, info = handle_arp(packet)
    else:
        protocol, info = packet.name, packet.summary()
    return source, destination, protocol, info


def get_current_ssid() -> str:
    current_os = platform.system()

    try:
        if current_os == 'Windows':
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'SSID' in line:
                    return line.split(':')[1].strip()

        elif current_os == 'Darwin':  # macOS
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                                     '-I'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ' SSID' in line:
                    return line.split(': ')[1].strip()

        elif current_os == 'Linux':
            result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
            return result.stdout.strip()

    except Exception as e:
        print(f"Error getting SSID: {e}")
        return ""


def handle_tcp(packet) -> tuple[str, str]:
    sport, dport = packet[TCP].sport, packet[TCP].dport
    flags = packet[TCP].flags
    protocol = "TCP"
    info = f"{sport} → {dport} "

    # Determine application layer protocol
    if dport == 443 or sport == 443:
        protocol = "HTTPS-TCP"
    elif dport == 80 or sport == 80:
        protocol = "HTTP-TCP"

    # Flag information
    if flags.S and not flags.A:
        info += "[SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=2037676640 TSecr=0 WS=128"
    elif flags.S and flags.A:
        info += "[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
    elif flags.A and not flags.P:
        info += "[ACK] Seq=1 Ack=1 Win=65535 Len=0"
    elif flags.P and flags.A:
        info += (f"[PSH, ACK] Seq={packet[TCP].seq} Ack={packet[TCP].ack} "
                 f"Win=65535 Len={len(packet[TCP].payload)}")
    elif flags.F:
        info += "[FIN, ACK] Seq=1 Ack=1 Win=65535 Len=0"
    else:
        info += f"[{flags}] {len(packet[TCP].payload)} bytes"

    return protocol, info


def handle_udp(packet) -> tuple[str, str]:
    sport, dport = packet[UDP].sport, packet[UDP].dport
    protocol = "UDP"
    info = f"{sport} → {dport} Len={len(packet[UDP].payload)}"

    # Determine application layer protocol
    if dport == 53 or sport == 53:
        protocol = "DNS-UDP"

    return protocol, info


def handle_icmp(packet) -> tuple[str, str]:
    protocol = "ICMP"
    icmp_type = packet[ICMP].type
    icmp_code = packet[ICMP].code
    if icmp_type == 8:
        info = "Echo (ping) request"
    elif icmp_type == 0:
        info = "Echo (ping) reply"
    else:
        info = f"Type={icmp_type}, Code={icmp_code}"

    return protocol, info


def handle_arp(packet) -> tuple[str, str, str, str]:
    protocol = "ARP"
    source = packet[ARP].hwsrc
    destination = packet[ARP].hwdst
    info = ""
    if packet[ARP].op == 1:  # ARP request
        info = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
    elif packet[ARP].op == 2:  # ARP reply
        info = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"

    return protocol, source, destination, info


def handle_icmpv6(packet) -> tuple[str, str]:
    # Initialize values for ICMPv6
    protocol = "ICMPv6"
    icmpv6_packet = packet[IPv6].payload  # Get the payload of the IPv6 packet
    if isinstance(icmpv6_packet, ICMPv6DestUnreach):
        info = "Destination Unreachable"
    elif isinstance(icmpv6_packet, ICMPv6EchoRequest):
        info = "Echo Request"
    elif isinstance(icmpv6_packet, ICMPv6EchoReply):
        info = "Echo Reply"
    elif isinstance(icmpv6_packet, ICMPv6ND_NS):  # Neighbor Solicitation
        info = "Neighbor Solicitation"
    elif isinstance(icmpv6_packet, ICMPv6ND_NA):  # Neighbor Advertisement
        info = "Neighbor Advertisement"
    else:
        info = f"Other ICMPv6 type: {type(icmpv6_packet).__name__}"

    return protocol, info


def handle_igmp(packet) -> tuple[str, str]:
    protocol = "IGMP"
    info = ""

    if IGMP in packet:
        igmp_packet = packet[IGMP]
        igmp_type = igmp_packet.type

        if igmp_type == 0x11:  # Membership Query
            info = "IGMP Membership Query"
        elif igmp_type == 0x22:  # Membership Report
            info = "IGMP Membership Report"
        elif igmp_type == 0x1:  # Leave Group
            info = "IGMP Leave Group"
        else:
            info = f"Unknown IGMP type: {igmp_type}"
    elif IGMPv3 in packet:
        igmp_packet = packet[IGMPv3]
        igmp_type = igmp_packet.type

        if igmp_type == 0x11:  # Membership Query
            info = "IGMP Membership Query"
        elif igmp_type == 0x22:  # Membership Report
            info = "IGMP Membership Report"
        elif igmp_type == 0x1:  # Leave Group
            info = "IGMP Leave Group"
        else:
            info = f"Unknown IGMP type: {igmp_type}"

    return protocol, info


def handle_other_ip(packet, ip_layer) -> tuple[str, str]:
    try:
        protocol = f"Other IP (proto={packet[ip_layer].proto})"
        info = (f"Next Header: {packet[ip_layer].nh}"
                if ip_layer == IPv6
                else f"Protocol: {packet[ip_layer].proto}")
    except AttributeError:
        protocol = "Unknown IP Protocol"
        info = "Could not retrieve protocol information"

    return protocol, info
