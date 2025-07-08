from scapy.all import sniff, ARP, Ether, IP, ICMP
from collections import defaultdict
import time

seen_devices = defaultdict(lambda: {'mac': None, 'last_seen': 0})


def packet_callback(pkt):
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        src_ip = pkt[IP].src if IP in pkt else None
        dst_ip = pkt[IP].dst if IP in pkt else None
        seen_devices[src_mac]['mac'] = src_mac
        seen_devices[src_mac]['last_seen'] = time.time()
        if src_ip:
            seen_devices[src_mac]['ip'] = src_ip
        print(f"[{now}] MAC {src_mac} -> {dst_mac} | IP {src_ip} -> {dst_ip}")
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        src_mac = pkt[ARP].hwsrc
        src_ip = pkt[ARP].psrc
        dst_mac = pkt[ARP].hwdst
        dst_ip = pkt[ARP].pdst
        seen_devices[src_mac]['mac'] = src_mac
        seen_devices[src_mac]['ip'] = src_ip
        seen_devices[src_mac]['last_seen'] = time.time()
        print(f"[{now}] ARP: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")
    if ICMP in pkt:
        print(f"[{now}] ICMP: {pkt[IP].src} -> {pkt[IP].dst}")

def print_devices():
    print("\n--- Devices seen on the network ---")
    for mac, info in seen_devices.items():
        last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['last_seen']))
        ip = info.get('ip', 'Unknown')
        print(f"MAC: {mac} | IP: {ip} | Last seen: {last_seen}")
    print("-----------------------------------\n")

if __name__ == "__main__":
    print("[*] Starting network sniffer. Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer.")
        print_devices()
