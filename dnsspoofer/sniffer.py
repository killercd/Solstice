#!/usr/bin/python
import scapy
from scapy.all import *
import configparser
import whois

config = configparser.ConfigParser()
config.read("config.ini")

iface = config["arpspoofer"]["iface"]
target = config["arpspoofer"]["target"]

waddress = {}

def packet_callback(packet):
    global waddress
    if packet.haslayer(IP) and (packet[IP].src==target or packet[IP].dst==target):
        source = packet[IP].src
        dest = packet[IP].src
        srport = 0
        dstport = 0
        if packet.haslayer(UDP):
            srport = packet[UDP].sport
            dstport = packet[UDP].dport
        elif packet.haslayer(TCP):
            srport = packet[TCP].sport
            dstport = packet[TCP].dport
        
        if source in waddress:
            sourcewhois = waddress[source]
        else:
            whois_info = whois.whois(source)
            org = whois_info["org"] if "org" in whois_info else "N/A"
            country = whois_info["country"] if "country" in whois_info else "N/A" 
            waddress[source] = f"{org} - {country}"
            sourcewhois = waddress[source]
        
        if dest in waddress:
            destwhois = waddress[dest]
        else:
            whois_info = whois.whois(dest)
            org = whois_info["org"] if "org" in whois_info else "N/A"
            country = whois_info["country"] if "country" in whois_info else "N/A"
            waddress[source] = f"{org} - {country}"
            destwhois = waddress[source]
            
        
        print(f"{source}:{srport} ({sourcewhois}) -> {dest}:{dstport} ({destwhois})")
        
sniff(iface=iface, prn=packet_callback, store=0)