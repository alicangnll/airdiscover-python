#!/usr/bin/env python3
# -*- coding: utf-8 -*-

print("""
    █████╗ ██╗██████╗ ██████╗ ██╗ ██████╗ ██████╗ ███████╗███████╗██████╗ 
   ██╔══██╗██║██╔══██╗██╔══██╗██║██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔══██╗
   ███████║██║██║  ██║██████╔╝██║██║  ███╗██████╔╝█████╗  █████╗  ██████╔╝
   ██╔══██║██║██║  ██║██╔══██╗██║██║   ██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔═══╝ 
   ██║  ██║██║██████╔╝██║  ██║██║╚██████╔╝██║     ███████╗███████╗██║     
   ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝╚═╝     
                                                                          
                      AirDiscover - Developed by Ali Can Gönüllü
                  🔗 https://www.linkedin.com/in/alicangonullu/

""")

from scapy.all import sniff, DNS, DNSQR, Ether
import re

INTERFACE = input("What is the name of your AWDL adapter (e.g. awdl0) : ")

airdrop_pattern = re.compile(r"_airdrop\._tcp\.local", re.IGNORECASE)

def handle_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname.decode(errors="ignore")
        if re.search(airdrop_pattern, query_name):
            print(f"\n📡 AirDrop Discovered!")
            print(f"   ✳️ Checked: {query_name}")

            if packet.haslayer(Ether):
                print(f"   🟢 Source MAC : {packet[Ether].src}")
                print(f"   🔴 Destination MAC  : {packet[Ether].dst}")
            else:
                print("   ⚠️ MAC address information not available (no Ether layer)")

def main():
    print("🛰️  listening to mDNS (AirDrop) over " + INTERFACE + " interface...\n")
    try:
        sniff(
            iface=INTERFACE,
            filter="udp port 5353",  # mDNS port
            prn=handle_packet,
            store=0
        )
    except PermissionError:
        print("❌ This script must be run with root/sudo.")

if __name__ == '__main__':
    main()
