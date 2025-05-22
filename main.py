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

INTERFACE = input("What is your AWDL adapter name (ex. awdl0) : ")
# Airdrop hizmet adını tespit etmek için desen
airdrop_pattern = re.compile(r"_airdrop\._tcp\.local", re.IGNORECASE)

def handle_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname.decode(errors="ignore")
        if re.search(airdrop_pattern, query_name):
            print(f"\n📡 AirDrop keşfi!")
            print(f"   ✳️ Sorgulanan: {query_name}")

            if packet.haslayer(Ether):
                print(f"   🟢 Kaynak MAC : {packet[Ether].src}")
                print(f"   🔴 Hedef MAC  : {packet[Ether].dst}")
            else:
                print("   ⚠️ MAC adresi bilgisi mevcut değil (Ether katmanı yok)")

def main():
    print("🛰️ " + INTERFACE + " arayüzü üzerinden mDNS (AirDrop) dinleniyor...\n")
    try:
        sniff(
            iface=INTERFACE,
            filter="udp port 5353",  # mDNS portu
            prn=handle_packet,
            store=0
        )
    except PermissionError:
        print("❌ Bu betik root/sudo ile çalıştırılmalıdır.")

if __name__ == '__main__':
    main()
