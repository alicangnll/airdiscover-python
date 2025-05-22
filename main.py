#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from class_applenum import Apple_iPhone_Enum, macOS_Enum

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apple cihaz bulma ve ağ tarama aracı")
    parser.add_argument(
        "-m", "--mode",
        choices=["iphone", "macos"],
        required=True,
        help="Çalışma modu: 'iphone' veya 'macos'"
    )
    parser.add_argument(
        "-n", "--network",
        type=str,
        default="192.168.1.0/24",
        help="Taranacak ağ aralığı (sadece 'macos' modunda kullanılır). Varsayılan: 192.168.1.0/24"
    )
    args = parser.parse_args()

    if args.mode == "iphone":
        Apple_iPhone_Enum.main()
    elif args.mode == "macos":
        macOS_Enum.scan_network(args.network)
