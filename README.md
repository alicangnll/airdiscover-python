# 🚀 AirDiscover

**AirDiscover** is an AirDrop discovery tool developed in Python.
It listens to mDNS traffic on the `awdl0` interface on macOS systems and identifies devices broadcasting AirDrop services in the network.

![banner](https://github.com/user-attachments/assets/3bff818e-90a6-4de1-8870-33ec194625fd)


## 🧰 Features

* 📡 Listens for mDNS (UDP 5353) traffic over the `awdl0` interface
* 🔍 Detects DNS queries related to `_airdrop._tcp.local`
* 🖥️ Displays source and destination MAC addresses
* 📝 Provides real-time terminal output

## ⚙️ Installation

1. Ensure you have Python 3.x installed.
2. Install the required Python package: ```pip3 install scapy```

## 🚀 Usage

Run the script in your terminal using: ```sudo python3 main.py```

> ⚠️ The `awdl0` interface is a special wireless interface available only on macOS. Make sure you're using a macOS system.

## 📄 License

This project is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

## 🙋‍♂️ Author

**Ali Can Gönüllü**

* 🌐 [LinkedIn](https://www.linkedin.com/in/alicangonullu/)
* 💻 [GitHub](https://github.com/alicangnll)
