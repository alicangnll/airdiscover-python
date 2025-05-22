# 🍏 AirDiscover - Apple Device Discovery and Network Scanning Tool 🚀

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ali%20Can%20Gönüllü-blue)](https://www.linkedin.com/in/alicangonullu/)

![banner](https://github.com/user-attachments/assets/45466523-feca-49c6-8395-3875432947d1)

## 📖 About the Project

**AirDiscover** is a Python-based tool designed to discover Apple devices (macOS and iPhone) on your local network and gather detailed information about them.  
It identifies Apple devices by detecting MAC addresses using their OUI (Organizationally Unique Identifier) and retrieves IP addresses along with system details.

## ✨ Features

- 🔍 Scan for macOS and iPhone devices on the network  
- 🍎 Filter devices based on Apple OUI prefixes  
- 📋 Extract detailed plist-based information from devices  
- 🌐 Customizable network range for scanning  
- 🛠️ Command-line interface with argparse support  
- 🛡️ Robust error handling and informative logging  

## 🛠️ Installation

```bash
git clone https://github.com/alicangnll/airdiscover-python.git
cd airdiscover-python
pip install -r requirements.txt
````

## ✨ Pictures
![scr1](https://github.com/user-attachments/assets/64bf044a-21c9-42fe-8ce6-02f259d2081b)


## 🚀 Usage

### ❓ Help Menu

```bash
python3 main.py -h
```

### 💡 Example Commands

* 📱 Scan for iPhone devices:

```bash
python3 main.py -i iphone
```

* 💻 Scan for macOS devices in a specified network range:

```bash
python3 main.py -i macos -m 192.168.1.0/24
```

> ⚠️ *Note: The network range parameter (`-m`) is only used in `macos` mode.*


## 👨‍💻 Developer

Ali Can Gönüllü
🔗 [LinkedIn Profile](https://www.linkedin.com/in/alicangonullu/)

## 📄 License

This project is licensed under the Apache 2 License. See the `LICENSE` file for details.
