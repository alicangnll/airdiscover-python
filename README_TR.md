# 🚀 AirDiscover

**AirDiscover**, Python ile geliştirilmiş bir AirDrop keşif aracıdır. Bu araç, macOS sistemlerinde `awdl0` arayüzü üzerinden mDNS trafiğini dinleyerek, ağdaki AirDrop cihazlarını tespit eder.

## 🧰 Özellikler

* 📡 `awdl0` arayüzü üzerinden mDNS (UDP 5353) trafiğini dinler.
* 🔍 `_airdrop._tcp.local` DNS sorgularını tespit eder.
* 🖥️ Kaynak ve hedef MAC adreslerini gösterir.
* 📝 Gerçek zamanlı olarak terminal çıktısı sağlar.

## ⚙️ Kurulum

1. Python 3.x yüklü olduğundan emin olun.
2. Gerekli Python paketlerini yükleyin: ```pip3 install scapy```

## 🚀 Kullanım

Scripti çalıştırmak için terminalde aşağıdaki komutu kullanın: ```sudo python3 main.py```

> ⚠️ `awdl0` arayüzü özel bir ağ arayüzüdür ve yalnızca macOS sistemlerinde bulunur. Bu nedenle, scripti çalıştırmak için macOS kullanmanız gerekmektedir.

## 📄 Lisans
Bu proje [Apache 2.0 Lisansı](https://www.apache.org/licenses/LICENSE-2.0) ile lisanslanmıştır.

## 🙋‍♂️ Geliştirici

**Ali Can Gönüllü**

* 🌐 [LinkedIn](https://www.linkedin.com/in/alicangonullu/)
* 💻 [GitHub](https://github.com/alicangnll)
