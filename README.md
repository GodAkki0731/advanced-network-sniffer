![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Project-Active-brightgreen)
![Tests](https://img.shields.io/badge/Tests-Passing-success)

# 🚀 Advanced Network Packet Sniffer & Analyzer

A professional-grade Python-based packet sniffer designed to capture, inspect, and analyze real-time network traffic.  
Built using Scapy, this tool supports IP, TCP, UDP, DNS Query/Response parsing, unknown protocol detection, and complete automated test coverage.

---

## ✨ Features

- 📡 **Real-time packet sniffing**
- 🌐 **IP / TCP / UDP protocol parsing**
- 🔍 **DNS Query & Response detection**
- 🛑 **Unknown protocol identification**
- 🧼 **Clean, readable CLI output**
- 🧪 **Fully tested with unittest + pytest**
- 🧩 **Modular and extendable architecture**

---

## 📁 Project Structure

```

advanced-network-sniffer/
│── sniffer.py
│── requirements.txt
│── README.md
│── LICENSE
│── .gitignore
│
└── tests/
└── test_sniffer.py

```

---

# 🛠 Installation & Setup Guide  
(Use these steps to set up and run the project on any system)

---

## ✔️ Step 1 — Clone the repository

```

git clone [https://github.com/GodAkki0731/advanced-network-sniffer.git](https://github.com/GodAkki0731/advanced-network-sniffer.git)
cd advanced-network-sniffer

```

---

## ✔️ Step 2 — Install dependencies

```

pip install -r requirements.txt

```

This installs:
- Scapy  
- Pytest  
- Unittest2  

---

# ▶️ Running the Sniffer

## ✔️ Linux / macOS:
```

sudo python sniffer.py

```
(*sudo required for raw socket access*)

## ✔️ Windows:
```

python sniffer.py

```

---

# 🧪 Running Tests

You can use **either pytest OR unittest**.

---

## ✔️ Run tests using Pytest (Recommended)

```

pytest -v

```

---

## ✔️ Run tests using Python Unittest

```

python -m unittest discover

```

---

# 🔧 What the Sniffer Detects

| Protocol | Details Detected |
|---------|------------------|
| **IP** | Source & Destination IP |
| **TCP** | Source/Destination Port, protocol details |
| **UDP** | Source/Destination Port |
| **DNS Query** | Domain requested by client |
| **DNS Response** | Domain → Resolved IP |
| **Unknown Protocols** | Raw protocol number |

---

# 🚀 Future Enhancements

- 🔐 TLS/HTTPS packet fingerprinting  
- 🌐 ARP, ICMP, and DHCP decoding  
- 📊 Web dashboard for visualizing packet data  
- 🤖 Machine Learning–based anomaly detection  
- 📁 PCAP export & import  
- 🕵 Deep packet inspection modules  

---

# 👨‍💻 Author

**Akaash Kumar (Master Creox)**  
Cybersecurity Engineer • Ethical Hacker • Network Analyst  
Building AI-powered cybersecurity tools and intelligent systems.

---

# ⭐ Contributions  
Pull requests are welcome.  
Feel free to open issues or suggest improvements!

---


