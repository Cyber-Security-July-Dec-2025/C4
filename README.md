# 🔐 Two-Party Secure Messaging App (Qt + Crypto++)

This is a desktop GUI application that allows two parties to securely exchange encrypted messages. It is built with *Qt* (for GUI + networking) and *Crypto++* (for AES/RSA cryptography) in C++.

---

## ✨ Features

- *GUI* built with Qt Widgets
  - Input box to type messages
  - Display window showing conversation history
  - Buttons: *Connect*, *Send*, *Disconnect*
- *Networking*
  - Two instances can run on different machines
  - Uses TCP sockets (QTcpSocket/QTcpServer)
- *Cryptography*
  - RSA (2048-bit) public/private key pairs
  - AES-256 (fresh session key for each message)
  - Each message is encrypted with AES, and the AES key is RSA-encrypted
- *Configuration*
  - All parameters stored in config.ini (IP, ports, keys, algorithm settings)

---

## 📦 Requirements

- *Qt 6.x* (tested with 6.9.2 on macOS)
- *Crypto++* library (compiled locally or installed via package manager)
- *C++17 compiler*

---

## ⚙️ Setup

### 1. Install Qt

Download and install Qt from [qt.io](https://www.qt.io/download-qt-installer). Make sure qmake points to your Qt 6 installation:

```bash
~/Qt/6.9.2/macos/bin/qmake --version
```

### 2. Build Crypto++

Clone and build:

```bash
git clone https://github.com/weidai11/cryptopp.git ~/cryptopp
cd ~/cryptopp
make -j$(nproc)
```

This creates `libcryptopp.a`.

### 3. Generate RSA Key Pairs

In each project copy:

```bash
cd keygen
clang++ -std=c++17 keygen.cpp -I~/cryptopp ~/cryptopp/libcryptopp.a -o keygen
./keygen 2048
```

This produces:
- `keys/my_private.der`
- `keys/my_public.der`

Exchange public keys:
- Copy `my_public.der` from Machine A → Machine B's `peer_public.der`
- Copy `my_public.der` from Machine B → Machine A's `peer_public.der`

---

## 📝 Configuration (config.ini)

All runtime parameters are stored in `config.ini`.

### A & B on the same hotspot (LAN)

If:
- Machine A IP = 172.20.10.3
- Machine B IP = 172.20.10.2

**Machine A:**
```ini
[network]
listen_ip=172.20.10.3
listen_port=6000
peer_ip=172.20.10.2
peer_port=6001
```

**Machine B:**
```ini
[network]
listen_ip=172.20.10.2
listen_port=6001
peer_ip=172.20.10.3
peer_port=6000
```

### A & B on different networks

Use port forwarding on one machine's router (server).

Or install a VPN (Tailscale / Zerotier) and use VPN IPs directly.

Example with port forwarding on Machine B:
- Router forwards `203.0.113.50:6001` → `172.20.10.2:6001`

**Machine B:**
```ini
listen_ip=0.0.0.0
listen_port=6001
```

**Machine A:**
```ini
peer_ip=203.0.113.50
peer_port=6001
```

---

## ▶️ Running

### Build the project

```bash
cd ~/Documents/CYBER
~/Qt/6.9.2/macos/bin/qmake cyber.pro
make -j$(sysctl -n hw.ncpu)
```

### Launch

```bash
./cyber.app/Contents/MacOS/cyber
```

### Start order

1. Start the server machine first (it listens).
2. Start the client and press Connect.

### Send messages

Once connected, the Send and Disconnect buttons are enabled.
Type in the input box → press Send → encrypted message is transmitted.

---

## 🛠️ Troubleshooting

**"Server listen failed: address not available"**
→ Use `0.0.0.0` for `listen_ip` or set it to a valid IP from `ifconfig`.

**"Connection refused"**
→ Ensure the peer is running and listening. Check port numbers match.

**Firewall issues (macOS)**

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ~/Documents/CYBER/cyber.app
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ~/Documents/CYBER/cyber.app
```

**Different networks**
→ Use Port Forwarding or a VPN (Tailscale recommended for quick setup).

---

## 📂 Project Structure

```
CYBER/
├── config.ini
├── cyber.pro
├── src/
│   ├── main.cpp
│   ├── mainwindow.h / mainwindow.cpp
│   ├── crypto_utils.h / crypto_utils.cpp
├── keygen/
│   ├── keygen.cpp
│   └── keys/
│       ├── my_private.der
│       ├── my_public.der
│       └── peer_public.der
└── cyber.app/Contents/MacOS/cyber   # built executable
```


