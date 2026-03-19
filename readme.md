


# A Secure Person-to-Person (P2P) Micropayment System

## Quick Start

### Step 0. Install OpenSSL

**Ubuntu/Debian:**
```bash
sudo apt-get install openssl libssl-dev
```

**macOS:**
```bash
brew install openssl
```

### Step 1. Compile

```bash
g++ server.cpp -o server -lssl -lcrypto -pthread
g++ client.cpp -o client -lssl -lcrypto
```

### Step 2. Execute

```bash
./server
./client
```

---

## 1. Project Overview | 專案概述

### Overview | 系統簡介

This project implements a **secure third-party payment micropayment system** for peer-to-peer (P2P) transactions between users. The system follows a client–server architecture: a central server manages user accounts and authentication, while clients communicate directly with each other for transfers without relaying payment messages through the server. All communication—between clients and the server, and between clients—is encrypted. Encryption keys are negotiated between the two parties in each connection.

本專案實作一套**安全的第三方支付人際小額付款系統**，供使用者之間進行 P2P 轉帳。系統採用 Client–Server 架構：中央伺服器負責帳戶管理與認證，Client 之間則直接建立連線進行轉帳，不經由 Server 轉送付款訊息。Client 與 Server、Client 與 Client 之間的通訊皆經加密，每次連線時由通訊雙方協商加密金鑰。

### System Components | 系統元件

| Component<br>元件 | English Description | 中文說明 |
|------------------|---------------------|----------|
| **Client** | A user-facing application that handles registration, login, account balance queries, online user list, and direct P2P transfers. Clients connect to the server for authentication and account updates, but perform transfers peer-to-peer. | 使用者端程式，負責註冊、登入、查詢餘額、取得線上清單，以及與其他 Client 直接進行轉帳。Client 連線至 Server 進行認證與帳戶更新，但轉帳時由雙方 Client 直接通訊。 |
| **Server** | A multi-threaded server that accepts multiple client connections concurrently. It manages user registration, login, account balances, and the online user list. Each client connection is handled by a separate thread. Server does not relay messages between clients. | 多執行緒伺服器，可同時接受多個 Client 連線。負責使用者註冊、登入、帳戶餘額管理及線上清單維護。每個連線由獨立 thread 處理。Server 不替 Client 轉送訊息。 |
| **Secure Communication** | All communication uses OpenSSL for encryption. The encryption key (secret key) is negotiated between the two communicating parties. Client–Server and Client–Client channels are encrypted separately. | 所有通訊使用 OpenSSL 加密。加密金鑰由通訊雙方協定。Client–Server 與 Client–Client 的通道各自加密。 |

### Main Features | 主要功能

| Component<br>元件 | Functionality<br>功能 |
|------------------|----------------------|
| **Client** | Register, login, request balance/online list/public key, P2P transfer (direct), notify logout before exiting |
| **Client** | 註冊、登入、請求餘額／線上清單／公鑰、P2P 轉帳（直接連線）、離開前通知 Server |
| **Server** | Accept connections, user registration, authentication, send balance/online list/public key, receive logout notification |
| **Server** | 接受連線、使用者註冊、認證、回傳餘額／線上清單／公鑰、接收離線通知 |
| **Security** | Encryption keys negotiated per connection; OpenSSL for TLS/SSL |
| **安全** | 每次連線協商金鑰；使用 OpenSSL 進行加解密 |

---

## 2. System Requirements

- **OS:** Linux (kernel 2.6.x or later) / Unix
- **Language:** C/C++ with Unix/Linux Socket Programming
- **Libraries:** OpenSSL
- **Protocol:** TCP

### OpenSSL Installation

**Ubuntu/Debian:**
```bash
sudo apt-get install openssl
sudo apt-get install libssl-dev
```

**macOS:**
```bash
brew install openssl
```

---

## 3. Project Structure

```
Transfer-System-main/
├── client.cpp          # Client source code
├── server.cpp          # Server source code
├── Makefile            # Build configuration
├── client               # Compiled client executable
├── server               # Compiled server executable
└── README.md           # This file
```

---

## 4. Build Instructions

### Compile

```bash
make
```

Or compile manually:

```bash
g++ -o client client.cpp -lssl -lcrypto -lpthread
g++ -o server server.cpp -lssl -lcrypto -lpthread
```

### Clean Build

```bash
make clean
```

---

## 5. Execution

### Start the Server

```bash
./server <portNum> <Option>
```

- **portNum:** Port number (1024–65535)
- **Option:**
  - `-d`: Simple messages (register, login, logout)
  - `-s`: Above + online list on each login/logout
  - `-a`: Above + full message logging (for debugging)

**Example:**
```bash
./server 12345 -s
```

### Start the Client

1. Run the client executable
2. Enter **username** when prompted (for registration)
3. Enter **Server IP** and **Port** when logging in
4. Enter your **listening port** for P2P communication

---

## 6. Communication Protocol

### Client → Server Messages

| Action | Message Format | Server Response |
|--------|----------------|-----------------|
| Register | `REGISTER#<UserAccountName>` | `100 OK` or `210 FAIL` |
| Login | `<UserAccountName>#<portNum>` | Online list or `220 AUTH_FAIL` |
| Get List | `List` | Account balance, public key, online users |
| Logout | `Exit` | `Bye` |

### Online List Format (Server → Client)

```
<accountBalance><CRLF>
<serverPublicKey><CRLF>
<number of accounts online><CRLF>
<userAccount1>#<IP>#<portNum><CRLF>
<userAccount2>#<IP>#<portNum><CRLF>
...
```

### P2P Transfer (Client → Client → Server)

1. **Client A → Client B:** `<MyUserAccountName>#<payAmount>#<PayeeUserAccountName>` (encrypted with B's public key)
2. **Client B** decrypts, confirms, re-encrypts with Server's public key, sends to Server
3. **Server** decrypts, updates both account balances

**Note:** Server does not relay messages between clients.

---

## 7. Default Settings

- **Initial account balance:** 10,000 (per user upon registration)

---

## 8. Development Phases

| Phase | Content | Deadline |
|-------|---------|----------|
| Part 1 | Client-only (test with TA's Server) | Nov 17, 2024 |
| Part 2 | Multi-threaded Server | Dec 1, 2024 |
| Part 3 | Secure transmission (OpenSSL) | Dec 22, 2024 |

---

## 9. References

- [OpenSSL Official Website](https://www.openssl.org/)
- Unix/Linux Socket Programming
- Course lecture slides and assignment handout
