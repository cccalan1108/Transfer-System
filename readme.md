


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

## 1. Project Overview

This project implements a secure third-party payment micropayment system for peer-to-peer transactions between users. The system consists of:

- **Client:** Handles user registration, login, account management, and peer-to-peer secure transfers
- **Server:** Multi-threaded server for user management, authentication, and account handling
- **Secure Communication:** All Client–Server and Client–Client communications are encrypted using OpenSSL

### Main Features

| Component | Functionality |
|-----------|---------------|
| **Client** | Register, login, request balance/online list, P2P transfer, notify logout |
| **Server** | Accept connections, user registration, authentication, account management, online list |
| **Security** | Encryption keys negotiated between communicating parties; OpenSSL for secure transmission |

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

安裝openssl

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
