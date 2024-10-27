# Custom GSSAPI Mechanism with QKD-Based Session Key Integration

## Overview

This project implements a custom GSSAPI mechanism that integrates with OpenSSH to utilize session keys derived from Quantum Key Distribution (QKD) devices. The mechanism establishes a secure SSH connection using keys obtained from QKD devices, ensuring enhanced security through quantum-safe key exchange.

The session key forming mechanism involves a protocol where three 256-bit keys are retrieved from the QKD devices. Specific parts of these keys are used for mutual authentication and to form the session key for the SSH session.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Session Key Forming Mechanism](#session-key-forming-mechanism)
  - [Key Retrieval](#key-retrieval)
  - [First Message (Client to Server)](#first-message-client-to-server)
  - [Second Message (Server to Client)](#second-message-server-to-client)
  - [Session Key Formation](#session-key-formation)
- [Particularities](#particularities)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Quantum-Safe Key Exchange**: Utilizes keys from QKD devices to establish SSH sessions.
- **Custom GSSAPI Mechanism**: Implements a GSSAPI mechanism without modifying the OpenSSH codebase.
- **Mutual Authentication**: Verifies that both client and server have synchronized keys.
- **Secure Session Key Formation**: Derives the session key from verified key material.

## Prerequisites

- **Operating System**: Linux (e.g., Ubuntu, CentOS)
- **C Compiler**: GCC or Clang
- **GSSAPI Development Libraries and Headers**: e.g., MIT Kerberos or Heimdal
- **libcurl**: For HTTP communication with QKD devices
- **OpenSSH**: Version supporting GSSAPI (both client and server)
- **Access to QKD Devices**: With an HTTP API for key retrieval

## Build Instructions

### 1. Clone the Repository

```bash
git clone https://your-repo-url/qkd_gssapi.git
cd qkd_gssapi
```

### 2. Install Dependencies

For **Debian/Ubuntu**:

```bash
sudo apt-get update
sudo apt-get install libcurl4-openssl-dev libjson-c-dev libssl-dev uuid-dev
```

For **CentOS/RHEL**:

```bash
sudo yum groupinstall "Development Tools"
sudo yum install krb5-devel libcurl-devel
```

### 3. Build the Shared Library

Run the following command to compile the code into a shared library:

```bash
make
```

This command uses the provided `Makefile` to compile `qkd_gssapi.c` into `libgss_qkd.so`.

## Installation

### 1. Install the Shared Library

Copy the compiled shared library to a directory where the system can find it, such as `/usr/lib`:

```bash
sudo cp libgss_qkd.so /usr/lib/
```

### 2. Update GSSAPI Mechanism Configuration

Create or update the GSSAPI mechanism configuration file, typically located at `/etc/gss/mech` or `/etc/gssapi/mech`.

Add the following entry to register your mechanism:

```
qkd    1.3.6.1.4.1.12345.2    /usr/lib/libgss_qkd.so
```

Replace `1.3.6.1.4.1.12345.2` with the actual OID used in your implementation if different.

## Configuration

### 1. Configure OpenSSH Client

Edit the OpenSSH client configuration file `~/.ssh/config` or `/etc/ssh/ssh_config`:

```ini
Host *
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no
    GSSAPIKeyExchange yes
    GSSAPITrustDns no
    GSSAPIClientIdentity qkd
```

### 2. Configure OpenSSH Server

Edit the OpenSSH server configuration file `/etc/ssh/sshd_config`:

```ini
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
GSSAPIKeyExchange yes
GSSAPIStrictAcceptorCheck no
GSSAPIStoreCredentialsOnRekey no
```

Restart the SSH daemon:

```bash
sudo systemctl restart sshd
```

## Usage

Establish an SSH connection using your custom GSSAPI mechanism:

```bash
ssh -vvv user@server.com
```

The `-vvv` flag enables verbose output for debugging purposes.

## Session Key Forming Mechanism

### Overview

The session key forming mechanism ensures that both the client and server use synchronized keys from their respective QKD devices. The protocol involves exchanging encrypted messages that confirm key synchronization and ultimately derive a session key for the SSH session.

### Key Retrieval

- **Client and Server** each independently retrieve **three 256-bit keys** from their QKD devices:
  - **Key1**: 256 bits
  - **Key2**: 256 bits
  - **Key3**: 256 bits

### First Message (Client to Server)

1. **Client** takes the **first 128 bits of Key1** (`Key1[1-128]`).
2. **Client** encrypts `Key1[1-128]` using a One-Time Pad (OTP) with the **first 128 bits of Key2** (`Key2[1-128]`):
   - **Encryption**: `EM1 = Key1[1-128] ⊕ Key2[1-128]`
3. **Client** sends `EM1` along with the **Key IDs** for Key1, Key2, and Key3 to the **Server**.

### Second Message (Server to Client)

1. **Server** receives `EM1` and the Key IDs.
2. **Server** retrieves **Key1**, **Key2**, and **Key3** from its QKD device using the provided Key IDs.
3. **Server** decrypts `EM1` using `Key2[1-128]` to obtain `Key1[1-128]`:
   - **Decryption**: `Key1[1-128] = EM1 ⊕ Key2[1-128]`
4. **Server** verifies that `Key1[1-128]` matches its own `Key1[1-128]`.
5. **Server** encrypts the **next 128 bits of Key2** (`Key2[129-256]`) using an OTP with the **first 128 bits of Key3** (`Key3[1-128]`):
   - **Encryption**: `EM2 = Key2[129-256] ⊕ Key3[1-128]`
6. **Server** sends `EM2` back to the **Client**.

### Session Key Formation

1. **Client** receives `EM2`.
2. **Client** decrypts `EM2` using `Key3[1-128]` to obtain `Key2[129-256]`:
   - **Decryption**: `Key2[129-256] = EM2 ⊕ Key3[1-128]`
3. **Client** verifies that `Key2[129-256]` matches its own `Key2[129-256]`.
4. **Both Client and Server** form the **session key** by concatenating:
   - `SessionKey = Key1[129-256] || Key3[129-256]`
5. **SessionKey** is a 256-bit key used to secure the SSH session.

### Diagram

```
Client                                            Server
------                                            ------

Retrieve Key1, Key2, Key3                         Retrieve Key1, Key2, Key3

Compute EM1 = Key1[1-128] ⊕ Key2[1-128]
Send EM1, Key IDs to Server  ------------------>  

                                               Decrypt EM1:
                                               Key1[1-128] = EM1 ⊕ Key2[1-128]
                                               Verify Key1[1-128]

                                               Compute EM2 = Key2[129-256] ⊕ Key3[1-128]
                               <------------------  Send EM2 to Client

Decrypt EM2:
Key2[129-256] = EM2 ⊕ Key3[1-128]
Verify Key2[129-256]

Form SessionKey = Key1[129-256] || Key3[129-256]
                                               Form SessionKey = Key1[129-256] || Key3[129-256]
```

## Particularities

- **One-Time Pad (OTP)**: Encryption and decryption are performed using bitwise XOR operations, adhering to OTP principles.
- **Key Segments**: Keys are split into segments to ensure that each bit of key material is used only once.
- **Key IDs**: Key IDs are exchanged to retrieve the correct keys from the QKD devices.
- **Synchronization Verification**: The protocol verifies synchronization of all key segments used in the session key.
- **No Key Reuse**: Each key segment is used for a single purpose to maintain OTP security.

## Security Considerations

- **Key Material Protection**: Keys are securely handled in memory, and sensitive data is zeroized before being freed.
- **Desynchronization Detection**: The protocol detects any desynchronization of keys, preventing insecure connections.
- **Error Handling**: Meaningful error messages are provided without exposing sensitive information.

## Troubleshooting

- **Verbose Logging**: Use `ssh -vvv` to enable verbose logging and observe the authentication process.
- **Common Issues**:
  - **Key Synchronization Failed**: Indicates that the keys are desynchronized or incorrect keys were retrieved.
  - **Defective Token**: Suggests an issue with token serialization or deserialization.
  - **Mechanism Not Found**: Ensure that the GSSAPI mechanism configuration file is correctly updated.
- **Logs and Debugging**:
  - Check system logs and OpenSSH logs for additional information.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).

