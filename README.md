# QuantumShield VPN

**Quantum-resistant VPN with post-quantum cryptography and TUN device support**

## Security Features

- **ML-KEM-1024 (Kyber)** - NIST-standardized post-quantum key encapsulation
- **X25519** - Classical ECDH for hybrid security
- **ChaCha20-Poly1305** - Authenticated encryption
- **BLAKE3** - Fast, secure key derivation

### Why Hybrid Encryption?

This VPN uses a **hybrid approach** combining both classical (X25519) and post-quantum (Kyber) cryptography:

1. **Future-proof**: Even if Kyber has undiscovered weaknesses, X25519 provides fallback security
2. **Backward security**: Even if quantum computers break X25519, Kyber protects past sessions
3. **Defense in depth**: An attacker must break BOTH algorithms

## Installation

```bash
cd /home/worm/quantum_shield_vpn
cargo build --release
```

Binaries are in `target/release/`:
- `qs-keygen` - Generate quantum-resistant keypairs
- `qs-server` - VPN server with TUN device
- `qs-client` - VPN client with TUN device

## Quick Start

### 1. Generate Keys

```bash
# Generate server keys
./target/release/qs-keygen --name qs_server --output keys/

# Generate client keys
./target/release/qs-keygen --name qs_client --output keys/
```

This creates:
- `keys/qs_server.pub` - Server public key (share with clients)
- `keys/qs_server.key` - Server secret key (keep secure!)
- `keys/qs_client.pub` - Client public key
- `keys/qs_client.key` - Client secret key (keep secure!)

### 2. Start Server (requires root)

```bash
sudo ./target/release/qs-server \
    --listen 0.0.0.0:51820 \
    --private-key keys/qs_server.key \
    --tun-ip 10.0.0.1
```

### 3. Connect Client (requires root)

Copy `qs_server.pub` to the client machine, then:

```bash
sudo ./target/release/qs-client \
    --server YOUR_SERVER_IP:51820 \
    --server-key keys/qs_server.pub \
    --private-key keys/qs_client.key
```

The client will:
1. Perform quantum-resistant handshake
2. Receive assigned IP (e.g., 10.0.0.2)
3. Create TUN device with that IP
4. Route traffic through encrypted tunnel

## Server Options

```
--listen         Listen address (default: 0.0.0.0:51820)
--private-key    Server private key file
--tun-ip         TUN device IP (default: 10.0.0.1)
--tun-netmask    TUN netmask (default: 255.255.255.0)
--mtu            MTU size (default: 1400)
```

## Client Options

```
--server         Server address (required)
--server-key     Server public key file
--private-key    Client private key file
--mtu            MTU size (default: 1400)
```

## Protocol Overview

```
Client                                    Server
  |                                          |
  |  1. Generate ephemeral X25519 keypair    |
  |  2. Encapsulate with Kyber               |
  |                                          |
  |  -------- Handshake Packet ----------->  |
  |   [Client Kyber PK]                      |
  |   [X25519 Ephemeral PK]                  |
  |   [Kyber Ciphertext]                     |
  |                                          |
  |                                          |  3. Decapsulate Kyber
  |                                          |  4. X25519 ECDH
  |                                          |  5. Derive session keys
  |                                          |
  |  <------- Handshake Response ---------   |
  |   [Assigned IP]                          |
  |   [Server PK]                            |
  |                                          |
  |  ========== Encrypted Tunnel =========   |
  |  ChaCha20-Poly1305 with derived keys     |
  |  IP packets through TUN device           |
  |                                          |
```

## Key Sizes

| Component | Size |
|-----------|------|
| Kyber-1024 Public Key | 1,568 bytes |
| Kyber-1024 Secret Key | 3,168 bytes |
| Kyber-1024 Ciphertext | 1,568 bytes |
| X25519 Public Key | 32 bytes |
| X25519 Secret Key | 32 bytes |
| Combined Shared Secret | 64 bytes |
| Session Keys | 32 bytes each |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux | Full support with TUN device |
| macOS | Full support with TUN device |
| iOS | Requires NetworkExtension app |
| Windows | Not yet implemented |

## Security Considerations

1. **Keep secret keys secure** - They have 0600 permissions by default
2. **Verify server fingerprints** - Displayed on connection
3. **No hardcoded passwords** - Unlike vulnerable VPNs
4. **No deprecated ciphers** - Uses modern, audited algorithms
5. **Perfect forward secrecy** - Each session derives new keys
6. **Run as root** - Required for TUN device creation

## Development

Run tests:
```bash
cargo test
```

Build debug version:
```bash
cargo build
```

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (Kyber) Specification](https://pq-crystals.org/kyber/)
- [ChaCha20-Poly1305 RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
- [X25519 RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)

## License

MIT License
