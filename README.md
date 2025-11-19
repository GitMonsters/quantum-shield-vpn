# QuantumShield VPN

**Quantum-resistant VPN with post-quantum cryptography**

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
- `qs-server` - VPN server
- `qs-client` - VPN client

## Quick Start

### 1. Generate Keys

```bash
# Generate server keys
./target/release/qs-keygen --server --output ./keys --name quantum_shield

# Generate client keys
./target/release/qs-keygen --client --output ./keys --name quantum_shield
```

This creates:
- `keys/quantum_shield_server.pub` - Server public key
- `keys/quantum_shield_server.key` - Server secret key (keep secure!)
- `keys/quantum_shield_client.pub` - Client public key
- `keys/quantum_shield_client.key` - Client secret key (keep secure!)

### 2. Start Server

```bash
./target/release/qs-server \
    --listen 0.0.0.0:51820 \
    --public-key keys/quantum_shield_server.pub \
    --secret-key keys/quantum_shield_server.key \
    --subnet 10.0.0.0/24
```

### 3. Connect Client

Copy `quantum_shield_server.pub` to the client machine, then:

```bash
./target/release/qs-client \
    --server YOUR_SERVER_IP:51820 \
    --server-key keys/quantum_shield_server.pub \
    --public-key keys/quantum_shield_client.pub \
    --secret-key keys/quantum_shield_client.key
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

## Security Considerations

1. **Keep secret keys secure** - They have 0600 permissions by default
2. **Verify server fingerprints** - Displayed on connection
3. **No hardcoded passwords** - Unlike the vulnerable VPNs in the research paper
4. **No deprecated ciphers** - Uses modern, audited algorithms
5. **Perfect forward secrecy** - Each session derives new keys

## Comparison with Vulnerable VPNs

| Feature | QuantumShield | Turbo VPN, etc. |
|---------|---------------|-----------------|
| Key Exchange | ML-KEM + X25519 | Hard-coded Shadowsocks |
| Encryption | ChaCha20-Poly1305 | RC4-MD5 (deprecated) |
| Passwords | Unique per connection | Hard-coded, shared |
| Quantum-safe | Yes | No |
| Traffic decryptable | No | Yes, by anyone |

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
