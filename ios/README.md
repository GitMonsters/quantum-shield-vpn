# QuantumShield VPN - iOS App

Quantum-resistant VPN client for iOS using NetworkExtension framework.

## Requirements

- macOS with Xcode 15+
- Apple Developer Account (required for NetworkExtension entitlements)
- iOS 15.0+ device (simulator won't work for VPN testing)

## Setup

### 1. Create Xcode Project

1. Open Xcode
2. File → New → Project
3. Select "App" under iOS
4. Product Name: `QuantumShieldVPN`
5. Bundle Identifier: `com.quantumshield.vpn`
6. Interface: SwiftUI
7. Language: Swift

### 2. Add Network Extension Target

1. File → New → Target
2. Select "Network Extension" under iOS
3. Product Name: `PacketTunnelProvider`
4. Provider Type: Packet Tunnel
5. Bundle Identifier: `com.quantumshield.vpn.tunnel`

### 3. Configure Entitlements

Both targets need Network Extension entitlements:

1. Select project in navigator
2. Select each target
3. Signing & Capabilities → + Capability
4. Add "Network Extensions"
5. Check "Packet Tunnel"
6. Add "App Groups" → `group.com.quantumshield.vpn`
7. Add "Keychain Sharing" → `com.quantumshield.vpn`

### 4. Add Source Files

Copy files from this directory:

**Main App:**
- `QuantumShieldVPN/QuantumShieldVPNApp.swift`
- `QuantumShieldVPN/Info.plist`
- `QuantumShieldVPN/QuantumShieldVPN.entitlements`

**Extension:**
- `PacketTunnelProvider/PacketTunnelProvider.swift`
- `PacketTunnelProvider/Info.plist`
- `PacketTunnelProvider/PacketTunnelProvider.entitlements`

### 5. Add Crypto Libraries

The app needs post-quantum crypto libraries:

#### Option A: liboqs-swift (Recommended)

```swift
// Package.swift dependency
.package(url: "https://github.com/nickcrafford/liboqs-swift", from: "1.0.0")
```

#### Option B: Bridge Rust Code

1. Build Rust crypto as static library with `cargo-lipo`
2. Create bridging header
3. Import functions

### 6. Configure Provisioning

1. Go to developer.apple.com
2. Identifiers → App IDs → Create both:
   - `com.quantumshield.vpn`
   - `com.quantumshield.vpn.tunnel`
3. Enable Network Extension capability for both
4. Certificates → Create distribution certificate
5. Profiles → Create provisioning profiles

## Building

```bash
# Open project
open QuantumShieldVPN.xcodeproj

# Build for device (simulator won't work)
# Select your device and press Cmd+B
```

## Testing

1. Run on physical iOS device
2. Configure server address in settings
3. Import server public key
4. Import client private key
5. Tap Connect

## Architecture

```
┌─────────────────────────┐
│   QuantumShieldVPN App  │
│  ┌───────────────────┐  │
│  │    SwiftUI UI     │  │
│  │  - Settings       │  │
│  │  - VPNManager     │  │
│  └───────────────────┘  │
└────────────┬────────────┘
             │
             │ NETunnelProviderManager
             │
┌────────────▼────────────┐
│  PacketTunnelProvider   │
│  ┌───────────────────┐  │
│  │  VPNSession       │  │
│  │  - ML-KEM-1024    │  │
│  │  - X25519         │  │
│  │  - ChaCha20       │  │
│  └───────────────────┘  │
└────────────┬────────────┘
             │
             │ UDP Socket
             │
┌────────────▼────────────┐
│   QuantumShield Server  │
└─────────────────────────┘
```

## Files

```
ios/
├── README.md
└── QuantumShieldVPN/
    ├── QuantumShieldVPN/
    │   ├── QuantumShieldVPNApp.swift    # Main app + UI
    │   ├── Info.plist
    │   └── QuantumShieldVPN.entitlements
    └── PacketTunnelProvider/
        ├── PacketTunnelProvider.swift   # VPN tunnel implementation
        ├── Info.plist
        └── PacketTunnelProvider.entitlements
```

## Crypto Implementation Status

The Swift code includes placeholder implementations for:

- [ ] ML-KEM-1024 (Kyber) key encapsulation
- [ ] X25519 ECDH
- [ ] ChaCha20-Poly1305 encryption
- [ ] BLAKE3 key derivation

### TODO: Implement with CryptoKit + liboqs

```swift
// ChaCha20-Poly1305 (use CryptoKit)
import CryptoKit

func encrypt(key: SymmetricKey, nonce: Data, plaintext: Data) throws -> Data {
    let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: ChaChaPoly.Nonce(data: nonce))
    return sealedBox.combined
}

// ML-KEM-1024 (use liboqs-swift)
import liboqs

func kyberEncapsulate(publicKey: Data) -> (ciphertext: Data, sharedSecret: Data) {
    let kem = KEM(name: "Kyber1024")
    return kem.encapsulate(publicKey: publicKey)
}
```

## Security Notes

1. Store keys in iOS Keychain, not UserDefaults
2. Use app groups to share keys with extension
3. Validate server certificate/fingerprint
4. Clear sensitive data from memory after use

## License

MIT License
