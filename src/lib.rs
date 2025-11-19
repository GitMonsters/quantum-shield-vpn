//! QuantumShield VPN - Quantum-resistant VPN implementation
//!
//! Uses hybrid encryption combining:
//! - ML-KEM-1024 (Kyber) for post-quantum security
//! - X25519 for classical ECDH
//! - ChaCha20-Poly1305 for symmetric encryption

pub mod crypto;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Protocol version
pub const VERSION: u8 = 1;

/// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 65535;

/// VPN packet types
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    Handshake = 1,
    HandshakeResponse = 2,
    Data = 3,
    Keepalive = 4,
    Disconnect = 5,
}

/// VPN packet header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub sequence: u64,
    pub length: u32,
}

/// Handshake packet (client -> server)
#[derive(Clone, Serialize, Deserialize)]
pub struct HandshakePacket {
    pub client_public: crypto::HybridPublicKey,
    pub encapsulated: crypto::EncapsulatedKey,
    pub timestamp: u64,
}

/// Handshake response (server -> client)
#[derive(Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub success: bool,
    pub assigned_ip: [u8; 4],
    pub server_public: crypto::HybridPublicKey,
}

/// Parse packet from bytes
pub fn parse_packet(data: &[u8]) -> Result<(PacketHeader, &[u8])> {
    if data.len() < 14 {
        return Err(anyhow::anyhow!("Packet too short"));
    }

    let header: PacketHeader = bincode::deserialize(&data[..14])?;
    let payload = &data[14..];

    Ok((header, payload))
}

/// Build packet bytes
pub fn build_packet(packet_type: PacketType, sequence: u64, payload: &[u8]) -> Vec<u8> {
    let header = PacketHeader {
        version: VERSION,
        packet_type,
        sequence,
        length: payload.len() as u32,
    };

    let mut packet = bincode::serialize(&header).expect("Failed to serialize header");
    packet.extend_from_slice(payload);
    packet
}
