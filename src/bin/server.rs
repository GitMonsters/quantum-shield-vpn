//! QuantumShield VPN Server

use anyhow::{anyhow, Result};
use clap::Parser;
use quantum_shield_vpn::crypto::{self, HybridKeypair, SessionKeys};
use quantum_shield_vpn::{
    build_packet, parse_packet, HandshakePacket, HandshakeResponse, PacketType,
};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "qs-server")]
#[command(about = "QuantumShield VPN Server - Quantum-resistant security")]
struct Args {
    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:51820")]
    listen: String,

    /// Server public key file
    #[arg(long, default_value = "quantum_shield_server.pub")]
    public_key: PathBuf,

    /// Server secret key file
    #[arg(long, default_value = "quantum_shield_server.key")]
    secret_key: PathBuf,

    /// VPN subnet (e.g., 10.0.0.0/24)
    #[arg(long, default_value = "10.0.0.0/24")]
    subnet: String,
}

struct ClientSession {
    session_keys: SessionKeys,
    assigned_ip: [u8; 4],
    last_seen: std::time::Instant,
    rx_sequence: u64,
    tx_sequence: u64,
}

struct Server {
    socket: UdpSocket,
    keypair: HybridKeypair,
    sessions: RwLock<HashMap<SocketAddr, ClientSession>>,
    next_ip: RwLock<u8>,
}

impl Server {
    async fn new(listen_addr: &str, keypair: HybridKeypair) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Server listening on {}", listen_addr);

        Ok(Server {
            socket,
            keypair,
            sessions: RwLock::new(HashMap::new()),
            next_ip: RwLock::new(2), // Start at .2
        })
    }

    async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, addr) = self.socket.recv_from(&mut buf).await?;
            let data = &buf[..len];

            if let Err(e) = self.handle_packet(addr, data).await {
                warn!("Error handling packet from {}: {}", addr, e);
            }
        }
    }

    async fn handle_packet(&self, addr: SocketAddr, data: &[u8]) -> Result<()> {
        let (header, payload) = parse_packet(data)?;

        match header.packet_type {
            PacketType::Handshake => {
                self.handle_handshake(addr, payload).await?;
            }
            PacketType::Data => {
                self.handle_data(addr, header.sequence, payload).await?;
            }
            PacketType::Keepalive => {
                self.handle_keepalive(addr).await?;
            }
            PacketType::Disconnect => {
                self.handle_disconnect(addr).await?;
            }
            _ => {
                warn!("Unknown packet type from {}", addr);
            }
        }

        Ok(())
    }

    async fn handle_handshake(&self, addr: SocketAddr, payload: &[u8]) -> Result<()> {
        info!("Handshake from {}", addr);

        let handshake: HandshakePacket = bincode::deserialize(payload)?;

        // Perform quantum-resistant key exchange
        let shared_secret = crypto::decapsulate(&handshake.encapsulated, &self.keypair.secret)?;

        // Derive session keys (server is not initiator)
        let session_keys = crypto::derive_session_keys(&shared_secret, false);

        // Assign IP address
        let mut next_ip = self.next_ip.write().await;
        let assigned_ip = [10, 0, 0, *next_ip];
        *next_ip = next_ip.wrapping_add(1);
        if *next_ip == 0 || *next_ip == 1 {
            *next_ip = 2;
        }

        // Create session
        let session = ClientSession {
            session_keys,
            assigned_ip,
            last_seen: std::time::Instant::now(),
            rx_sequence: 0,
            tx_sequence: 0,
        };

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(addr, session);
        }

        // Send response
        let response = HandshakeResponse {
            success: true,
            assigned_ip,
            server_public: self.keypair.public.clone(),
        };

        let response_bytes = bincode::serialize(&response)?;
        let packet = build_packet(PacketType::HandshakeResponse, 0, &response_bytes);

        self.socket.send_to(&packet, addr).await?;

        info!(
            "Client {} connected, assigned IP {}.{}.{}.{}",
            addr, assigned_ip[0], assigned_ip[1], assigned_ip[2], assigned_ip[3]
        );

        Ok(())
    }

    async fn handle_data(&self, addr: SocketAddr, sequence: u64, payload: &[u8]) -> Result<()> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&addr)
            .ok_or_else(|| anyhow!("Unknown client"))?;

        // Decrypt payload
        let decrypted = crypto::decrypt(&session.session_keys.decrypt_key, sequence, payload)?;

        // Here you would forward the decrypted packet to the TUN interface
        // For now, just log it
        info!(
            "Received {} bytes of encrypted data from {} (seq: {})",
            decrypted.len(),
            addr,
            sequence
        );

        Ok(())
    }

    async fn handle_keepalive(&self, addr: SocketAddr) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&addr) {
            session.last_seen = std::time::Instant::now();
        }
        Ok(())
    }

    async fn handle_disconnect(&self, addr: SocketAddr) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(&addr).is_some() {
            info!("Client {} disconnected", addr);
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║         QuantumShield VPN Server v1.0                      ║");
    println!("║   Quantum-Resistant: ML-KEM-1024 + X25519 Hybrid          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Load keypair
    let public_bytes = base64::decode(fs::read_to_string(&args.public_key)?)?;
    let secret_bytes = base64::decode(fs::read_to_string(&args.secret_key)?)?;
    let keypair = HybridKeypair::from_bytes(&public_bytes, &secret_bytes)?;

    info!("Loaded server keypair");
    info!("Public key fingerprint: {}", {
        let hash = blake3::hash(&public_bytes);
        hex::encode(&hash.as_bytes()[..16])
    });

    // Create and run server
    let server = Arc::new(Server::new(&args.listen, keypair).await?);

    info!("Server started with quantum-resistant encryption");
    info!("VPN subnet: {}", args.subnet);

    server.run().await
}
