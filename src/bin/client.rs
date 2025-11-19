//! QuantumShield VPN Client

use anyhow::{anyhow, Result};
use clap::Parser;
use quantum_shield_vpn::crypto::{self, HybridKeypair, SessionKeys};
use quantum_shield_vpn::{
    build_packet, parse_packet, HandshakePacket, HandshakeResponse, PacketType,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "qs-client")]
#[command(about = "QuantumShield VPN Client - Quantum-resistant security")]
struct Args {
    /// Server address
    #[arg(short, long)]
    server: String,

    /// Server public key file
    #[arg(long, default_value = "quantum_shield_server.pub")]
    server_key: PathBuf,

    /// Client public key file
    #[arg(long, default_value = "quantum_shield_client.pub")]
    public_key: PathBuf,

    /// Client secret key file
    #[arg(long, default_value = "quantum_shield_client.key")]
    secret_key: PathBuf,
}

struct Client {
    socket: UdpSocket,
    keypair: HybridKeypair,
    server_public: crypto::HybridPublicKey,
    session_keys: RwLock<Option<SessionKeys>>,
    assigned_ip: RwLock<Option<[u8; 4]>>,
    tx_sequence: AtomicU64,
}

impl Client {
    async fn new(
        server_addr: &str,
        keypair: HybridKeypair,
        server_public: crypto::HybridPublicKey,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server_addr).await?;

        info!("Connected to server: {}", server_addr);

        Ok(Client {
            socket,
            keypair,
            server_public,
            session_keys: RwLock::new(None),
            assigned_ip: RwLock::new(None),
            tx_sequence: AtomicU64::new(1),
        })
    }

    async fn handshake(&self) -> Result<()> {
        info!("Initiating quantum-resistant handshake...");

        // Perform key encapsulation
        let (encapsulated, shared_secret) = crypto::encapsulate(&self.server_public)?;

        // Derive session keys (client is initiator)
        let session_keys = crypto::derive_session_keys(&shared_secret, true);

        // Build handshake packet
        let handshake = HandshakePacket {
            client_public: self.keypair.public.clone(),
            encapsulated,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let handshake_bytes = bincode::serialize(&handshake)?;
        let packet = build_packet(PacketType::Handshake, 0, &handshake_bytes);

        // Send handshake
        self.socket.send(&packet).await?;
        info!("Sent handshake packet ({} bytes)", packet.len());

        // Receive response
        let mut buf = vec![0u8; 65535];
        let len = self.socket.recv(&mut buf).await?;
        let (header, payload) = parse_packet(&buf[..len])?;

        match header.packet_type {
            PacketType::HandshakeResponse => {
                let response: HandshakeResponse = bincode::deserialize(payload)?;

                if response.success {
                    // Store session keys
                    *self.session_keys.write().await = Some(session_keys);
                    *self.assigned_ip.write().await = Some(response.assigned_ip);

                    info!(
                        "Handshake successful! Assigned IP: {}.{}.{}.{}",
                        response.assigned_ip[0],
                        response.assigned_ip[1],
                        response.assigned_ip[2],
                        response.assigned_ip[3]
                    );

                    Ok(())
                } else {
                    Err(anyhow!("Handshake failed: server rejected"))
                }
            }
            _ => Err(anyhow!("Unexpected response type")),
        }
    }

    async fn send_data(&self, data: &[u8]) -> Result<()> {
        let session_keys = self.session_keys.read().await;
        let keys = session_keys
            .as_ref()
            .ok_or_else(|| anyhow!("No active session"))?;

        let sequence = self.tx_sequence.fetch_add(1, Ordering::SeqCst);

        // Encrypt data
        let encrypted = crypto::encrypt(&keys.encrypt_key, sequence, data)?;

        // Build and send packet
        let packet = build_packet(PacketType::Data, sequence, &encrypted);
        self.socket.send(&packet).await?;

        Ok(())
    }

    async fn run(&self) -> Result<()> {
        // Perform handshake
        self.handshake().await?;

        // Main loop - receive packets
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = self.socket.recv(&mut buf) => {
                    match result {
                        Ok(len) => {
                            if let Err(e) = self.handle_packet(&buf[..len]).await {
                                warn!("Error handling packet: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Socket error: {}", e);
                            break;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutting down...");
                    self.disconnect().await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_packet(&self, data: &[u8]) -> Result<()> {
        let (header, payload) = parse_packet(data)?;

        match header.packet_type {
            PacketType::Data => {
                let session_keys = self.session_keys.read().await;
                let keys = session_keys
                    .as_ref()
                    .ok_or_else(|| anyhow!("No active session"))?;

                // Decrypt payload
                let decrypted = crypto::decrypt(&keys.decrypt_key, header.sequence, payload)?;

                // Here you would write to the TUN interface
                info!(
                    "Received {} bytes of data (seq: {})",
                    decrypted.len(),
                    header.sequence
                );
            }
            PacketType::Keepalive => {
                // Respond with keepalive
                let packet = build_packet(PacketType::Keepalive, 0, &[]);
                self.socket.send(&packet).await?;
            }
            _ => {
                warn!("Unexpected packet type");
            }
        }

        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        let packet = build_packet(PacketType::Disconnect, 0, &[]);
        self.socket.send(&packet).await?;
        info!("Sent disconnect packet");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║         QuantumShield VPN Client v1.0                      ║");
    println!("║   Quantum-Resistant: ML-KEM-1024 + X25519 Hybrid          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Load client keypair
    let public_bytes = base64::decode(fs::read_to_string(&args.public_key)?)?;
    let secret_bytes = base64::decode(fs::read_to_string(&args.secret_key)?)?;
    let keypair = HybridKeypair::from_bytes(&public_bytes, &secret_bytes)?;

    info!("Loaded client keypair");

    // Load server public key
    let server_public_bytes = base64::decode(fs::read_to_string(&args.server_key)?)?;
    let server_public: crypto::HybridPublicKey = bincode::deserialize(&server_public_bytes)?;

    info!("Loaded server public key");
    info!("Server fingerprint: {}", {
        let hash = blake3::hash(&server_public_bytes);
        hex::encode(&hash.as_bytes()[..16])
    });

    // Create and run client
    let client = Arc::new(Client::new(&args.server, keypair, server_public).await?);

    info!("Starting quantum-resistant VPN connection...");

    client.run().await
}
