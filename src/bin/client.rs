//! QuantumShield VPN Client with TUN support

use anyhow::{anyhow, Result};
use clap::Parser;
use quantum_shield_vpn::crypto::{self, HybridKeypair, SessionKeys};
use quantum_shield_vpn::tun_device::TunDevice;
use quantum_shield_vpn::{
    build_packet, parse_packet, HandshakePacket, HandshakeResponse, PacketType,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "qs-client")]
#[command(about = "QuantumShield VPN Client - Quantum-resistant security")]
struct Args {
    /// Server address
    #[arg(short, long)]
    server: String,

    /// Server public key file
    #[arg(long, default_value = "keys/qs_server.pub")]
    server_key: PathBuf,

    /// Client secret key file
    #[arg(long, default_value = "keys/qs_client.key")]
    private_key: PathBuf,

    /// MTU size
    #[arg(long, default_value = "1400")]
    mtu: i32,
}

struct Client {
    socket: Arc<UdpSocket>,
    keypair: HybridKeypair,
    server_public: crypto::HybridPublicKey,
    session_keys: Arc<RwLock<Option<SessionKeys>>>,
    assigned_ip: Arc<RwLock<Option<[u8; 4]>>>,
    tx_sequence: AtomicU64,
    tun_tx: mpsc::Sender<Vec<u8>>,
}

impl Client {
    async fn new(
        server_addr: &str,
        keypair: HybridKeypair,
        server_public: crypto::HybridPublicKey,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(server_addr).await?;

        info!("Connected to server: {}", server_addr);

        Ok(Client {
            socket,
            keypair,
            server_public,
            session_keys: Arc::new(RwLock::new(None)),
            assigned_ip: Arc::new(RwLock::new(None)),
            tx_sequence: AtomicU64::new(1),
            tun_tx,
        })
    }

    async fn handshake(&self) -> Result<[u8; 4]> {
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

                    Ok(response.assigned_ip)
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

    async fn run_socket_handler(self: Arc<Self>) -> Result<()> {
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

                // Decrypt payload (IP packet from server)
                let decrypted = crypto::decrypt(&keys.decrypt_key, header.sequence, payload)?;

                // Send to TUN device
                self.tun_tx.send(decrypted).await?;
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
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║         QuantumShield VPN Client v1.0                      ║");
    println!("║   Quantum-Resistant: ML-KEM-1024 + X25519 Hybrid          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Load client keypair
    let secret_bytes = base64::decode(fs::read_to_string(&args.private_key)?.trim())?;
    let keypair = HybridKeypair::from_secret_bytes(&secret_bytes)?;

    info!("Loaded client keypair");
    info!("Client fingerprint: {}", {
        let public_bytes = keypair.public.to_bytes();
        let hash = blake3::hash(&public_bytes);
        hex::encode(&hash.as_bytes()[..8])
    });

    // Load server public key
    let server_public_bytes = base64::decode(fs::read_to_string(&args.server_key)?.trim())?;
    let server_public: crypto::HybridPublicKey = bincode::deserialize(&server_public_bytes)?;

    info!("Loaded server public key");
    info!("Server fingerprint: {}", {
        let hash = blake3::hash(&server_public_bytes);
        hex::encode(&hash.as_bytes()[..8])
    });

    // Channel for TUN packets
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(1000);

    // Create client
    let client = Arc::new(
        Client::new(&args.server, keypair, server_public, tun_tx).await?,
    );

    info!("Starting quantum-resistant VPN connection...");

    // Perform handshake to get assigned IP
    let assigned_ip = client.handshake().await?;
    let tun_ip = format!(
        "{}.{}.{}.{}",
        assigned_ip[0], assigned_ip[1], assigned_ip[2], assigned_ip[3]
    );

    // Create TUN device with assigned IP
    info!("Creating TUN device with IP {}...", tun_ip);
    let mut tun = TunDevice::new(&tun_ip, "255.255.255.0", args.mtu)?;
    info!("TUN device {} created", tun.name());

    // Spawn socket handler
    let client_clone = Arc::clone(&client);
    let socket_handle = tokio::spawn(async move {
        if let Err(e) = client_clone.run_socket_handler().await {
            error!("Socket handler error: {}", e);
        }
    });

    // Spawn TUN reader (reads from TUN, sends to server)
    let client_clone = Arc::clone(&client);
    let tun_read_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun.read_packet(&mut buf) {
                Ok(len) => {
                    if len > 0 {
                        if let Err(e) = client_clone.send_data(&buf[..len]).await {
                            warn!("Failed to send data: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("TUN read error: {}", e);
                    break;
                }
            }
        }
    });

    // Spawn TUN writer (receives from channel, writes to TUN)
    let tun_write_handle = tokio::spawn(async move {
        let mut tun_write = TunDevice::new(&tun_ip, "255.255.255.0", args.mtu)
            .expect("Failed to open TUN for writing");

        while let Some(packet) = tun_rx.recv().await {
            if let Err(e) = tun_write.write_packet(&packet) {
                error!("TUN write error: {}", e);
            }
        }
    });

    // Wait for tasks
    tokio::select! {
        _ = socket_handle => {}
        _ = tun_read_handle => {}
        _ = tun_write_handle => {}
    }

    Ok(())
}
