//! QuantumShield VPN Server with TUN support

use anyhow::{anyhow, Result};
use clap::Parser;
use quantum_shield_vpn::crypto::{self, HybridKeypair, SessionKeys};
use quantum_shield_vpn::tun_device::TunDevice;
use quantum_shield_vpn::{
    build_packet, parse_packet, HandshakePacket, HandshakeResponse, PacketType,
};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "qs-server")]
#[command(about = "QuantumShield VPN Server - Quantum-resistant security")]
struct Args {
    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:51820")]
    listen: String,

    /// Server secret key file
    #[arg(long, default_value = "keys/qs_server.key")]
    private_key: PathBuf,

    /// TUN device IP address
    #[arg(long, default_value = "10.0.0.1")]
    tun_ip: String,

    /// TUN netmask
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: String,

    /// MTU size
    #[arg(long, default_value = "1400")]
    mtu: i32,
}

struct ClientSession {
    session_keys: SessionKeys,
    assigned_ip: [u8; 4],
    last_seen: std::time::Instant,
    tx_sequence: u64,
}

struct Server {
    socket: Arc<UdpSocket>,
    keypair: HybridKeypair,
    sessions: Arc<RwLock<HashMap<SocketAddr, ClientSession>>>,
    ip_to_addr: Arc<RwLock<HashMap<[u8; 4], SocketAddr>>>,
    next_ip: RwLock<u8>,
    tun_tx: mpsc::Sender<Vec<u8>>,
}

impl Server {
    async fn new(
        listen_addr: &str,
        keypair: HybridKeypair,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        info!("Server listening on {}", listen_addr);

        Ok(Server {
            socket,
            keypair,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ip_to_addr: Arc::new(RwLock::new(HashMap::new())),
            next_ip: RwLock::new(2),
            tun_tx,
        })
    }

    async fn run_socket_handler(self: Arc<Self>) -> Result<()> {
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
            tx_sequence: 0,
        };

        // Store session and IP mapping
        {
            let mut sessions = self.sessions.write().await;
            let mut ip_to_addr = self.ip_to_addr.write().await;
            sessions.insert(addr, session);
            ip_to_addr.insert(assigned_ip, addr);
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

        // Decrypt payload (IP packet from client)
        let decrypted = crypto::decrypt(&session.session_keys.decrypt_key, sequence, payload)?;

        // Send to TUN device
        self.tun_tx.send(decrypted).await?;

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
        let mut ip_to_addr = self.ip_to_addr.write().await;

        if let Some(session) = sessions.remove(&addr) {
            ip_to_addr.remove(&session.assigned_ip);
            info!("Client {} disconnected", addr);
        }
        Ok(())
    }

    async fn send_to_client(&self, dest_ip: [u8; 4], data: &[u8]) -> Result<()> {
        let ip_to_addr = self.ip_to_addr.read().await;
        let mut sessions = self.sessions.write().await;

        if let Some(&addr) = ip_to_addr.get(&dest_ip) {
            if let Some(session) = sessions.get_mut(&addr) {
                // Encrypt and send
                let encrypted = crypto::encrypt(
                    &session.session_keys.encrypt_key,
                    session.tx_sequence,
                    data,
                )?;

                let packet = build_packet(PacketType::Data, session.tx_sequence, &encrypted);
                session.tx_sequence += 1;

                self.socket.send_to(&packet, addr).await?;
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║         QuantumShield VPN Server v1.0                      ║");
    println!("║   Quantum-Resistant: ML-KEM-1024 + X25519 Hybrid          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Load keypair
    let secret_bytes = base64::decode(fs::read_to_string(&args.private_key)?.trim())?;
    let keypair = HybridKeypair::from_secret_bytes(&secret_bytes)?;

    info!("Loaded server keypair");
    info!("Public key fingerprint: {}", {
        let public_bytes = keypair.public.to_bytes();
        let hash = blake3::hash(&public_bytes);
        hex::encode(&hash.as_bytes()[..8])
    });

    // Create TUN device
    info!("Creating TUN device...");
    let mut tun = TunDevice::new(&args.tun_ip, &args.tun_netmask, args.mtu)?;
    info!("TUN device {} created with IP {}", tun.name(), args.tun_ip);

    // Channel for TUN packets
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(1000);

    // Create server
    let server = Arc::new(Server::new(&args.listen, keypair, tun_tx).await?);

    info!("Server started with quantum-resistant encryption");

    // Spawn socket handler
    let server_clone = Arc::clone(&server);
    let socket_handle = tokio::spawn(async move {
        if let Err(e) = server_clone.run_socket_handler().await {
            error!("Socket handler error: {}", e);
        }
    });

    // Spawn TUN reader (reads from TUN, sends to clients)
    let server_clone = Arc::clone(&server);
    let tun_read_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun.read_packet(&mut buf) {
                Ok(len) => {
                    if len >= 20 {
                        // Extract destination IP from IPv4 header
                        let dest_ip = [buf[16], buf[17], buf[18], buf[19]];

                        if let Err(e) = server_clone.send_to_client(dest_ip, &buf[..len]).await {
                            warn!("Failed to send to client: {}", e);
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
        let mut tun_write = TunDevice::new(&args.tun_ip, &args.tun_netmask, args.mtu)
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
