//! Key generation utility for QuantumShield VPN

use anyhow::Result;
use clap::Parser;
use quantum_shield_vpn::crypto::HybridKeypair;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "qs-keygen")]
#[command(about = "Generate quantum-resistant keypairs for QuantumShield VPN")]
struct Args {
    /// Output directory for keys
    #[arg(short, long, default_value = ".")]
    output: PathBuf,

    /// Key name prefix
    #[arg(short, long, default_value = "quantum_shield")]
    name: String,

    /// Generate server keys
    #[arg(long)]
    server: bool,

    /// Generate client keys
    #[arg(long)]
    client: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Create output directory if it doesn't exist
    fs::create_dir_all(&args.output)?;

    if args.server || (!args.server && !args.client) {
        generate_keypair(&args.output, &format!("{}_server", args.name))?;
    }

    if args.client || (!args.server && !args.client) {
        generate_keypair(&args.output, &format!("{}_client", args.name))?;
    }

    Ok(())
}

fn generate_keypair(output_dir: &PathBuf, name: &str) -> Result<()> {
    println!("Generating quantum-resistant keypair: {}", name);
    println!("  Algorithm: ML-KEM-1024 (Kyber) + X25519 hybrid");

    let keypair = HybridKeypair::generate();

    // Save public key
    let public_path = output_dir.join(format!("{}.pub", name));
    let public_bytes = keypair.public_key_bytes();
    fs::write(&public_path, base64::encode(&public_bytes))?;
    println!("  Public key: {} ({} bytes)", public_path.display(), public_bytes.len());

    // Save secret key
    let secret_path = output_dir.join(format!("{}.key", name));
    let secret_bytes = keypair.secret_key_bytes();
    fs::write(&secret_path, base64::encode(&secret_bytes))?;

    // Set restrictive permissions on secret key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&secret_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&secret_path, perms)?;
    }

    println!("  Secret key: {} ({} bytes)", secret_path.display(), secret_bytes.len());
    println!("  ✓ Keypair generated successfully\n");

    // Print fingerprint
    let fingerprint = blake3::hash(&public_bytes);
    println!("  Fingerprint: {}", hex::encode(&fingerprint.as_bytes()[..16]));

    Ok(())
}
