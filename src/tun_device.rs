use anyhow::{Result, Context};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use tun::Device as TunDeviceTrait;
use tun::platform::Device;

pub struct TunDevice {
    device: Device,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device with the specified IP and netmask
    pub fn new(address: &str, netmask: &str, mtu: i32) -> Result<Self> {
        let mut config = tun::Configuration::default();

        let addr: Ipv4Addr = address.parse().context("Invalid TUN address")?;
        let mask: Ipv4Addr = netmask.parse().context("Invalid netmask")?;

        config
            .address(addr)
            .netmask(mask)
            .mtu(mtu)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        let device = tun::create(&config)
            .context("Failed to create TUN device. Run with sudo.")?;

        let name = TunDeviceTrait::name(&device)
            .context("Failed to get TUN device name")?;

        tracing::info!("Created TUN device: {} with IP {}/{}", name, address, netmask);

        Ok(Self { device, name })
    }

    /// Get the device name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read a packet from the TUN device
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.device.read(buf)
            .context("Failed to read from TUN device")?;
        Ok(n)
    }

    /// Write a packet to the TUN device
    pub fn write_packet(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.device.write(buf)
            .context("Failed to write to TUN device")?;
        Ok(n)
    }
}

/// Configure routing to send traffic through the VPN tunnel
#[cfg(target_os = "linux")]
pub fn setup_routing(tun_name: &str, server_ip: &str) -> Result<()> {
    use std::process::Command;

    // Enable IP forwarding
    Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()
        .context("Failed to enable IP forwarding")?;

    // Add NAT rule for server
    Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-o", tun_name, "-j", "MASQUERADE"])
        .output()
        .context("Failed to add NAT rule")?;

    tracing::info!("Routing configured for {}", tun_name);
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn setup_routing(tun_name: &str, _server_ip: &str) -> Result<()> {
    use std::process::Command;

    // Enable IP forwarding on macOS
    Command::new("sysctl")
        .args(["-w", "net.inet.ip.forwarding=1"])
        .output()
        .context("Failed to enable IP forwarding")?;

    // Add route for VPN subnet
    Command::new("route")
        .args(["add", "-net", "10.0.0.0/24", "-interface", tun_name])
        .output()
        .context("Failed to add route")?;

    tracing::info!("Routing configured for {}", tun_name);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn setup_routing(_tun_name: &str, _server_ip: &str) -> Result<()> {
    tracing::warn!("Routing setup not implemented for this platform");
    Ok(())
}
