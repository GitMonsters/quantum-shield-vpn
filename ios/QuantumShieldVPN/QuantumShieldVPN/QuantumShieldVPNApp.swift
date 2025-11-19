import SwiftUI
import NetworkExtension

@main
struct QuantumShieldVPNApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @StateObject private var vpnManager = VPNManager()

    var body: some View {
        NavigationView {
            VStack(spacing: 30) {
                // Status indicator
                Circle()
                    .fill(vpnManager.isConnected ? Color.green : Color.red)
                    .frame(width: 100, height: 100)
                    .overlay(
                        Image(systemName: vpnManager.isConnected ? "lock.shield.fill" : "lock.shield")
                            .font(.system(size: 40))
                            .foregroundColor(.white)
                    )

                Text(vpnManager.statusText)
                    .font(.headline)

                if vpnManager.isConnected {
                    Text("IP: \(vpnManager.assignedIP)")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                // Connect/Disconnect button
                Button(action: {
                    if vpnManager.isConnected {
                        vpnManager.disconnect()
                    } else {
                        vpnManager.connect()
                    }
                }) {
                    Text(vpnManager.isConnected ? "Disconnect" : "Connect")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(width: 200, height: 50)
                        .background(vpnManager.isConnected ? Color.red : Color.blue)
                        .cornerRadius(25)
                }
                .disabled(vpnManager.isConnecting)

                Spacer()

                // Settings
                NavigationLink(destination: SettingsView(vpnManager: vpnManager)) {
                    HStack {
                        Image(systemName: "gear")
                        Text("Settings")
                    }
                }
                .padding()
            }
            .padding()
            .navigationTitle("QuantumShield VPN")
        }
    }
}

struct SettingsView: View {
    @ObservedObject var vpnManager: VPNManager

    var body: some View {
        Form {
            Section(header: Text("Server")) {
                TextField("Server Address", text: $vpnManager.serverAddress)
                    .keyboardType(.URL)
                    .autocapitalization(.none)

                TextField("Server Port", text: $vpnManager.serverPort)
                    .keyboardType(.numberPad)
            }

            Section(header: Text("Keys")) {
                Button("Import Server Public Key") {
                    // Open file picker
                }

                Button("Import Client Private Key") {
                    // Open file picker
                }
            }

            Section(header: Text("Security")) {
                Text("Encryption: ML-KEM-1024 + X25519")
                Text("Cipher: ChaCha20-Poly1305")
                Text("KDF: BLAKE3")
            }
            .foregroundColor(.secondary)
        }
        .navigationTitle("Settings")
    }
}

class VPNManager: ObservableObject {
    @Published var isConnected = false
    @Published var isConnecting = false
    @Published var statusText = "Disconnected"
    @Published var assignedIP = ""
    @Published var serverAddress = ""
    @Published var serverPort = "51820"

    private var vpnManager: NETunnelProviderManager?

    init() {
        loadVPNConfiguration()
        observeVPNStatus()
    }

    func loadVPNConfiguration() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let error = error {
                print("Failed to load VPN configurations: \(error)")
                return
            }

            self?.vpnManager = managers?.first ?? NETunnelProviderManager()
        }
    }

    func observeVPNStatus() {
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            self?.updateStatus(connection.status)
        }
    }

    func updateStatus(_ status: NEVPNStatus) {
        switch status {
        case .connected:
            isConnected = true
            isConnecting = false
            statusText = "Connected (Quantum-Secured)"
        case .connecting:
            isConnecting = true
            statusText = "Establishing quantum-resistant tunnel..."
        case .disconnecting:
            statusText = "Disconnecting..."
        case .disconnected:
            isConnected = false
            isConnecting = false
            statusText = "Disconnected"
            assignedIP = ""
        case .invalid:
            statusText = "Invalid configuration"
        case .reasserting:
            statusText = "Reconnecting..."
        @unknown default:
            statusText = "Unknown status"
        }
    }

    func connect() {
        guard let manager = vpnManager else {
            configureVPN { [weak self] in
                self?.startVPNTunnel()
            }
            return
        }

        if manager.connection.status == .disconnected {
            startVPNTunnel()
        }
    }

    func disconnect() {
        vpnManager?.connection.stopVPNTunnel()
    }

    private func configureVPN(completion: @escaping () -> Void) {
        let manager = NETunnelProviderManager()

        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = "com.quantumshield.vpn.tunnel"
        tunnelProtocol.serverAddress = "\(serverAddress):\(serverPort)"

        // Pass configuration to tunnel provider
        tunnelProtocol.providerConfiguration = [
            "serverAddress": serverAddress,
            "serverPort": serverPort
        ]

        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "QuantumShield VPN"
        manager.isEnabled = true

        manager.saveToPreferences { [weak self] error in
            if let error = error {
                print("Failed to save VPN configuration: \(error)")
                return
            }

            manager.loadFromPreferences { error in
                if let error = error {
                    print("Failed to reload VPN configuration: \(error)")
                    return
                }

                self?.vpnManager = manager
                completion()
            }
        }
    }

    private func startVPNTunnel() {
        do {
            try vpnManager?.connection.startVPNTunnel()
        } catch {
            print("Failed to start VPN tunnel: \(error)")
            statusText = "Failed to connect"
        }
    }
}

#Preview {
    ContentView()
}
