# Forwarding Plane for CyberTom VPN

The forwarding plane, also known as the edge node of CyberTom VPN, is responsible for providing VPN services to users. It is developed using Golang.

## Features
- Supports multiple VPN protocols (e.g., WireGuard)
- Configurable with public key pairs for secure communication
- Easy-to-use configuration and management interface

## Build & Installation

### Prerequisites
- Golang 1.23 or later

### Build Instructions
```bash
git clone https://github.com/Cybertom-Opensource/forwarding-plane.git
cd forwarding-plane
go build -o forwarding-plane
```

The above command will generate a single binary file named `forwarding-plane` in your current directory.

## Running the Service

1. **Configuration**
   - Create a `config` directory if it doesn't exist.
   - Place the corresponding public key files required by the control plane in this directory.

2. **Service Start**
   - Refer to the provided `systemd` unit file in the repository and adjust it according to your system's requirements.
   - Use the following commands to start and enable the service:
     ```bash
     sudo systemctl daemon-reload
     sudo systemctl start forwarding-plane
     sudo systemctl enable forwarding-plane
     ```

3. **Testing**
   - After starting the service, you can test its availability by connecting via a VPN client configured with the appropriate settings.

## Notes

- The forwarding plane does not automatically configure IPv4 forwarding or `nftables/iptables` rules. You must manually set up these configurations before deploying the service.
- Ensure that any required Access Control Lists (ACLs) and TCP Maximum Segment Size (MSS) adjustments are properly configured to optimize performance and security.

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please fork the repository and create a pull request. Please ensure your code adheres to the existing coding style and conventions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.