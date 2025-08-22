# Omni Infrastructure Provider for Proxmox VE

This is an infrastructure provider for [Omni](https://github.com/siderolabs/omni) that enables management of virtual machines in Proxmox VE environments.

## Overview

The Proxmox infrastructure provider connects to Omni as an infra provider and manages VMs in Proxmox Virtual Environment. It allows you to provision and manage Talos Linux machines through Omni using Proxmox VE as the underlying virtualization platform.

## Features

- VM provisioning and management in Proxmox VE
- Integration with Omni's infrastructure provider interface
- Support for both password and API token authentication
- Configurable storage pools for VMs and images
- TLS configuration options for secure connections

## Prerequisites

- Go 1.24.5 or later
- Access to a Proxmox VE cluster
- Omni instance with API access
- Service account key for Omni authentication

## Setup

### Omni Setup
1. Login to your Omni instance
2. Navigate to **Infra Providers**
3. Click **New Infra Provider Setup**
4. Enter `proxmox` as the ID
5. Copy the generated service token

### Proxmox Setup
1. Create a role: `pveum role add omni-provider -privs VM.Allocate,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.PowerMgmt,VM.Monitor,VM.Audit,Datastore.Allocate,Datastore.AllocateSpace,Datastore.Audit,Datastore.AllocateTemplate,Sys.Audit`
2. Create a user: `pveum user add omni-provider@pve`
3. Assign the role: `pveum aclmod / -user omni-provider@pve -role omni-provider`

### Configuration

Copy the sample environment file and configure your settings:

```bash
cp .env.sample .env
```

Edit the `.env` file with your specific configuration:

### Required Configuration

- `OMNI_ENDPOINT`: Your Omni API endpoint
- `OMNI_SERVICE_ACCOUNT_KEY`: Service account key for Omni authentication
- `PROXMOX_URL`: Proxmox VE API endpoint (e.g., `https://your-proxmox-host:8006/api2/json`)
- `PROXMOX_USER`: Proxmox username (e.g., `root@pam`)
- Either `PROXMOX_PASSWORD` or `PROXMOX_TOKEN` for authentication

### Optional Configuration

- `PROVIDER_ID`: Custom provider ID (default: auto-generated)
- `PROVIDER_NAME`: Provider name in Omni (default: "Proxmox")
- `PROVIDER_DESCRIPTION`: Provider description (default: "Proxmox VE infrastructure provider")
- `PROXMOX_REALM`: Authentication realm (default: "pam")
- `PROXMOX_STORAGE_POOL`: Storage pool for VM disks (default: "local")
- `PROXMOX_IMAGE_STORAGE_POOL`: Storage pool for images (default: "local")
- `INSECURE_SKIP_VERIFY`: Skip TLS verification for Omni (default: false)
- `INSECURE_SKIP_TLS`: Skip TLS verification for Proxmox (default: false)

## Building and Running

### Build the Provider
```bash
go build -o omni-infra-provider-proxmox ./cmd/omni-infra-provider-proxmox
```

### Run the Provider

### Using environment variables

```bash
export OMNI_ENDPOINT="https://your-omni-instance.com"
export OMNI_SERVICE_ACCOUNT_KEY="your-service-account-key"
export PROXMOX_URL="https://your-proxmox-host:8006/api2/json"
export PROXMOX_USER="root@pam"
export PROXMOX_PASSWORD="your-password"

./omni-infra-provider-proxmox
```

### Using command line flags

```bash
./omni-infra-provider-proxmox \
  --omni-api-endpoint https://your-omni-instance.com \
  --omni-service-account-key your-service-account-key \
  --proxmox-url https://your-proxmox-host:8006/api2/json \
  --proxmox-user root@pam \
  --proxmox-password your-password
```

## Authentication

The provider supports two authentication methods for Proxmox:

1. **Password Authentication**: Use `PROXMOX_PASSWORD` with your user credentials
2. **API Token Authentication**: Use `PROXMOX_TOKEN` for token-based authentication

API token authentication is recommended for production deployments.

Once the provider is running and connected to Omni, you can see it listed in the **Infra Providers** section and begin creating machine classes.

## Creating Machine Classes

Once the provider is running and connected to Omni, you can create machine classes to define VM configurations.

### Step-by-Step

1. Log into your Omni instance
2. Navigate to **Machine Management** → **Classes**
3. Click **Create Machine Class**
4. Select **Proxmox** as the infrastructure provider
5. Configure the machine class parameters (see options below)

### Machine Class Options

#### Required Parameters

- **`proxmox_node`** (string): Proxmox node name where VMs will be created
- **`cores`** (integer, minimum: 1): Number of CPU cores for the VM
- **`memory`** (integer): Memory allocation in MB
- **`disk_size`** (integer): Root disk size in GB
- **`architecture`** (enum): CPU architecture - either `amd64` or `arm64`

#### Optional Parameters

**Networking:**
- **`network_bridge`** (string, default: "vmbr0"): Proxmox network bridge for VM networking
- **`subnet`** (string): Static IP subnet in CIDR notation (e.g., "192.168.1.0/24"). If provided, VMs will get IP addresses based on their VM ID within this subnet. If not provided, DHCP will be used.
- **`gateway`** (string): Gateway IP address (required if subnet is provided)
- **`dns_servers`** (array of strings): DNS server addresses (optional, defaults to ["8.8.8.8", "8.8.4.4"])

**Disk Performance:**
- **`disk_ssd`** (boolean, default: true): Enable SSD emulation for better performance
- **`disk_discard`** (boolean, default: true): Enable TRIM/discard support for better SSD performance
- **`disk_iothread`** (boolean, default: false): Enable dedicated iothread for disk operations (can improve performance but uses more resources)

### Example Configuration

When creating a machine class, the Omni UI will present form fields for each option. Here's an example configuration:

- **Proxmox Node**: `pve1`
- **Cores**: `4`
- **Memory**: `8192` (MB)
- **Disk Size**: `50` (GB)
- **Architecture**: `amd64`
- **Network Bridge**: `vmbr0`
- **Subnet**: `192.168.100.0/24`
- **Gateway**: `192.168.100.1`
- **DNS Servers**: `1.1.1.1, 8.8.8.8`
- **Disk SSD**: ✓ (enabled)
- **Disk Discard**: ✓ (enabled)
- **Disk IOThread**: ✗ (disabled)

This configuration creates VMs with:
- 4 CPU cores and 8GB RAM
- 50GB SSD root disk 
- Static IPs in the 192.168.100.x range
- High-performance disk settings

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.