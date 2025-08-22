// SPDX-License-Identifier: MIT

package provider

// Data is the provider custom machine config.
type Data struct {
	ProxmoxNode     string   `yaml:"proxmox_node"`
	NetworkBridge   string   `yaml:"network_bridge"`
	Architecture    string   `yaml:"architecture"`
	Cores          int      `yaml:"cores"`
	DiskSize       int      `yaml:"disk_size"`
	Memory         uint64   `yaml:"memory"`
	DiskSSD        bool     `yaml:"disk_ssd"`
	DiskDiscard    bool     `yaml:"disk_discard"`
	DiskIOThread   bool     `yaml:"disk_iothread"`
	Subnet         string   `yaml:"subnet,omitempty"`
	Gateway        string   `yaml:"gateway,omitempty"`
	DNSServers     []string `yaml:"dns_servers,omitempty"`
}
