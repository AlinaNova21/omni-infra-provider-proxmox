// SPDX-License-Identifier: MIT

// Package provider implements Proxmox infra provider core.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/google/uuid"
	"github.com/siderolabs/omni/client/pkg/constants"
	"github.com/siderolabs/omni/client/pkg/infra/provision"
	"github.com/siderolabs/omni/client/pkg/omni/resources/infra"
	"go.uber.org/zap"

	"github.com/alinanova21/omni-infra-provider-proxmox/internal/pkg/provider/resources"
)

// Provisioner implements Proxmox infra provider.
type Provisioner struct {
	proxmoxClient    *proxmox.Client
	storagePool      string
	imageStoragePool string
}

// NewProvisioner creates a new provisioner.
func NewProvisioner(proxmoxClient *proxmox.Client, storagePool, imageStoragePool string) *Provisioner {
	return &Provisioner{
		proxmoxClient:    proxmoxClient,
		storagePool:      storagePool,
		imageStoragePool: imageStoragePool,
	}
}

// ProvisionSteps implements infra.Provisioner.
func (p *Provisioner) ProvisionSteps() []provision.Step[*resources.Machine] {
	return []provision.Step[*resources.Machine]{
		provision.NewStep("validateRequest", func(_ context.Context, _ *zap.Logger, pctx provision.Context[*resources.Machine]) error {
			if len(pctx.GetRequestID()) > 62 {
				return fmt.Errorf("the machine request name can not be longer than 63 characters")
			}

			return nil
		}),
		provision.NewStep("createSchematic", func(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
			// Force CustomDataEncoded to false to avoid request ID conflict
			pctx.ConnectionParams.CustomDataEncoded = false
			
			logger.Info("generating schematic with connection params included (CustomDataEncoded forced to false)")
			schematic, err := pctx.GenerateSchematicID(ctx, logger,
				provision.WithExtraKernelArgs("console=ttyS0,115200n8"),
			)
			if err != nil {
				return err
			}

			logger.Info("schematic generated", zap.String("schematic", schematic))
			pctx.State.TypedSpec().Value.Schematic = schematic

			return nil
		}),
		provision.NewStep("prepareImage", func(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
			logger.Info("starting prepareImage step")
			pctx.State.TypedSpec().Value.TalosVersion = pctx.GetTalosVersion()

			url, err := url.Parse(constants.ImageFactoryBaseURL)
			if err != nil {
				logger.Error("failed to parse image factory URL", zap.Error(err))
				return err
			}

			var data Data
			err = pctx.UnmarshalProviderData(&data)
			if err != nil {
				logger.Error("failed to unmarshal provider data", zap.Error(err))
				return err
			}
			logger.Info("provider data", zap.Any("data", data))

			url = url.JoinPath("image",
				pctx.State.TypedSpec().Value.Schematic,
				fmt.Sprintf("v%s", pctx.GetTalosVersion()),
				fmt.Sprintf("nocloud-%s.qcow2", data.Architecture),
			)

			// Generate unique filename based on URL hash
			hash := sha256.New()
			if _, err = hash.Write([]byte(url.String())); err != nil {
				return err
			}
			schematicHash := hex.EncodeToString(hash.Sum(nil))[:8]

			filename := fmt.Sprintf("omni-v%s-%s-nocloud-%s.qcow2",
				pctx.GetTalosVersion(),
				schematicHash,
				data.Architecture)

			logger.Info("image details",
				zap.String("url", url.String()),
				zap.String("schematic", pctx.State.TypedSpec().Value.Schematic),
				zap.String("talosVersion", pctx.GetTalosVersion()),
				zap.String("schematicHash", schematicHash),
				zap.String("filename", filename))

			pctx.State.TypedSpec().Value.ImageName = filename

			logger.Info("checking if image exists", 
				zap.String("node", data.ProxmoxNode),
				zap.String("imageStorage", p.imageStoragePool),
				zap.String("filename", filename))

			// Check if qcow2 image already exists
			exists, err := ImageExists(p.proxmoxClient, data.ProxmoxNode, p.imageStoragePool, filename)
			if err != nil {
				logger.Error("failed to check if qcow2 image exists", zap.Error(err))
				return err
			}

			if exists {
				logger.Info("qcow2 image already exists, skipping download", zap.String("filename", filename))
				return nil
			}

			// Download qcow2 image via import-from API
			qcow2Config := ConfigContent_Qcow2{
				Node:     data.ProxmoxNode,
				Storage:  p.imageStoragePool,
				Content:  "import",
				Filename: filename,
				URL:      url.String(),
			}

			logger.Info("downloading qcow2 image", 
				zap.String("url", url.String()), 
				zap.String("filename", filename),
				zap.String("node", data.ProxmoxNode),
				zap.String("imageStorage", p.imageStoragePool))

			if err := qcow2Config.DownloadQcow2FromUrl(p.proxmoxClient); err != nil {
				logger.Error("failed to download qcow2 image", zap.Error(err))
				return fmt.Errorf("failed to download qcow2 image: %w", err)
			}

			logger.Info("qcow2 download started")

			// Wait for download completion (polling)
			return provision.NewRetryInterval(time.Second * 10)
		}),
		provision.NewStep("createVM", func(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) (err error) {
			logger.Info("starting createVM step")
			if pctx.State.TypedSpec().Value.Uuid == "" {
				pctx.State.TypedSpec().Value.Uuid = uuid.NewString()
			}

			logger = logger.With(zap.String("uuid", pctx.State.TypedSpec().Value.Uuid))

			var (
				data   Data
				vmRef  *proxmox.VmRef
			)
			
			if err = pctx.UnmarshalProviderData(&data); err != nil {
				logger.Error("failed to unmarshal provider data in createVM", zap.Error(err))
				return err
			}
			logger.Info("createVM provider data", zap.Any("data", data))

			// Check metadata first - if we already have a VM ID stored, use it
			existingVMID := int(pctx.State.TypedSpec().Value.VmId)
			existingNode := pctx.State.TypedSpec().Value.Node
			
			if existingVMID != 0 && existingNode != "" {
				logger.Info("found VM ID in metadata", zap.Int("vmid", existingVMID), zap.String("node", existingNode))
				
				// Verify the VM still exists in Proxmox
				if exists, err := p.vmExists(ctx, existingNode, existingVMID); err != nil {
					logger.Warn("failed to verify VM exists", zap.Error(err))
				} else if exists {
					logger.Info("verified VM exists in Proxmox", zap.Int("vmid", existingVMID))
					return p.checkVMReady(ctx, existingNode, existingVMID)
				} else {
					logger.Warn("VM in metadata no longer exists in Proxmox, will create new one", zap.Int("vmid", existingVMID))
					// Clear the metadata since the VM no longer exists
					pctx.State.TypedSpec().Value.VmId = 0
					pctx.State.TypedSpec().Value.Node = ""
				}
			}

			// No valid VM in metadata, need to create a new one
			logger.Info("no existing VM found in metadata, will create new one")
			
			// Get next available VM ID for new VM
			vmid, err := p.getNextVMID(ctx, data.ProxmoxNode)
			if err != nil {
				return fmt.Errorf("failed to get next VM ID: %w", err)
			}
			
			// Store VM ID and node in metadata immediately
			pctx.State.TypedSpec().Value.VmId = int32(vmid)
			pctx.State.TypedSpec().Value.Node = data.ProxmoxNode
			
			logger.Info("creating new VM", zap.Int("vmid", vmid), zap.String("node", data.ProxmoxNode))

			// Build VM configuration using ConfigQemu
			vmGuestName := proxmox.GuestName(pctx.GetRequestID())
			vmDesc := "Talos cluster node managed by OMNI"
			vmTags := proxmox.Tags{"omni"}
			
			// Set up CPU and Memory configuration
			cpuCores := proxmox.QemuCpuCores(data.Cores)
			cpuSockets := proxmox.QemuCpuSockets(1)
			cpuType := proxmox.CpuType("host")
			memoryCapacity := proxmox.QemuMemoryCapacity(data.Memory)
			
			// Set up boolean pointers
			onbootTrue := true
			agentTrue := true
			
			vmConfig := &proxmox.ConfigQemu{
				Name:        &vmGuestName,
				Description: &vmDesc,
				Memory: &proxmox.QemuMemory{
					CapacityMiB: &memoryCapacity,
				},
				CPU: &proxmox.QemuCPU{
					Cores:   &cpuCores,
					Sockets: &cpuSockets,
					Type:    &cpuType,
				},
				QemuOs:     "l26",
				Machine:    "q35",
				Bios:       "seabios",
				Boot:       "order=scsi0",
				Scsihw:     "virtio-scsi-single",
				Onboot:     &onbootTrue,
				Agent:      &proxmox.QemuGuestAgent{Enable: &agentTrue},
				Tags:       &vmTags,
			}

			// Configure disks: use ImportFrom for the qcow2 image
			importedImageVolume := fmt.Sprintf("%s:import/%s", p.imageStoragePool, pctx.State.TypedSpec().Value.ImageName)
			
			logger.Info("disk configuration",
				zap.String("importedImageVolume", importedImageVolume),
				zap.Int("targetSizeGB", data.DiskSize))
			
			vmConfig.Disks = &proxmox.QemuStorages{
				Scsi: &proxmox.QemuScsiDisks{
					Disk_0: &proxmox.QemuScsiStorage{
						Disk: &proxmox.QemuScsiDisk{
							Storage:          p.storagePool, // Use main storage pool for the VM disk
							Format:           proxmox.QemuDiskFormat("qcow2"),
							EmulateSSD:       data.DiskSSD,
							Discard:          data.DiskDiscard,
							IOThread:         data.DiskIOThread,
							Backup:           true,
							ImportFrom:       importedImageVolume, // Import from image storage pool
						},
					},
				},
				Ide: &proxmox.QemuIdeDisks{
					Disk_0: &proxmox.QemuIdeStorage{
						CloudInit: &proxmox.QemuCloudInitDisk{
							Storage: p.storagePool,
							Format:  proxmox.QemuDiskFormat("raw"),
						},
					},
				},
			}

			// Configure network using Networks field
			bridgeName := data.NetworkBridge
			networkModel := proxmox.QemuNetworkModelVirtIO
			vmConfig.Networks = make(proxmox.QemuNetworkInterfaces)
			vmConfig.Networks[0] = proxmox.QemuNetworkInterface{
				Model:  &networkModel,
				Bridge: &bridgeName,
			}

			// Configure cloud-init if networking details are provided
			vmConfig.CloudInit = &proxmox.CloudInit{}
			if data.Subnet != "" && data.Gateway != "" {
				// Calculate IP address based on VM ID and subnet
				vmIP, err := p.calculateVMIP(data.Subnet, vmid)
				if err != nil {
					return fmt.Errorf("failed to calculate VM IP: %w", err)
				}
				
				// Set up static IP configuration
				ipCIDR := proxmox.IPv4CIDR(vmIP)
				gatewayAddr := proxmox.IPv4Address(data.Gateway)
				
				vmConfig.CloudInit.NetworkInterfaces = make(proxmox.CloudInitNetworkInterfaces)
				vmConfig.CloudInit.NetworkInterfaces[0] = proxmox.CloudInitNetworkConfig{
					IPv4: &proxmox.CloudInitIPv4Config{
						Address: &ipCIDR,
						Gateway: &gatewayAddr,
					},
				}
				
				// Set DNS servers if provided
				if len(data.DNSServers) > 0 {
					// Convert string IPs to netip.Addr
					var nameservers []netip.Addr
					for _, dns := range data.DNSServers {
						if addr, err := netip.ParseAddr(dns); err == nil {
							nameservers = append(nameservers, addr)
						}
					}
					vmConfig.CloudInit.DNS = &proxmox.GuestDNS{
						NameServers: &nameservers,
					}
				}
				
				logger.Info("configuring static networking",
					zap.String("ip", vmIP),
					zap.String("gateway", data.Gateway),
					zap.Strings("dns", data.DNSServers))
			} else {
				// Use DHCP
				vmConfig.CloudInit.NetworkInterfaces = make(proxmox.CloudInitNetworkInterfaces)
				vmConfig.CloudInit.NetworkInterfaces[0] = proxmox.CloudInitNetworkConfig{
					IPv4: &proxmox.CloudInitIPv4Config{
						DHCP: true,
					},
				}
				logger.Info("configuring DHCP networking")
			}

			logger.Info("creating VM", zap.Int("vmid", vmid))
			logger.Info("VM config", zap.Any("config", vmConfig))

			// Set the VM ID and node for creation
			vmID := proxmox.GuestID(vmid)
			nodeName := proxmox.NodeName(data.ProxmoxNode)
			vmConfig.ID = &vmID
			vmConfig.Node = &nodeName
			
			// Create VM using ConfigQemu
			vmRef, err = vmConfig.Create(ctx, p.proxmoxClient)
			if err != nil {
				logger.Error("failed to create VM", zap.Error(err), zap.Any("config", vmConfig))
				return fmt.Errorf("failed to create VM: %w", err)
			}
			logger.Info("VM created successfully")

			// Set up cleanup function for failures after VM creation
			vmCreated := true
			defer func() {
				if vmCreated && err != nil {
					logger.Warn("VM creation failed after VM was created, cleaning up", zap.Int("vmid", vmid))
					if cleanupErr := p.cleanupVM(ctx, vmRef); cleanupErr != nil {
						logger.Error("failed to cleanup VM after creation failure", zap.Error(cleanupErr), zap.Int("vmid", vmid))
					} else {
						logger.Info("VM cleanup completed", zap.Int("vmid", vmid))
						// Clear metadata since VM was deleted
						pctx.State.TypedSpec().Value.VmId = 0
						pctx.State.TypedSpec().Value.Node = ""
					}
				}
			}()

			// Disk imported from qcow2 image, will be resized in next step
			logger.Info("VM created with imported disk", zap.Int("vmid", vmid), zap.String("imageName", pctx.State.TypedSpec().Value.ImageName))

			// Mark VM creation as successful (no cleanup needed)
			vmCreated = false

			logger.Info("VM created successfully, disk resize will happen next")
			return nil
		}),
		provision.NewStep("resizeDisk", func(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
			logger.Info("starting resizeDisk step")
			
			var data Data
			if err := pctx.UnmarshalProviderData(&data); err != nil {
				logger.Error("failed to unmarshal provider data in resizeDisk", zap.Error(err))
				return err
			}
			
			// Get VM ID and node from metadata
			vmid := int(pctx.State.TypedSpec().Value.VmId)
			node := pctx.State.TypedSpec().Value.Node
			
			if vmid == 0 || node == "" {
				return fmt.Errorf("VM metadata not found for resize operation")
			}
			
			logger.Info("resizing disk to target size",
				zap.Int("vmid", vmid),
				zap.String("node", node),
				zap.Int("targetSizeGB", data.DiskSize))
			
			// Create VmRef for resize operation
			vmRef := proxmox.NewVmRef(proxmox.GuestID(vmid))
			vmRef.SetNode(node)
			
			// Resize disk to absolute target size
			targetSize := fmt.Sprintf("%dG", data.DiskSize)
			if err := p.resizeDisk(ctx, vmRef, "scsi0", targetSize); err != nil {
				logger.Error("failed to resize disk", zap.Error(err), zap.String("targetSize", targetSize))
				return fmt.Errorf("failed to resize disk to %s: %w", targetSize, err)
			}
			
			logger.Info("disk resized successfully", zap.String("targetSize", targetSize))
			return nil
		}),
		provision.NewStep("startVM", func(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
			logger.Info("starting startVM step")
			
			var data Data
			if err := pctx.UnmarshalProviderData(&data); err != nil {
				logger.Error("failed to unmarshal provider data in startVM", zap.Error(err))
				return err
			}
			
			// Get VM ID and node from metadata
			vmid := int(pctx.State.TypedSpec().Value.VmId)
			node := pctx.State.TypedSpec().Value.Node
			
			if vmid == 0 || node == "" {
				return fmt.Errorf("VM metadata not found for start operation")
			}
			
			logger.Info("starting VM after disk resize",
				zap.Int("vmid", vmid),
				zap.String("node", node))
			
			// Create VmRef for start operation
			vmRef := proxmox.NewVmRef(proxmox.GuestID(vmid))
			vmRef.SetNode(node)
			
			// Start the VM
			if _, err := p.proxmoxClient.StartVm(ctx, vmRef); err != nil {
				logger.Error("failed to start VM", zap.Error(err))
				return fmt.Errorf("failed to start VM: %w", err)
			}
			
			logger.Info("VM start command sent successfully")
			
			// Check if VM is running and ready
			return p.checkVMReady(ctx, node, vmid)
		}),
		provision.NewStep("cleanupImage", func(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
			logger.Info("starting cleanupImage step")
			
			var data Data
			if err := pctx.UnmarshalProviderData(&data); err != nil {
				logger.Error("failed to unmarshal provider data in cleanupImage", zap.Error(err))
				return err
			}
			
			// Clean up the imported image since it's no longer needed
			imageName := pctx.State.TypedSpec().Value.ImageName
			imageVolId := fmt.Sprintf("%s:import/%s", p.imageStoragePool, imageName)
			
			logger.Info("cleaning up imported image",
				zap.String("imageName", imageName),
				zap.String("imageVolId", imageVolId),
				zap.String("node", data.ProxmoxNode),
				zap.String("imageStorage", p.imageStoragePool))
			
			if err := p.deleteStorageVolume(ctx, data.ProxmoxNode, p.imageStoragePool, imageVolId); err != nil {
				// Don't fail the provisioning if cleanup fails, just log the error
				logger.Warn("failed to cleanup imported image", zap.Error(err), zap.String("imageVolId", imageVolId))
			} else {
				logger.Info("successfully cleaned up imported image", zap.String("imageVolId", imageVolId))
			}
			
			return nil
		}),
	}
}

// Deprovision implements infra.Provisioner.
func (p *Provisioner) Deprovision(ctx context.Context, logger *zap.Logger, machine *resources.Machine, machineRequest *infra.MachineRequest) error {
	logger.Info("starting deprovision")
	
	// Check if we have VM information stored in machine metadata
	if machine != nil && machine.TypedSpec() != nil && machine.TypedSpec().Value != nil {
		vmid := int(machine.TypedSpec().Value.VmId)
		node := machine.TypedSpec().Value.Node
		
		if vmid != 0 && node != "" {
			logger.Info("found VM information in metadata", zap.Int("vmid", vmid), zap.String("node", node))
			
			// Verify VM exists before trying to delete it
			if exists, err := p.vmExists(ctx, node, vmid); err != nil {
				logger.Warn("failed to verify VM exists", zap.Error(err))
			} else if !exists {
				logger.Info("VM no longer exists in Proxmox, considering it already deprovisioned", zap.Int("vmid", vmid))
				return nil
			}
			
			return p.deleteVM(ctx, logger, vmid, node)
		}
	}
	
	// Fallback to searching by name if no metadata is available
	vmName := machineRequest.Metadata().ID()
	logger.Info("no VM metadata found, searching by name", zap.String("vmName", vmName))
	
	vmid, node, err := p.findVMByNameGlobal(ctx, vmName)
	if err != nil {
		logger.Warn("failed to find VM by name", zap.Error(err), zap.String("vmName", vmName))
		return nil
	}
	
	if vmid == 0 {
		logger.Info("VM not found, considering it already deprovisioned", zap.String("vmName", vmName))
		return nil
	}

	logger.Info("found VM by name search", zap.Int("vmid", vmid), zap.String("node", node))
	return p.deleteVM(ctx, logger, vmid, node)
}

// deleteVM handles the actual VM deletion process
func (p *Provisioner) deleteVM(ctx context.Context, logger *zap.Logger, vmid int, node string) error {
	logger.Info("stopping and deleting VM", zap.Int("vmid", vmid), zap.String("node", node))

	vmRef := proxmox.NewVmRef(proxmox.GuestID(vmid))
	vmRef.SetNode(node)

	// Stop VM first (force stop if necessary)
	logger.Info("stopping VM", zap.Int("vmid", vmid))
	if _, err := p.proxmoxClient.StopVm(ctx, vmRef); err != nil {
		logger.Warn("failed to stop VM, attempting force stop", zap.Error(err))
		// Try force shutdown
		if _, err := p.proxmoxClient.ShutdownVm(ctx, vmRef); err != nil {
			logger.Warn("failed to shutdown VM, proceeding with deletion anyway", zap.Error(err))
		}
	}

	// Give a moment for the VM to stop before deletion
	time.Sleep(2 * time.Second)

	// Delete VM
	logger.Info("deleting VM", zap.Int("vmid", vmid))
	if _, err := p.proxmoxClient.DeleteVm(ctx, vmRef); err != nil {
		logger.Error("failed to delete VM", zap.Error(err), zap.Int("vmid", vmid))
		return fmt.Errorf("failed to delete VM %d: %w", vmid, err)
	}

	logger.Info("VM successfully deprovisioned", zap.Int("vmid", vmid))
	return nil
}

// Helper methods

func (p *Provisioner) getNextVMID(ctx context.Context, node string) (int, error) {
	// Get next available VM ID from cluster
	nextid, err := p.proxmoxClient.GetNextID(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to get next VM ID: %w", err)
	}
	return int(nextid), nil
}

func (p *Provisioner) vmExists(ctx context.Context, node string, vmid int) (bool, error) {
	vmRef := proxmox.NewVmRef(proxmox.GuestID(vmid))
	vmRef.SetNode(node)
	
	_, err := p.proxmoxClient.GetVmConfig(ctx, vmRef)
	if err != nil {
		// VM doesn't exist if we get an error (likely 404)
		return false, nil
	}
	
	return true, nil
}

func (p *Provisioner) checkVMReady(ctx context.Context, node string, vmid int) error {
	vmRef := proxmox.NewVmRef(proxmox.GuestID(vmid))
	vmRef.SetNode(node)
	
	status, err := p.proxmoxClient.GetVmState(ctx, vmRef)
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	currentStatus := status["status"]
	if currentStatus == "running" {
		return nil
	}

	// VM not ready yet, retry
	return provision.NewRetryInterval(time.Second * 10)
}

// calculateVMIP calculates an IP address for a VM based on the subnet and VM ID
func (p *Provisioner) calculateVMIP(subnet string, vmid int) (string, error) {
	// Parse the subnet CIDR
	ipNet, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet format: %w", err)
	}
	
	// Get network address and calculate available host bits
	networkAddr := ipNet.Addr()
	prefixLen := ipNet.Bits()
	hostBits := 32 - prefixLen
	
	// Calculate maximum number of hosts (subtract 2 for network and broadcast addresses)
	maxHosts := (1 << hostBits) - 2
	
	// Use VM ID directly as host number, with modulo to wrap around if needed
	// Since VM IDs start from 1, we don't need to add 1 to avoid network address
	hostNum := vmid % maxHosts
	if hostNum == 0 {
		hostNum = maxHosts // If wrapping results in 0, use the last available host number
	}
	
	// Convert network address to 4-byte representation
	networkBytes := networkAddr.As4()
	
	// Add the host number to the network address
	// For IPv4, we add to the last bytes depending on subnet size
	if hostBits <= 8 {
		// /24 or larger - modify last octet only
		networkBytes[3] += byte(hostNum)
	} else if hostBits <= 16 {
		// /16 to /23 - modify last two octets
		networkBytes[2] += byte(hostNum >> 8)
		networkBytes[3] += byte(hostNum & 0xFF)
	} else if hostBits <= 24 {
		// /8 to /15 - modify last three octets
		networkBytes[1] += byte(hostNum >> 16)
		networkBytes[2] += byte((hostNum >> 8) & 0xFF)
		networkBytes[3] += byte(hostNum & 0xFF)
	} else {
		// Very large subnets - modify all four octets
		networkBytes[0] += byte(hostNum >> 24)
		networkBytes[1] += byte((hostNum >> 16) & 0xFF)
		networkBytes[2] += byte((hostNum >> 8) & 0xFF)
		networkBytes[3] += byte(hostNum & 0xFF)
	}
	
	// Create the final IP address
	vmAddr := netip.AddrFrom4(networkBytes)
	
	// Return with the original prefix length
	return fmt.Sprintf("%s/%d", vmAddr.String(), prefixLen), nil
}

// findVMByNameGlobal searches for a VM by name across all nodes and returns its VM ID and node
func (p *Provisioner) findVMByNameGlobal(ctx context.Context, vmName string) (int, string, error) {
	fmt.Printf("DEBUG: Searching for VM name: %s\n", vmName)
	
	// Use the library's built-in function to find VM by name
	vmRef, err := p.proxmoxClient.GetVmRefByName(ctx, proxmox.GuestName(vmName))
	if err != nil {
		fmt.Printf("DEBUG: GetVmRefByName failed: %v\n", err)
		// VM not found or error occurred
		return 0, "", nil
	}
	
	if vmRef == nil {
		fmt.Printf("DEBUG: VM %s not found in cluster\n", vmName)
		return 0, "", nil
	}
	
	vmID := int(vmRef.VmId())
	node := string(vmRef.Node())
	
	fmt.Printf("DEBUG: Found matching VM %d on node %s\n", vmID, node)
	return vmID, node, nil
}

// resizeDisk resizes a VM disk to the specified size
func (p *Provisioner) resizeDisk(ctx context.Context, vmRef *proxmox.VmRef, diskName, size string) error {
	// Use Proxmox API to resize the disk
	// The disk resize API endpoint is: PUT /nodes/{node}/qemu/{vmid}/resize
	params := map[string]interface{}{
		"disk": diskName,
		"size": size,
	}
	
	url := fmt.Sprintf("/nodes/%s/qemu/%d/resize", vmRef.Node(), vmRef.VmId())
	
	// Use PutWithTask for disk resize operation (PUT request, not POST)
	_, err := p.proxmoxClient.PutWithTask(ctx, params, url)
	if err != nil {
		return fmt.Errorf("failed to resize disk %s to %s: %w", diskName, size, err)
	}
	
	return nil
}

// cleanupVM removes a VM that was created but failed during setup
func (p *Provisioner) cleanupVM(ctx context.Context, vmRef *proxmox.VmRef) error {
	// Stop VM if running (ignore errors if already stopped)
	_, _ = p.proxmoxClient.StopVm(ctx, vmRef)
	
	// Give a moment for the VM to stop
	time.Sleep(1 * time.Second)
	
	// Delete the VM
	_, err := p.proxmoxClient.DeleteVm(ctx, vmRef)
	if err != nil {
		return fmt.Errorf("failed to delete VM during cleanup: %w", err)
	}
	
	return nil
}

// isoExists checks if an ISO already exists in Proxmox storage
func (p *Provisioner) isoExists(ctx context.Context, node, storage, filename string) (bool, error) {
	fmt.Printf("DEBUG: Checking if ISO exists - node: %s, storage: %s, filename: %s\n", node, storage, filename)
	
	// Create a VmRef for the storage check 
	vmRef := proxmox.NewVmRef(999999)
	vmRef.SetNode(node)
	vmRef.SetVmType("qemu")
	
	// Get storage content list to check if our ISO exists
	content, err := p.proxmoxClient.GetStorageContent(ctx, vmRef, storage)
	if err != nil {
		fmt.Printf("DEBUG: GetStorageContent failed: %v\n", err)
		return false, fmt.Errorf("failed to list storage content: %w", err)
	}
	
	expectedVolID := fmt.Sprintf("%s:iso/%s", storage, filename)
	fmt.Printf("DEBUG: Looking for ISO volid: %s\n", expectedVolID)
	
	// Check if our ISO exists in the storage content list
	if data, ok := content["data"].([]interface{}); ok {
		for _, item := range data {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if volid, exists := itemMap["volid"]; exists && volid == expectedVolID {
					fmt.Printf("DEBUG: ISO exists!\n")
					return true, nil
				}
			}
		}
	}
	
	fmt.Printf("DEBUG: ISO not found in storage content\n")
	return false, nil
}

// cleanupOldISOs removes old OMNI ISOs and keeps only the latest version
func (p *Provisioner) cleanupOldISOs(ctx context.Context, node, storage, keepFilename string) error {
	fmt.Printf("DEBUG: Starting cleanup of old ISOs, keeping: %s\n", keepFilename)
	
	// Create a VmRef for the storage check
	vmRef := proxmox.NewVmRef(999999)
	vmRef.SetNode(node)
	vmRef.SetVmType("qemu")
	
	// Get storage content list
	content, err := p.proxmoxClient.GetStorageContent(ctx, vmRef, storage)
	if err != nil {
		return fmt.Errorf("failed to list storage content for cleanup: %w", err)
	}
	
	// Find all OMNI ISOs
	var omniISOs []string
	if data, ok := content["data"].([]interface{}); ok {
		for _, item := range data {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if volid, exists := itemMap["volid"]; exists {
					if volidStr, ok := volid.(string); ok {
						// Check if this is an OMNI file with our pattern (ISO or qcow2)
						if filename := extractFilenameFromVolid(volidStr); filename != "" {
							if (isOmniISO(filename) || isOmniQcow2(filename)) && filename != keepFilename {
								omniISOs = append(omniISOs, volidStr)
								fmt.Printf("DEBUG: Found old OMNI file to delete: %s\n", filename)
							}
						}
					}
				}
			}
		}
	}
	
	// Delete old ISOs, but only if they're not mounted in any VMs
	for _, volid := range omniISOs {
		fmt.Printf("DEBUG: Checking if ISO is in use: %s\n", volid)
		inUse, err := p.isISOInUse(ctx, node, volid)
		if err != nil {
			fmt.Printf("DEBUG: Failed to check if ISO %s is in use: %v\n", volid, err)
			continue // Skip this ISO if we can't determine usage
		}
		
		if inUse {
			fmt.Printf("DEBUG: ISO is mounted in VM, skipping deletion: %s\n", volid)
			continue
		}
		
		fmt.Printf("DEBUG: Deleting old ISO: %s\n", volid)
		if err := p.deleteStorageVolume(ctx, node, storage, volid); err != nil {
			fmt.Printf("DEBUG: Failed to delete ISO %s: %v\n", volid, err)
			// Continue with other ISOs even if one fails
		} else {
			fmt.Printf("DEBUG: Successfully deleted old ISO: %s\n", volid)
		}
	}
	
	fmt.Printf("DEBUG: ISO cleanup completed, deleted %d old ISOs\n", len(omniISOs))
	return nil
}

// cleanupOldImages removes old OMNI images and keeps only the latest version
func (p *Provisioner) cleanupOldImages(ctx context.Context, node, storage, keepFilename string) error {
	fmt.Printf("DEBUG: Starting cleanup of old images, keeping: %s\n", keepFilename)
	
	// Create a VmRef for the storage check
	vmRef := proxmox.NewVmRef(999999)
	vmRef.SetNode(node)
	vmRef.SetVmType("qemu")
	
	// Get storage content list
	content, err := p.proxmoxClient.GetStorageContent(ctx, vmRef, storage)
	if err != nil {
		return fmt.Errorf("failed to list storage content for cleanup: %w", err)
	}
	
	// Find all OMNI images
	var omniImages []string
	if data, ok := content["data"].([]interface{}); ok {
		for _, item := range data {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if volid, exists := itemMap["volid"]; exists {
					if volidStr, ok := volid.(string); ok {
						// Check if this is an OMNI image with our pattern (qcow2 or old formats)
						if filename := extractFilenameFromVolid(volidStr); filename != "" {
							if (isOmniImage(filename) || isOmniQcow2(filename)) && filename != keepFilename {
								omniImages = append(omniImages, volidStr)
								fmt.Printf("DEBUG: Found old OMNI image to delete: %s\n", filename)
							}
						}
					}
				}
			}
		}
	}
	
	// Delete old images
	for _, volid := range omniImages {
		fmt.Printf("DEBUG: Deleting old image: %s\n", volid)
		if err := p.deleteStorageVolume(ctx, node, storage, volid); err != nil {
			fmt.Printf("DEBUG: Failed to delete image %s: %v\n", volid, err)
			// Continue with other images even if one fails
		} else {
			fmt.Printf("DEBUG: Successfully deleted old image: %s\n", volid)
		}
	}
	
	fmt.Printf("DEBUG: Cleanup completed, deleted %d old images\n", len(omniImages))
	return nil
}

// extractFilenameFromVolid extracts filename from volume ID (format: "storage:content/filename")
func extractFilenameFromVolid(volid string) string {
	parts := strings.Split(volid, "/")
	if len(parts) == 2 {
		return parts[1] // Return the filename part
	}
	return ""
}

// isOmniImage checks if filename matches our OMNI image pattern
func isOmniImage(filename string) bool {
	// Pattern: omni-v{version}-{hash}-nocloud-{arch}.qcow2
	return strings.HasPrefix(filename, "omni-v") && 
		   strings.Contains(filename, "-nocloud-") && 
		   strings.HasSuffix(filename, ".qcow2")
}

// isOmniISO checks if filename matches our OMNI ISO pattern
func isOmniISO(filename string) bool {
	// Pattern: omni-v{version}-{hash}-{platform}-{arch}.iso (supports any platform: nocloud, metal, etc.)
	return strings.HasPrefix(filename, "omni-v") && 
		   strings.HasSuffix(filename, ".iso")
}

// isOmniQcow2 checks if filename matches our OMNI qcow2 pattern  
func isOmniQcow2(filename string) bool {
	// Pattern: omni-v{version}-{hash}-{platform}-{arch}.qcow2 (supports any platform: nocloud, metal, etc.)
	return strings.HasPrefix(filename, "omni-v") && 
		   strings.HasSuffix(filename, ".qcow2")
}

// isISOInUse checks if an ISO is currently mounted in any VM in the cluster
func (p *Provisioner) isISOInUse(ctx context.Context, node, volid string) (bool, error) {
	fmt.Printf("DEBUG: Checking if ISO %s is in use\n", volid)
	
	// Get list of all VMs on this node
	nodeVMs, err := p.proxmoxClient.GetVmList(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get VM list: %w", err)
	}
	
	// Check each VM to see if it has this ISO mounted
	if data, ok := nodeVMs["data"].([]interface{}); ok {
		for _, item := range data {
			if vmMap, ok := item.(map[string]interface{}); ok {
				if vmid, exists := vmMap["vmid"]; exists {
					if vmidFloat, ok := vmid.(float64); ok {
						vmIDInt := int(vmidFloat)
						
						// Get VM configuration to check for mounted ISOs
						vmRef := proxmox.NewVmRef(proxmox.GuestID(vmIDInt))
						vmRef.SetNode(node)
						
						vmConfig, err := p.proxmoxClient.GetVmConfig(ctx, vmRef)
						if err != nil {
							fmt.Printf("DEBUG: Failed to get VM %d config: %v\n", vmIDInt, err)
							continue // Skip this VM if we can't get its config
						}
						
						// Check IDE CD-ROM drives for the ISO
						for i := 0; i < 4; i++ {
							ideKey := fmt.Sprintf("ide%d", i)
							if ideValue, exists := vmConfig[ideKey]; exists {
								if ideStr, ok := ideValue.(string); ok {
									// Check if this IDE contains our ISO volid
									if strings.Contains(ideStr, volid) {
										fmt.Printf("DEBUG: Found ISO %s mounted in VM %d on %s\n", volid, vmIDInt, ideKey)
										return true, nil
									}
								}
							}
						}
						
						// Also check SATA CD-ROM drives (sata0, sata1, etc.)
						for i := 0; i < 6; i++ {
							sataKey := fmt.Sprintf("sata%d", i)
							if sataValue, exists := vmConfig[sataKey]; exists {
								if sataStr, ok := sataValue.(string); ok {
									// Check if this SATA contains our ISO volid
									if strings.Contains(sataStr, volid) {
										fmt.Printf("DEBUG: Found ISO %s mounted in VM %d on %s\n", volid, vmIDInt, sataKey)
										return true, nil
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	fmt.Printf("DEBUG: ISO %s is not in use by any VM\n", volid)
	return false, nil
}

// deleteStorageVolume deletes a volume from Proxmox storage
func (p *Provisioner) deleteStorageVolume(ctx context.Context, node, storage, volid string) error {
	// Use the Proxmox API to delete the storage volume
	url := fmt.Sprintf("/nodes/%s/storage/%s/content/%s", node, storage, volid)
	
	err := p.proxmoxClient.Delete(ctx, url)
	if err != nil {
		return fmt.Errorf("failed to delete storage volume %s: %w", volid, err)
	}
	
	return nil
}

