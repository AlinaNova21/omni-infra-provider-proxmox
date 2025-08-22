// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"fmt"
	"net/url"

	"github.com/Telmate/proxmox-api-go/proxmox"
)

// ConfigContent_Qcow2 represents an image download configuration for Proxmox
type ConfigContent_Qcow2 struct {
	Node        string `json:"node"`
	Storage     string `json:"storage"`
	Content     string `json:"content"`
	Filename    string `json:"filename"`
	URL         string `json:"url"`
	Checksum    string `json:"checksum,omitempty"`
	Compression string `json:"compression,omitempty"`
}

// Validate checks if all required fields are present
func (config ConfigContent_Qcow2) Validate() error {
	if config.Node == "" {
		return fmt.Errorf("node is required")
	}
	if config.Storage == "" {
		return fmt.Errorf("storage is required")
	}
	if config.Content == "" {
		return fmt.Errorf("content type is required")
	}
	if config.Filename == "" {
		return fmt.Errorf("filename is required")
	}
	if config.URL == "" {
		return fmt.Errorf("URL is required")
	}

	// Validate URL format
	if _, err := url.Parse(config.URL); err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	return nil
}

// mapToApiValues converts the config to API-compatible map
func (config ConfigContent_Qcow2) mapToApiValues() map[string]interface{} {
	values := map[string]interface{}{
		"content":  config.Content,
		"filename": config.Filename,
		"url":      config.URL,
	}

	if config.Checksum != "" {
		values["checksum-algorithm"] = "sha256"
		values["checksum"] = config.Checksum
	}

	if config.Compression != "" {
		values["compression"] = config.Compression
	}

	return values
}

// DownloadQcow2FromUrl downloads a qcow2 image from URL to Proxmox storage
func (config ConfigContent_Qcow2) DownloadQcow2FromUrl(client *proxmox.Client) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	return config.download(client)
}

// download performs the actual download operation
func (config ConfigContent_Qcow2) download(client *proxmox.Client) error {
	reqbody := config.mapToApiValues()
	
	url := fmt.Sprintf("/nodes/%s/storage/%s/download-url", config.Node, config.Storage)
	
	fmt.Printf("DEBUG: Making request to: %s\n", url)
	fmt.Printf("DEBUG: Request body: %+v\n", reqbody)
	
	result, err := client.PostWithTask(context.Background(), reqbody, url)
	if err != nil {
		fmt.Printf("DEBUG: API error: %v\n", err)
		fmt.Printf("DEBUG: Error type: %T\n", err)
		
		return fmt.Errorf("API request failed: %w", err)
	}
	
	fmt.Printf("DEBUG: API response: %+v\n", result)
	return nil
}

// ImageExists checks if a qcow2 image already exists in Proxmox storage
func ImageExists(client *proxmox.Client, node, storage, filename string) (bool, error) {
	fmt.Printf("DEBUG: Checking if image exists - node: %s, storage: %s, filename: %s\n", node, storage, filename)
	
	// Try to check if the specific volume exists by attempting to get its info
	// Using the API endpoint: /nodes/{node}/storage/{storage}/content/{volume}
	volume := fmt.Sprintf("%s:import/%s", storage, filename)
	url := fmt.Sprintf("/nodes/%s/storage/%s/content/%s", node, storage, volume)
	
	fmt.Printf("DEBUG: Checking volume existence with PostWithTask: %s\n", url)
	
	// Create a VmRef for the storage check 
	// Use a high VM ID that's unlikely to exist (999999) to avoid conflicts
	vmRef := proxmox.NewVmRef(999999)
	vmRef.SetNode(node)
	vmRef.SetVmType("qemu")  // Set vmType to avoid CheckVmRef calling GetVmInfo
	
	fmt.Printf("DEBUG: Created VmRef with node and vmType, proceeding with storage content check\n")
	
	// Get storage content list to check if our volume exists
	content, err := client.GetStorageContent(context.Background(), vmRef, storage)
	if err != nil {
		fmt.Printf("DEBUG: GetStorageContent failed: %v\n", err)
		return false, fmt.Errorf("failed to list storage content: %w", err)
	}
	
	fmt.Printf("DEBUG: Storage content response: %+v\n", content)
	
	expectedVolID := fmt.Sprintf("%s:import/%s", storage, filename)
	fmt.Printf("DEBUG: Looking for volid: %s\n", expectedVolID)
	
	// Check if our volume exists in the storage content list
	if data, ok := content["data"].([]interface{}); ok {
		for _, item := range data {
			if itemMap, ok := item.(map[string]interface{}); ok {
				fmt.Printf("DEBUG: Found item: %+v\n", itemMap)
				if volid, exists := itemMap["volid"]; exists && volid == expectedVolID {
					fmt.Printf("DEBUG: Volume exists!\n")
					return true, nil
				}
			}
		}
	} else {
		fmt.Printf("DEBUG: No data array in storage content\n")
	}
	
	fmt.Printf("DEBUG: Volume not found in storage content\n")
	return false, nil
}