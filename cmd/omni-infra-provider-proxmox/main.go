// SPDX-License-Identifier: MIT

// Package main is the root cmd of the provider script.
package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/go-logr/logr"
	"github.com/siderolabs/omni/client/pkg/client"
	"github.com/siderolabs/omni/client/pkg/infra"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/alinanova21/omni-infra-provider-proxmox/internal/pkg/provider"
	"github.com/alinanova21/omni-infra-provider-proxmox/internal/pkg/provider/meta"
)

//go:embed data/schema.json
var schema string

//go:embed data/icon.svg
var icon []byte

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:          "provider",
	Short:        "Proxmox Omni infrastructure provider",
	Long:         `Connects to Omni as an infra provider and manages VMs in Proxmox VE`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		loggerConfig := zap.NewProductionConfig()

		logger, err := loggerConfig.Build(
			zap.AddStacktrace(zapcore.ErrorLevel),
		)
		if err != nil {
			return fmt.Errorf("failed to create logger: %w", err)
		}

		log.SetLogger(logr.Discard())

		if cfg.omniAPIEndpoint == "" {
			return fmt.Errorf("omni-api-endpoint flag is not set")
		}

		if cfg.proxmoxURL == "" {
			return fmt.Errorf("proxmox-url flag is not set")
		}

		if cfg.proxmoxUser == "" {
			return fmt.Errorf("proxmox-user flag is not set")
		}

		if cfg.proxmoxPassword == "" && cfg.proxmoxToken == "" {
			return fmt.Errorf("either proxmox-password or proxmox-token must be set")
		}

		if cfg.storagePool == "" {
			return fmt.Errorf("storage-pool flag is not set")
		}

		// Create Proxmox client
		var tlsConfig *tls.Config
		if cfg.insecureSkipTLS {
			tlsConfig = &tls.Config{InsecureSkipVerify: true}
		}

		proxmoxClient, err := proxmox.NewClient(cfg.proxmoxURL, nil, "", tlsConfig, "", 300)
		if err != nil {
			return fmt.Errorf("failed to create Proxmox client: %w", err)
		}

		if cfg.proxmoxToken != "" {
			// Set API token authentication
			logger.Info("using API token authentication", zap.String("user", cfg.proxmoxUser))
			proxmoxClient.SetAPIToken(cfg.proxmoxUser, cfg.proxmoxToken)
		} else {
			logger.Info("attempting password authentication",
				zap.String("user", cfg.proxmoxUser),
				zap.String("realm", cfg.proxmoxRealm),
				zap.String("url", cfg.proxmoxURL))
			if err := proxmoxClient.Login(cmd.Context(), cfg.proxmoxUser, cfg.proxmoxPassword, ""); err != nil {
				return fmt.Errorf("failed to login to Proxmox (user: %s, realm: %s, url: %s): %w",
					cfg.proxmoxUser, cfg.proxmoxRealm, cfg.proxmoxURL, err)
			}
			logger.Info("successfully authenticated with Proxmox")
		}

		provisioner := provider.NewProvisioner(proxmoxClient, cfg.storagePool, cfg.imageStoragePool)

		ip, err := infra.NewProvider(meta.ProviderID, provisioner, infra.ProviderConfig{
			Name:        cfg.providerName,
			Description: cfg.providerDescription,
			Icon:        base64.RawStdEncoding.EncodeToString(icon),
			Schema:      schema,
		})
		if err != nil {
			return fmt.Errorf("failed to create infra provider: %w", err)
		}

		logger.Info("starting infra provider")

		clientOptions := []client.Option{
			client.WithInsecureSkipTLSVerify(cfg.insecureSkipVerify),
		}

		if cfg.serviceAccountKey != "" {
			clientOptions = append(clientOptions, client.WithServiceAccount(cfg.serviceAccountKey))
		}

		return ip.Run(cmd.Context(), logger, infra.WithOmniEndpoint(cfg.omniAPIEndpoint), infra.WithClientOptions(
			clientOptions...,
		), infra.WithEncodeRequestIDsIntoTokens())
	},
}

var cfg struct {
	omniAPIEndpoint     string
	serviceAccountKey   string
	providerName        string
	providerDescription string
	proxmoxURL          string
	proxmoxUser         string
	proxmoxPassword     string
	proxmoxToken        string
	proxmoxRealm        string
	storagePool         string
	imageStoragePool    string
	insecureSkipVerify  bool
	insecureSkipTLS     bool
}

func main() {
	if err := app(); err != nil {
		os.Exit(1)
	}
}

func app() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer cancel()

	return rootCmd.ExecuteContext(ctx)
}

func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string) bool {
	value := os.Getenv(key)
	return value == "true" || value == "1"
}

func init() {
	rootCmd.Flags().StringVar(&cfg.omniAPIEndpoint, "omni-api-endpoint", os.Getenv("OMNI_ENDPOINT"),
		"the endpoint of the Omni API, if not set, defaults to OMNI_ENDPOINT env var.")
	rootCmd.Flags().StringVar(&meta.ProviderID, "id", getEnvDefault("PROVIDER_ID", meta.ProviderID), "the id of the infra provider, it is used to match the resources with the infra provider label.")
	rootCmd.Flags().StringVar(&cfg.serviceAccountKey, "omni-service-account-key", os.Getenv("OMNI_SERVICE_ACCOUNT_KEY"), "Omni service account key, if not set, defaults to OMNI_SERVICE_ACCOUNT_KEY.")
	rootCmd.Flags().StringVar(&cfg.providerName, "provider-name", getEnvDefault("PROVIDER_NAME", "Proxmox"), "provider name as it appears in Omni")
	rootCmd.Flags().StringVar(&cfg.providerDescription, "provider-description", getEnvDefault("PROVIDER_DESCRIPTION", "Proxmox VE infrastructure provider"), "Provider description as it appears in Omni")
	rootCmd.Flags().StringVar(&cfg.proxmoxURL, "proxmox-url", os.Getenv("PROXMOX_URL"), "Proxmox VE API endpoint URL")
	rootCmd.Flags().StringVar(&cfg.proxmoxUser, "proxmox-user", os.Getenv("PROXMOX_USER"), "Proxmox username (e.g. root@pam)")
	rootCmd.Flags().StringVar(&cfg.proxmoxPassword, "proxmox-password", os.Getenv("PROXMOX_PASSWORD"), "Proxmox password")
	rootCmd.Flags().StringVar(&cfg.proxmoxToken, "proxmox-token", os.Getenv("PROXMOX_TOKEN"), "Proxmox API token (alternative to password)")
	rootCmd.Flags().StringVar(&cfg.proxmoxRealm, "proxmox-realm", getEnvDefault("PROXMOX_REALM", "pam"), "Proxmox authentication realm")
	rootCmd.Flags().StringVar(&cfg.storagePool, "storage-pool", getEnvDefault("PROXMOX_STORAGE_POOL", "local"), "Proxmox storage pool for VM disks")
	rootCmd.Flags().StringVar(&cfg.imageStoragePool, "image-storage-pool", getEnvDefault("PROXMOX_IMAGE_STORAGE_POOL", "local"), "Proxmox storage pool for downloading images")
	rootCmd.Flags().BoolVar(&cfg.insecureSkipVerify, "insecure-skip-verify", getBoolEnv("INSECURE_SKIP_VERIFY"), "ignores untrusted certs on Omni side")
	rootCmd.Flags().BoolVar(&cfg.insecureSkipTLS, "insecure-skip-tls", getBoolEnv("INSECURE_SKIP_TLS"), "ignores untrusted certs on Proxmox side")
}
