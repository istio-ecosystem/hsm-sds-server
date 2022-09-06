package cmd

import (
	"context"
	"flag"
	"fmt"

	"github.com/spf13/cobra"
	"istio.io/pkg/log"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/sds"
)

var (
	kubeconfig    string
	configContext string
)

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "sds-server",
		Short:        "SDS Server",
		Long:         "SDS server provides Secret Discovery Service based back by Intel SGX enclave.",
		SilenceUsage: true,
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},
		PreRunE: func(c *cobra.Command, args []string) error {
			addFlags(c)
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			log.Info("Start the Secret Discovery Service back by Intel SGX......")
			sdsServer := sds.NewServer(kubeconfig, configContext)
			if sdsServer == nil {
				return fmt.Errorf("failed to create SDS grpc server!")
			}
			err := sdsServer.Start(context.Background())
			return err
		},
	}

	rootCmd.PersistentFlags().StringVarP(&kubeconfig, "kubeconfig", "c", "",
		"Kubernetes configuration file")
	rootCmd.PersistentFlags().StringVar(&configContext, "context", "",
		"The name of the kubeconfig context to use")

	addFlags(rootCmd)
	addFlags(waitCmd)
	rootCmd.AddCommand(waitCmd)
	return rootCmd
}

// AddFlags adds all command line flags to the given command.
func addFlags(rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
}
