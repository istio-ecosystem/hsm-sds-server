package cmd

import (
	"fmt"
	"flag"

	"github.com/spf13/cobra"
	"istio.io/pkg/log"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/sds"
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
			mTLSServer := sds.NewServer()
			if mTLSServer == nil {
				return fmt.Errorf("failed to create mTLS SDS grpc server!")
			}
			mTLSErr := mTLSServer.StartmTLSSDSService()
			return mTLSErr
		},
	}

	addFlags(waitCmd)
	rootCmd.AddCommand(waitCmd)
	return rootCmd
}

// AddFlags adds all command line flags to the given command.
func addFlags(rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
}
