package main

import (
	"fmt"
	"os"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/cmd"
)

func main() {
	rootCmd := cmd.NewRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("SDS Server start error: ", err)
		os.Exit(-1)
	}
}
