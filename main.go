package main

import (
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/sds"
)

func main() {
	sds.NewServer()
	// defer server.Stop()
}
