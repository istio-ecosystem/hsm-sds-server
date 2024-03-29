package uds

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"istio.io/pkg/log"
)

// NewListener create a new UDS Listener to serve the gRPC Server
func NewListener(path string) (net.Listener, error) {
	// Remove unix socket before use.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		// Anything other than "file not found" is an error.
		return nil, fmt.Errorf("failed to remove unix://%s: %v", path, err)
	}

	// Attempt to create the folder in case it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		// If we cannot create it, just warn here - we will fail later if there is a real error
		log.Infof("Failed to create directory for ", path, ":", err)
	}

	var err error
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket %q: %v", path, err)
	}

	// Update file permission so that istio-proxy has permission to access it.
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("uds file %q doesn't exist", path)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		return nil, fmt.Errorf("failed to update %q permission", path)
	}

	return listener, nil
}
