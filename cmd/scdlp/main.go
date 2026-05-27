// Command scdlp is the local CLI to the scdlp-agent daemon.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func defaultSocket() string {
	if u := os.Getenv("SCDLP_SOCKET"); u != "" {
		return u
	}
	return filepath.Join(os.TempDir(), "scdlp.sock")
}

var socketFlag string

func main() {
	root := &cobra.Command{
		Use:   "scdlp",
		Short: "Local CLI for the scdlp agent.",
	}
	root.PersistentFlags().StringVar(&socketFlag, "socket", defaultSocket(), "IPC socket path")

	root.AddCommand(statusCmd(), listCmd(), addCmd(), revokeCmd(), tailCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
