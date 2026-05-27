package main

import (
	"fmt"

	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report agent health.",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			st, err := c.Status()
			if err != nil {
				return err
			}
			fmt.Printf("healthy:        %v\n", st.Healthy)
			fmt.Printf("mode:           %s\n", st.Mode)
			fmt.Printf("uptime (s):     %d\n", st.UptimeSec)
			fmt.Printf("rules total:    %d\n", st.RulesTotal)
			return nil
		},
	}
}
