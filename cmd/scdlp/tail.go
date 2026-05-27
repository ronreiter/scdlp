package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/spf13/cobra"
)

func tailCmd() *cobra.Command {
	var sinceDur time.Duration
	var limit int
	var verdict string
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show recent decisions.",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			var since int64
			if sinceDur > 0 {
				since = time.Now().Add(-sinceDur).Unix()
			}
			rows, err := c.TailAudit(context.Background(), ipc.TailReq{
				Since: since, Verdict: verdict, Limit: limit,
			})
			if err != nil {
				return err
			}
			for _, r := range rows {
				ts := time.Unix(r.TS, 0).Format(time.RFC3339)
				fmt.Printf("%s  %-5s  %-20s  pid=%-6d  exe=%s  via=%s\n",
					ts, r.Verdict, truncate(r.FileKey, 20), r.ProcessPID,
					r.ProcessExe, r.ProcessChain)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&sinceDur, "since", time.Hour, "show events newer than this duration")
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter by verdict")
	cmd.Flags().IntVar(&limit, "limit", 100, "max rows")
	return cmd
}
