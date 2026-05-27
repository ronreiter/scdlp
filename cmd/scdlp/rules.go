package main

import (
	"fmt"
	"strconv"

	"github.com/ronreiter/scdlp/internal/ipc"
	"github.com/spf13/cobra"
)

func listCmd() *cobra.Command {
	var verdict string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List allow/deny rules.",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			rs, err := c.ListRules(ipc.ListReq{Verdict: verdict})
			if err != nil {
				return err
			}
			fmt.Printf("%-5s %-10s %-32s %-10s %-32s\n", "ID", "VERDICT", "FILE_KEY", "ID_KIND", "IDENTITY")
			for _, r := range rs {
				idShort := r.IdentityKey
				if len(idShort) > 12 {
					idShort = idShort[:12] + "…"
				}
				fmt.Printf("%-5d %-10s %-32s %-10s %-32s\n",
					r.ID, r.Verdict, truncate(r.FileKey, 32), r.IdentityKind, idShort)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter by 'allow' or 'deny'")
	return cmd
}

func addCmd() *cobra.Command {
	var spec ipc.AddRuleSpec
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an allow/deny rule.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if spec.Verdict != "allow" && spec.Verdict != "deny" {
				return fmt.Errorf("--verdict must be allow or deny")
			}
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			id, err := c.AddRule(spec)
			if err != nil {
				return err
			}
			fmt.Printf("rule %d added\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&spec.FileKey, "file-key", "", "path or category")
	cmd.Flags().StringVar(&spec.FileKeyKind, "file-kind", "category", "path|category")
	cmd.Flags().StringVar(&spec.IdentityKey, "identity-key", "", "chain sha256 or EXE:sha256")
	cmd.Flags().StringVar(&spec.IdentityKind, "identity-kind", "chain", "chain|exe-only")
	cmd.Flags().StringVar(&spec.Verdict, "verdict", "", "allow|deny")
	cmd.Flags().StringVar(&spec.Note, "note", "", "free-form note")
	return cmd
}

func revokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <rule-id>",
		Short: "Revoke (delete) a rule by id.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			c, err := ipc.Dial(socketFlag)
			if err != nil {
				return err
			}
			defer c.Close()
			return c.RevokeRule(id)
		},
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
