package findings

import (
	"github.com/spf13/cobra"
)

var FindingCmd = &cobra.Command{
	Use:   "findings",
	Short: "Manage vulnerability findings",
}

func init() {
	FindingCmd.AddCommand(FindingListCmd)
}
