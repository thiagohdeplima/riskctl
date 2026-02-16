package findings

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thiagohdeplima/riskctl/internal/config"
	"github.com/thiagohdeplima/riskctl/internal/findings"
	"github.com/thiagohdeplima/riskctl/internal/findings/sources"
	"github.com/thiagohdeplima/riskctl/internal/renderer"
)

var FindingListCmd = &cobra.Command{
	Use:   "list",
	Short: "retrieve vulnerabilities from a source",
	Run:   ExecFindingListCmd,
}

func init() {
	FindingCmd.AddCommand(FindingListCmd)
}

func ExecFindingListCmd(cmd *cobra.Command, args []string) {
	var r = renderer.JSONRenderer{}
	var l = config.ConfigLoader{}
	var s = sources.NewAWSInspectorSource()

	cfg, err := l.Load()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	data, err := s.ListFindings(cmd.Context(), cfg, findings.Query{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := r.Render(cmd.Context(), data, os.Stdout); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
