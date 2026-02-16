package findings

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/thiagohdeplima/riskctl/internal/config"
	findingspkg "github.com/thiagohdeplima/riskctl/internal/findings"
	"github.com/thiagohdeplima/riskctl/internal/findings/sources"
	"github.com/thiagohdeplima/riskctl/internal/renderer"
)

var FindingCmd = &cobra.Command{
	Use:   "findings",
	Short: "Manage vulnerability findings",
}

var FindingListCmd = &cobra.Command{
	Use:   "list",
	Short: "retrieve vulnerabilities from a source",
	Run:   ExecFindingListCmd,
}

func init() {
	FindingCmd.AddCommand(FindingListCmd)
}

func ExecFindingListCmd(cmd *cobra.Command, args []string) {
	var render = renderer.JSONRenderer{}
	var loader = config.ConfigLoader{}

	cfg, err := loader.Load()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	src := sources.NewAWSInspectorSource()
	findings, err := src.ListFindings(cmd.Context(), cfg, findingspkg.Query{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := render.Render(cmd.Context(), findings, os.Stdout); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
