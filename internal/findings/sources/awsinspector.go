package sources

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"

	appcfg "github.com/thiagohdeplima/riskctl/internal/config"
	"github.com/thiagohdeplima/riskctl/internal/findings"
)

// Compile-time check: AWSInspectorSource satisfies FindingSource.
var _ findings.FindingSource = (*AWSInspectorSource)(nil)

// inspectorAPI is the subset of the Inspector2 client used by this source.
// Defined as an interface to allow test doubles.
type inspectorAPI interface {
	ListFindings(
		ctx context.Context,
		params *inspector2.ListFindingsInput,
		optFns ...func(*inspector2.Options),
	) (*inspector2.ListFindingsOutput, error)
}

// AWSInspectorSource retrieves vulnerability findings from AWS Inspector.
// Regions are set at construction time; AWS credentials come from the
// default SDK credential chain (environment, profile, IMDS, etc.).
type AWSInspectorSource struct {
	regions   []string
	newClient func(ctx context.Context, region string) (inspectorAPI, error)
}

// NewAWSInspectorSource creates a source that scans the given AWS regions.
func NewAWSInspectorSource(regions []string) *AWSInspectorSource {
	return &AWSInspectorSource{
		regions:   regions,
		newClient: defaultInspectorClient,
	}
}

// defaultInspectorClient creates an Inspector2 client for the given region
// using the default AWS credential chain.
func defaultInspectorClient(ctx context.Context, region string) (inspectorAPI, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return inspector2.NewFromConfig(cfg), nil
}

// ListFindings iterates configured AWS regions and aggregates all active findings.
// The cfg and query parameters are accepted to satisfy the FindingSource interface
// but are not used — regions and credentials come from the environment.
func (s *AWSInspectorSource) ListFindings(ctx context.Context, _ appcfg.Config, _ findings.Query) ([]findings.Finding, error) {
	var out []findings.Finding

	if len(s.regions) == 0 {
		return nil, fmt.Errorf("aws inspector: no regions configured")
	}

	for _, region := range s.regions {
		regional, err := s.listFindingsForRegion(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("region %s: %w", region, err)
		}
		out = append(out, regional...)
	}

	return out, nil
}

// listFindingsForRegion creates a client for a single region, fetches all
// active findings via pagination, and converts them to the canonical model.
func (s *AWSInspectorSource) listFindingsForRegion(ctx context.Context, region string) ([]findings.Finding, error) {
	client, err := s.newClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("client init: %w", err)
	}

	awsFindings, err := fetchActiveFindings(ctx, client)
	if err != nil {
		return nil, err
	}

	out := make([]findings.Finding, 0, len(awsFindings))
	for i := range awsFindings {
		out = append(out, toCanonicalFinding(awsFindings[i]))
	}
	return out, nil
}

// fetchActiveFindings paginates the Inspector2 ListFindings API,
// collecting all findings with ACTIVE status across all pages.
func fetchActiveFindings(ctx context.Context, client inspectorAPI) ([]types.Finding, error) {
	filter := activeFilter()
	var all []types.Finding
	var nextToken *string

	for {
		out, err := client.ListFindings(ctx, &inspector2.ListFindingsInput{
			FilterCriteria: filter,
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, err
		}

		all = append(all, out.Findings...)

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return all, nil
}

// activeFilter builds filter criteria that selects only ACTIVE findings.
func activeFilter() *types.FilterCriteria {
	return &types.FilterCriteria{
		FindingStatus: []types.StringFilter{
			{
				Comparison: types.StringComparisonEquals,
				Value:      aws.String("ACTIVE"),
			},
		},
	}
}

// toCanonicalFinding converts a single AWS Inspector finding to the canonical model.
func toCanonicalFinding(f types.Finding) findings.Finding {
	return findings.Finding{
		FindingID:    deref(f.FindingArn),
		Source:       "aws_inspector",
		Severity:     string(f.Severity),
		VulnID:       extractVulnID(f),
		FixAvailable: f.FixAvailable == types.FixAvailableYes,
		AssetType:    extractAssetType(f),
		AssetID:      extractAssetID(f),
		FirstSeen:    derefTime(f.FirstObservedAt),
		LastSeen:     derefTime(f.LastObservedAt),
	}
}

// extractVulnID returns the vulnerability ID (e.g. CVE) from package
// vulnerability details, or empty string if not present.
func extractVulnID(f types.Finding) string {
	if d := f.PackageVulnerabilityDetails; d != nil {
		return deref(d.VulnerabilityId)
	}
	return ""
}

// extractAssetType returns the resource type of the first resource.
func extractAssetType(f types.Finding) string {
	if len(f.Resources) > 0 {
		return string(f.Resources[0].Type)
	}
	return ""
}

// extractAssetID returns the resource ID of the first resource.
func extractAssetID(f types.Finding) string {
	if len(f.Resources) > 0 {
		return deref(f.Resources[0].Id)
	}
	return ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
