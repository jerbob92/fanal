package terraform

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&terraformConfigAnalyzer{})
}

const version = 1

const requiredExt = ".tf"

type terraformConfigAnalyzer struct{}

// Analyze returns a name of Terraform file
func (a terraformConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.Terraform,
				FilePath: filepath.Join(input.Dir, input.FilePath), // tfsec requires a path from working dir
			},
		},
	}, nil
}

func (a terraformConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Ext(filePath) == requiredExt
}

func (terraformConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTerraform
}

func (terraformConfigAnalyzer) Version() int {
	return version
}
