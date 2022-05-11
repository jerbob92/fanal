package json

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&jsonConfigAnalyzer{})
}

const version = 1

var (
	requiredExt   = ".json"
	excludedFiles = []string{types.NpmPkgLock, types.NuGetPkgsLock, types.NuGetPkgsConfig}
)

type jsonConfigAnalyzer struct{}

func (a jsonConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := json.NewDecoder(input.Content).Decode(&parsed); err != nil {
		return nil, xerrors.Errorf("unable to decode JSON (%s): %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.JSON,
				FilePath: input.FilePath,
				Content:  parsed,
			},
		},
	}, nil
}

func (a jsonConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	filename := filepath.Base(filePath)
	for _, excludedFile := range excludedFiles {
		if filename == excludedFile {
			return false
		}
	}

	return filepath.Ext(filePath) == requiredExt
}

func (jsonConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJSON
}

func (jsonConfigAnalyzer) Version() int {
	return version
}
