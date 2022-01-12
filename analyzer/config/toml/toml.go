package toml

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/BurntSushi/toml"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&tomlConfigAnalyzer{})
}

const version = 1

var requiredExts = []string{".toml"}

type tomlConfigAnalyzer struct{}

func (a tomlConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if _, err := toml.NewDecoder(input.Content).Decode(&parsed); err != nil {
		return nil, xerrors.Errorf("unable to decode TOML (%s): %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.TOML,
				FilePath: input.FilePath,
				Content:  parsed,
			},
		},
	}, nil
}

func (a tomlConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (tomlConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTOML
}

func (tomlConfigAnalyzer) Version() int {
	return version
}
