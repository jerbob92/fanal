package yaml

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/config/parser/yaml"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&yamlConfigAnalyzer{
		parser: &yaml.Parser{},
	})
}

const version = 1

var requiredExts = []string{".yaml", ".yml"}

type yamlConfigAnalyzer struct {
	parser *yaml.Parser
}

func (a yamlConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read the yaml content: %w", err)
	}

	// YAML might have sub documents separated by "---"
	//
	// If the current configuration contains multiple configurations, evaluate each policy
	// independent of one another and aggregate the results under the same file name.
	docs := a.parser.SeparateSubDocuments(content)

	var configs []types.Config
	for _, doc := range docs {
		parsed, err := a.parser.Parse(doc)
		if err != nil {
			return nil, xerrors.Errorf("unable to parse YAML (%a): %w", input.FilePath, err)
		}

		configs = append(configs, types.Config{
			Type:     types.YAML,
			FilePath: input.FilePath,
			Content:  parsed,
		})
	}

	return &analyzer.AnalysisResult{
		Configs: configs,
	}, nil
}

func (a yamlConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (yamlConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYaml
}

func (yamlConfigAnalyzer) Version() int {
	return version
}
