package docker

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/config/parser/dockerfile"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&dockerConfigAnalyzer{
		parser: &dockerfile.Parser{},
	})
}

const version = 1

var requiredFile = "Dockerfile"

type dockerConfigAnalyzer struct {
	parser *dockerfile.Parser
}

func (s dockerConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parsed, err := s.parser.Parse(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse Dockerfile (%s): %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.Dockerfile,
				FilePath: input.FilePath,
				Content:  parsed,
			},
		},
	}, nil
}

// Required does a case-insensitive check for filePath and returns true if
// filePath equals/startsWith/hasExtension requiredFile
func (s dockerConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	if strings.EqualFold(base, requiredFile+ext) {
		return true
	}
	if strings.EqualFold(ext, "."+requiredFile) {
		return true
	}

	return false
}

func (s dockerConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (s dockerConfigAnalyzer) Version() int {
	return version
}
