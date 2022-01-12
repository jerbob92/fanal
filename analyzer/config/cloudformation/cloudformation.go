package cloudformation

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&cloudFormationConfigAnalyzer{})
}

const version = 1

var requiredExts = []string{".yaml", ".json", ".yml"}

var awsConfigurationRegex = regexp.MustCompile(`(?i)(?m)^\s*?["|]?AWSTemplateFormatVersion[:|"]?`)
var cloudFormationMatchRegex = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?m)^\s*?["|]?Resources[:|"]?`),
	regexp.MustCompile(`(?i)(?m)^\s*?["|]?Parameters[:|"]?`),
}

type cloudFormationConfigAnalyzer struct{}

// Analyze returns a results of CloudFormation file
func (a cloudFormationConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read the CloudFormation file: %w", err)
	}

	if looksLikeCloudFormation(content) {
		return &analyzer.AnalysisResult{
			Configs: []types.Config{
				{
					Type:     types.CloudFormation,
					FilePath: filepath.Join(input.Dir, input.FilePath),
				},
			},
		}, nil
	}
	return &analyzer.AnalysisResult{}, nil
}

func (a cloudFormationConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	for _, extension := range requiredExts {
		if filepath.Ext(filePath) == extension {
			return true
		}
	}
	return false
}

func (cloudFormationConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCloudFormation
}

func (cloudFormationConfigAnalyzer) Version() int {
	return version
}

func looksLikeCloudFormation(content []byte) bool {

	if awsConfigurationRegex.MatchString(string(content)) {
		return true
	}

	for _, regex := range cloudFormationMatchRegex {
		if !regex.MatchString(string(content)) {
			return false
		}
	}

	return true
}
