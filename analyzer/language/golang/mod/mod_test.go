package mod

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func Test_gomodAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/gomod_many.mod",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoMod,
						FilePath: "testdata/gomod_many.mod",
						Libraries: []types.Package{
							{Name: "github.com/BurntSushi/toml", Version: "1.0.0"},
							{Name: "github.com/cpuguy83/go-md2man/v2", Version: "2.0.1"},
							{Name: "github.com/davecgh/go-spew", Version: "1.1.1"},
							{Name: "github.com/kr/pretty", Version: "0.2.1"},
							{Name: "github.com/kr/text", Version: "0.1.0"},
							{Name: "github.com/pmezard/go-difflib", Version: "1.0.0"},
							{Name: "github.com/russross/blackfriday/v2", Version: "2.1.0"},
							{Name: "github.com/shurcooL/sanitized_anchor_name", Version: "1.0.0"},
							{Name: "github.com/stretchr/objx", Version: "0.3.0"},
							{Name: "github.com/stretchr/testify", Version: "1.7.0"},
							{Name: "github.com/urfave/cli", Version: "1.22.5"},
							{Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1"},
							{Name: "gopkg.in/check.v1", Version: "1.0.0-20201130134442-10cb98267c6c"},
							{Name: "gopkg.in/yaml.v2", Version: "2.4.0"},
							{Name: "gopkg.in/yaml.v3", Version: "3.0.0-20210107192922-496545a6307b"},
						},
					},
				},
			},
		}, {
			name:      "sad path",
			inputFile: "testdata/invalid.txt",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := gomodAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			if got != nil {
				sort.Slice(got.Applications[0].Libraries, func(i, j int) bool {
					return got.Applications[0].Libraries[i].Name < got.Applications[0].Libraries[j].Name
				})
				sort.Slice(tt.want.Applications[0].Libraries, func(i, j int) bool {
					return tt.want.Applications[0].Libraries[i].Name < tt.want.Applications[0].Libraries[j].Name
				})
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_gomodAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "test/go.mod",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "a/b/c/d/test.mod",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gomodAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
