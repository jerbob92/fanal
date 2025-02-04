package analyzer

import (
	"context"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

var (
	analyzers       = map[Type]analyzer{}
	configAnalyzers = map[Type]configAnalyzer{}

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

type AnalysisInput struct {
	Dir      string
	FilePath string
	Info     os.FileInfo
	Content  dio.ReadSeekerAt

	Options AnalysisOptions
}

type AnalysisOptions struct {
	Offline bool
}

type analyzer interface {
	Type() Type
	Version() int
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

type configAnalyzer interface {
	Type() Type
	Version() int
	Analyze(targetOS types.OS, content []byte) ([]types.Package, error)
	Required(osFound types.OS) bool
}

func RegisterAnalyzer(analyzer analyzer) {
	analyzers[analyzer.Type()] = analyzer
}

func RegisterConfigAnalyzer(analyzer configAnalyzer) {
	configAnalyzers[analyzer.Type()] = analyzer
}

type Opener func() (dio.ReadSeekCloserAt, error)

type AnalysisResult struct {
	m                    sync.Mutex
	OS                   *types.OS
	PackageInfos         []types.PackageInfo
	Applications         []types.Application
	Configs              []types.Config
	SystemInstalledFiles []string // A list of files installed by OS package manager
}

func (r *AnalysisResult) isEmpty() bool {
	return r.OS == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 &&
		len(r.Configs) == 0 && len(r.SystemInstalledFiles) == 0
}

func (r *AnalysisResult) Sort() {
	sort.Slice(r.PackageInfos, func(i, j int) bool {
		return r.PackageInfos[i].FilePath < r.PackageInfos[j].FilePath
	})

	for _, pi := range r.PackageInfos {
		sort.Slice(pi.Packages, func(i, j int) bool {
			return pi.Packages[i].Name < pi.Packages[j].Name
		})
	}

	sort.Slice(r.Applications, func(i, j int) bool {
		return r.Applications[i].FilePath < r.Applications[j].FilePath
	})

	for _, app := range r.Applications {
		sort.Slice(app.Libraries, func(i, j int) bool {
			if app.Libraries[i].Name != app.Libraries[j].Name {
				return app.Libraries[i].Name < app.Libraries[j].Name
			}
			return app.Libraries[i].Version < app.Libraries[j].Version
		})
	}
}

func (r *AnalysisResult) Merge(new *AnalysisResult) {
	if new == nil || new.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	if new.OS != nil {
		// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
		// In that case, OS must be overwritten with the content of /etc/oracle-release.
		// There is the same problem between Debian and Ubuntu.
		if r.OS == nil || r.OS.Family == aos.RedHat || r.OS.Family == aos.Debian {
			r.OS = new.OS
		}
	}

	if len(new.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, new.PackageInfos...)
	}

	if len(new.Applications) > 0 {
		r.Applications = append(r.Applications, new.Applications...)
	}

	r.Configs = append(r.Configs, new.Configs...)

	r.SystemInstalledFiles = append(r.SystemInstalledFiles, new.SystemInstalledFiles...)
}

type Analyzer struct {
	drivers           []analyzer
	configDrivers     []configAnalyzer
	disabledAnalyzers []Type
}

func NewAnalyzer(disabledAnalyzers []Type) Analyzer {
	var drivers []analyzer
	for analyzerType, a := range analyzers {
		if isDisabled(analyzerType, disabledAnalyzers) {
			continue
		}
		drivers = append(drivers, a)
	}

	var configDrivers []configAnalyzer
	for analyzerType, a := range configAnalyzers {
		if isDisabled(analyzerType, disabledAnalyzers) {
			continue
		}
		configDrivers = append(configDrivers, a)
	}

	return Analyzer{
		drivers:           drivers,
		configDrivers:     configDrivers,
		disabledAnalyzers: disabledAnalyzers,
	}
}

// AnalyzerVersions returns analyzer version identifier used for cache keys.
func (a Analyzer) AnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for analyzerType, aa := range analyzers {
		if isDisabled(analyzerType, a.disabledAnalyzers) {
			versions[string(analyzerType)] = 0
			continue
		}
		versions[string(analyzerType)] = aa.Version()
	}
	return versions
}

// ImageConfigAnalyzerVersions returns analyzer version identifier used for cache keys.
func (a Analyzer) ImageConfigAnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for _, ca := range configAnalyzers {
		if isDisabled(ca.Type(), a.disabledAnalyzers) {
			versions[string(ca.Type())] = 0
			continue
		}
		versions[string(ca.Type())] = ca.Version()
	}
	return versions
}

func (a Analyzer) AnalyzeFile(ctx context.Context, wg *sync.WaitGroup, limit *semaphore.Weighted, result *AnalysisResult,
	dir, filePath string, info os.FileInfo, opener Opener, opts AnalysisOptions) error {
	if info.IsDir() {
		return nil
	}
	for _, d := range a.drivers {
		// filepath extracted from tar file doesn't have the prefix "/"
		if !d.Required(strings.TrimLeft(filePath, "/"), info) {
			continue
		}
		rc, err := opener()
		if err != nil {
			return xerrors.Errorf("unable to open %s: %w", filePath, err)
		}

		if err = limit.Acquire(ctx, 1); err != nil {
			return xerrors.Errorf("semaphore acquire: %w", err)
		}
		wg.Add(1)

		go func(a analyzer, rc dio.ReadSeekCloserAt) {
			defer limit.Release(1)
			defer wg.Done()
			defer rc.Close()

			ret, err := a.Analyze(ctx, AnalysisInput{
				Dir:      dir,
				FilePath: filePath,
				Info:     info,
				Content:  rc,
				Options:  opts,
			})
			if err != nil && !xerrors.Is(err, aos.AnalyzeOSError) {
				log.Logger.Debugf("Analysis error: %s", err)
				return
			}
			result.Merge(ret)
		}(d, rc)
	}

	return nil
}

func (a Analyzer) AnalyzeImageConfig(targetOS types.OS, configBlob []byte) []types.Package {
	for _, d := range a.configDrivers {
		if !d.Required(targetOS) {
			continue
		}

		pkgs, err := d.Analyze(targetOS, configBlob)
		if err != nil {
			continue
		}
		return pkgs
	}
	return nil
}

func isDisabled(t Type, disabled []Type) bool {
	for _, d := range disabled {
		if t == d {
			return true
		}
	}
	return false
}
