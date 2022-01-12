package config

import (
	"sort"
)

type ScannerOption struct {
	Trace       bool
	Namespaces  []string
	PolicyPaths []string
	DataPaths   []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}
