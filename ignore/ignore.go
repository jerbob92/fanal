package main

import (
	"context"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"log"
	"os"

	_ "github.com/aquasecurity/fanal/analyzer/all"
)

func main() {
	parse()
}

func parse() error {
	ctx := context.Background()
	d := os.TempDir()
	c, err := cache.NewFSCache(d)
	if err != nil {
		log.Fatalln(err)
	}

	ar, err := local.NewArtifact("/home/jeroen/Projects/Klippa/DocHorizon/CIA/api", c, artifact.Option{
		FilePatterns: []string{
			"dockerfile:(?i)^((.*[\\.])?Dockerfile|Dockerfile([-\\.].*)?)$",
		},
	})
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(ar)

	out, err := ar.Inspect(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(out)
	return nil
}
