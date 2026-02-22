// Package version holds the build-time version variables for the dp binary.
// The zero values ("dev", "none", "unknown") are used for local builds.
// GoReleaser injects the real values via -ldflags at release time.
package version

import "fmt"

// These variables are overridden by GoReleaser ldflags at release time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info returns the formatted version string printed by dp version.
func Info() string {
	return fmt.Sprintf(
		"dp version %s\ncommit: %s\nbuilt: %s\n",
		Version,
		Commit,
		Date,
	)
}
