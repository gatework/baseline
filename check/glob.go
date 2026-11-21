package check

import (
	"path"
	"slices"
	"strings"
)

// globMatch matches name against a path.Match pattern, case-insensitively.
// A malformed pattern matches nothing.
func globMatch(pattern, name string) bool {
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	return err == nil && ok
}

// anyGlob reports whether name matches any of patterns.
func anyGlob(patterns []string, name string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return globMatch(p, name) })
}
