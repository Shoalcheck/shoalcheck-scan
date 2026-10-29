// Package envx reads the product's environment variables under the current name and, until the old name is
// retired, under the name they carried before the product was renamed from Assay to Shoalcheck.
//
// A RENAME MUST NOT SILENTLY DROP A SETTING. An operator whose CI exports ASSAY_INSTALL_KEY, or whose shell sets
// ASSAY_HOME, would otherwise get unsigned readings in a different directory with no word about why. The new
// name wins when both are set.
package envx

import (
	"os"
	"strings"
)

const (
	current = "SHOALCHECK_"
	legacy  = "ASSAY_"
)

// Get returns the variable's value, or its pre-rename twin's when the variable itself is unset or empty.
func Get(name string) string {
	v, _ := Lookup(name)
	return v
}

// Lookup is Get with the presence bit: it reports whether either name was set at all.
func Lookup(name string) (string, bool) {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v, true
	}
	if strings.HasPrefix(name, current) {
		if v, ok := os.LookupEnv(legacy + strings.TrimPrefix(name, current)); ok {
			return v, true
		}
	}
	return os.LookupEnv(name)
}
