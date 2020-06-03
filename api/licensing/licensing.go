package licensing

import (
	"path"
	"strings"
)

const (
	// GroupName is the group name for this API
	GroupName = "licensing"
	// Version is the version for this API
	Version = "v2"
	// LicenseResource is the name of the license resource
	LicenseResource = "license"
	keySeparator    = "/"
)

var (
	apiKeyPrefix = path.Join("api", "enterprise", GroupName, Version)

	// LicenseKeyBuilder is a key builder for the license
	LicenseKeyBuilder = NewKeyBuilder(
		strings.Join([]string{apiKeyPrefix, LicenseResource}, keySeparator),
	)
)

// LicenseKey returns the key to the license
func LicenseKey() string {
	return LicenseKeyBuilder.Build()
}

// LicenseURI returns the URI to the license
func LicenseURI() string {
	return path.Join("/", apiKeyPrefix, LicenseResource)
}
