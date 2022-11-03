package licensing

// automatically generated file, do not edit!

import (
	"path"

	corev2 "github.com/sensu/core/v2"
	apitools "github.com/sensu/sensu-api-tools"
)

func init() {
	for alias, v := range typeMap {
		if _, ok := v.(corev2.Resource); ok {
			apitools.RegisterType(
				path.Join(GroupName, Version),
				v,
				apitools.WithAlias(alias),
			)
		}
	}
}

// typeMap is used to dynamically look up data types from strings.
var typeMap = map[string]interface{}{
	"key_builder":       &KeyBuilder{},
	"license":           &License{},
	"license_file":      &LicenseFile{},
	"signature_options": &SignatureOptions{},
}
