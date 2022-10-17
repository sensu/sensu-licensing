package licensing

// automatically generated file, do not edit!

import (
	"path"

	corev2 "github.com/sensu/core/v2"
	"github.com/sensu/sensu-api-tools/apis"
)

func init() {
	for alias, v := range typeMap {
		if _, ok := v.(corev2.Resource); ok {
			apis.RegisterType(
				path.Join(GroupName, Version),
				v,
				apis.WithAlias(alias),
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
