package licensing

// automatically generated file, do not edit!

import (
	"path"
	"reflect"

	corev2 "github.com/sensu/core/v2"
	apitools "github.com/sensu/sensu-api-tools"
)

func init() {
	for _, t := range typeMap {
		apitools.RegisterType(path.Join(GroupName, Version), newResource(t))
	}
}

// typeMap is used to dynamically look up data types from strings.
var typeMap = map[string]interface{}{
	"KeyBuilder":        &KeyBuilder{},
	"key_builder":       &KeyBuilder{},
	"License":           &License{},
	"license":           &License{},
	"LicenseFile":       &LicenseFile{},
	"license_file":      &LicenseFile{},
	"SignatureOptions":  &SignatureOptions{},
	"signature_options": &SignatureOptions{},
}

// Make a new Resource to avoid aliasing problems with ResolveResource.
// don't use this function. no, seriously.
func newResource(r interface{}) corev2.Resource {
	return reflect.New(reflect.ValueOf(r).Elem().Type()).Interface().(corev2.Resource)
}
