package licensing

import "path"

const (
	// Root is the root of the sensu keyspace.
	Root = "/sensu.io"
)

// KeyBuilder builds multi-tenant resource keys.
type KeyBuilder struct {
	resourceName         string
	namespace            string
	includeTrailingSlash bool
}

// NewKeyBuilder creates a new KeyBuilder.
func NewKeyBuilder(resourceName string) KeyBuilder {
	builder := KeyBuilder{resourceName: resourceName}
	return builder
}

// Build builds a key from the components it is given.
func (b KeyBuilder) Build(keys ...string) string {
	items := append(
		[]string{
			Root,
			b.resourceName,
			b.namespace,
		},
		keys...,
	)

	key := path.Join(items...)

	// In order to not inadvertently build a key that could list across
	// namespaces, we need to make sure that we terminate the key with the key
	// separator when a namespace is involved without a specific object name
	// within it.
	if b.namespace != "" {
		if len(keys) == 0 || keys[len(keys)-1] == "" {
			key += keySeparator
		}
	}

	// Be specific when listing sub-resources for a specific resource.
	if b.includeTrailingSlash {
		key += keySeparator
	}

	return key
}
