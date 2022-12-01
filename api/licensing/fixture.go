package licensing

import (
	"crypto"

	corev2 "github.com/sensu/core/v2"
)

// TODO(eric): make this a real fixture
func FixtureLicenseFile(name string) *LicenseFile {
	return &LicenseFile{
		License: License{
			SignatureOptions: SignatureOptions{
				Algorithm: "PSS",
				Hash:      HashAlgorithm(crypto.SHA256),
			},
			EntityLimit: 20,
		},
		ObjectMeta: corev2.ObjectMeta{
			Name: name,
		},
	}
}
