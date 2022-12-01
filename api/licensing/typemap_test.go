package licensing

import (
	"testing"

	corev2 "github.com/sensu/core/v2"
	apitools "github.com/sensu/sensu-api-tools"
)

func TestLicenseFile(t *testing.T) {
	var _ corev2.Resource = new(LicenseFile)
	v, err := apitools.Resolve("licensing/v2", "LicenseFile")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*LicenseFile); !ok {
		t.Error("expected LicenseFile")
	}
}
