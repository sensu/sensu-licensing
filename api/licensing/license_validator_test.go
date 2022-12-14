package licensing

import (
	"crypto"
	"encoding/json"
	"testing"
	"time"

	"github.com/sensu/sensu-go/types"
	"github.com/stretchr/testify/assert"
)

var (
	// testTime is truncated to the minute to match the precision of its string
	// representation in the license JSON. The timezone is explicitly set to
	// UTC because otherwise timestamps won't match their deserialized
	// counterparts on systems that have their timezone set to UTC. See
	// https://github.com/golang/go/issues/19486#issuecomment-285536551
	now = time.Now().Truncate(time.Minute).UTC()

	mockedSignatureOptions = SignatureOptions{
		Algorithm:  "PSS",
		Hash:       HashAlgorithm(crypto.SHA256),
		SaltLength: 20,
	}

	// RSA private key used for testing signature verification
	// generated with command: openssl genrsa 2048
	testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA4ye3Vjxs0GxgJEpQsyFBe6/dI+kdXBh8tcadMxaXMHl7JfE0
611HDET8OXBO98d/xGDsGe+Omi4ahFdsCL0DWVZvXUe3EV6Ze5knZ11Edw/Pz/Si
OzB/T2VCufdsfHz9xbX3pF+UeqO5iHYsM595Sd/9amLrhMlO5c0o2mOF8IeUGuFQ
PtMFABmMZAkjAv5Rs6WHrlLxCxGLq61wmiX+68ZVPTheDtoJj/0DyU97HBlTmIR6
gsWj+nayj2Cx1BLm00teoTc1mHM4C7iHP3QCnBX9AcMJzVgOU2EMyz44vFOlaON+
drBLjXnWg9xKdjAIhU/6hUoS+dwl+GbmwFk1XQIDAQABAoIBAQDUq6R8eoouAKlq
kKFJdINId/iE3IX+aXapAVDAOhBG9BWWCmRPT79q/1Ndu4ZTeVZn1451IdHTDAML
kIW3EK+H/uK45KHDA1yTWWqI3ctx5T3dJt6Up+0pulZkof/R9XvqlVlLbaknwQ29
c1Yi5tW5kppB9mcmpQrXH+N1w+Pssl7+6jvYtIUsKrGSimNSZVz1ZvvilkAh5jxW
+cxci/BTRJGEK9g+XITfOLcsO37xvC+kN0CU1IzubQRDhUMLmkEBr2yFa8jPGDVk
W3y+grbfCaTZ/6qeHC6sAdUAt5Ardbmwq+kWJvqWoXqs/k/dIhc1GfUFUN51lyJU
oSnN4atBAoGBAPgWsMyZ1QhrgAxZybyrMe5R1pHx68Bh76GpkBwauPnmyMw5Ct+X
WwvNLbwLdo1nL+fhu7r4r9Szv1wYWqt1uRfFM8xGVYbgSz0GOpx0C2h0njMCWzcK
e1fdVVzplpwg++crU9GMqfv6m3sMDeH2ocUw2N+Laio2f52OX6MkvdVlAoGBAOpm
IbumDwbMsRMKFtrFJDdpb35pbNPz9tJ/MHM0N0TsvNQ0i4BG0/MSonXfzFk4VR35
qU+ucheX+7FZxRG0gIZMw/4cqfcrtMZXJ9B3v8vOB51jvuMM7sRULoM8e1+/Drlm
JoC0c+/5BXQ7fyYah4cQvJbaTtdwJu/JVSqPzTyZAoGASSOfYeJkPMQ8jueVowqx
gLod0Q8KWsBEvltYAgEa0YnpXtPeUca0b8lAl3SlsdBe/jS9fMS+Sa3oV4VSjcP6
Gnjn6Ww+4LGVXNtOQjuv9U6UKSOjspljfabh+K9g2Iyc1y0d2+RlZMUgO2l1Wk20
qYbaGSVn2iQRAWks5tL5KEUCgYEApwUDQFyBFI1CF5j21AfpWHqOcXrZiuWpmC/8
6/nm7/voSSTvygWt/OPoUymWyHQ1YliFZjudHGa1d5fJrmX5trh4Z1cxXOgNtc5g
llDdn3E9R87NM6gBcm+xfN3Z402WRlEdWlQ60GGWm03Ruerpazpnxu3jg+tsMyw4
vU0eJvECgYEAvM/pbaGQKKCCQgG+pVEBOXKiJim0nSCFkkAv47kYaLOt2Eb+Lj+j
kkmezMzYZtS0Qd9lURVXGBC7T59gulk9+ICSUmo+QlbDdQx2e2XXf3yn5cCLvmW4
RBHGPy1/fRAeedVEYD7JBkctoWhU0dQNlAkIqQGTzUWv1pGObBGNY60=
-----END RSA PRIVATE KEY-----`

	// RSA public key corresponding to testPrivateKey.
	// generated with command: openssl rsa -in /path/to/key.pem -pubout
	testPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4ye3Vjxs0GxgJEpQsyFB
e6/dI+kdXBh8tcadMxaXMHl7JfE0611HDET8OXBO98d/xGDsGe+Omi4ahFdsCL0D
WVZvXUe3EV6Ze5knZ11Edw/Pz/SiOzB/T2VCufdsfHz9xbX3pF+UeqO5iHYsM595
Sd/9amLrhMlO5c0o2mOF8IeUGuFQPtMFABmMZAkjAv5Rs6WHrlLxCxGLq61wmiX+
68ZVPTheDtoJj/0DyU97HBlTmIR6gsWj+nayj2Cx1BLm00teoTc1mHM4C7iHP3QC
nBX9AcMJzVgOU2EMyz44vFOlaON+drBLjXnWg9xKdjAIhU/6hUoS+dwl+GbmwFk1
XQIDAQAB
-----END PUBLIC KEY-----`
)

// NB:
// The following three test data objects are signed with the Sensu private key.

// expiredLicensePayload returns an expired but signed license
func expiredLicensePayload() []byte {
	return []byte(`{"type":"LicenseFile","api_version":"licensing/v2","metadata":{},"spec":{"license":{"version":1,"issuer":"Sensu, Inc.","accountName":"Sensu","accountID":42,"issued":"2019-02-03T18:32:59-05:00","validUntil":"0001-01-01T00:00:00Z","plan":"Testing Only","features":["all"],"signature":{"algorithm":"PSS","hashAlgorithm":"SHA256","saltLength":20}},"signature":"hKlv8Hr4pH8QEtbxUQ4S1og02iuR1TlyoWlLpmRAReWI8Ri6XIy6h6TnltlCMmrV5PWgUPzRC0R/HRg8rOoMvTU/nvbqd0bomWHJjJESc4S7odYgzUa9G2ZGBiQdCLmyXCXxNUAoXZ0eVyJsKyXa8COWCqpE4FkNe4eFgQstbCFPfj7m2lHfvvZhxfiIf0s01WHy/DdZ4F4vnRNVxfJlK+6r3WS03/lsQrzkpTSbyH1aXd3yiMe3M02DPm5cFBhDkkf7LEm8lGiYXvh83dUVP0sYR9k358OW9/1dSt1y4P4hpQb18e67PtIlJZ8KOiRuzA1W/zB+lUbnwmAbsnSHBA==","metadata":{}}}`)
}

// invalidLicensePayload returns a license payload with an invalid but signed
// license
func invalidLicensePayload() []byte {
	return []byte(`{"type":"LicenseFile","api_version":"licensing/v2","metadata":{},"spec":{"license":{"version":0,"issuer":"Sensu, Inc.","accountName":"Sensu","accountID":42,"issued":"2019-02-03T12:36:31-05:00","validUntil":"9999-12-04T15:30:07Z","plan":"Testing Only","features":["all"],"signature":{"algorithm":"PSS","hashAlgorithm":"SHA256","saltLength":20}},"signature":"Fw3hdLkIpY27IwSgaNJdNCpBaDPd/MguCfiEC8gwd6yigHTdLs0BcNhg9AkpAt3T/9QEIWJNQFHIVR83ClOhpHkQXiJBsISeX4y0zvYTknbbqpq53OSJRGmTof8oNGUVzlOThsLKow7w/HT9lJsOdV+3GjUqx3FCiOkvkfgfhQOG3KnyVnd8avtlA48QwmVQbEMmmlxKVIl29b9t5AHEn6DJQnvUZwf3xKgEM4YmTwSWWbyjtCLYPLpp3Ix3oaAJqNHlvtSLYB4uCW7IQeB2flXZ7CbKkE8oScYS00vL3uUuii+MpNHe71LICjlrXxjsMM65MZV6xVE5zR79jIX3lg==","metadata":{}}}`)
}

// licensePayload returns a license payload with a valid and signed license
func licensePayload() []byte {
	return []byte(`{"type":"LicenseFile","api_version":"licensing/v2","metadata":{},"spec":{"license":{"accountID":42,"accountName":"Sensu","features":["all"],"issued":"2019-02-03T12:33:02-05:00","issuer":"Sensu, Inc.","plan":"Testing Only","signature":{"algorithm":"PSS","hashAlgorithm":"SHA256","saltLength":20},"validUntil":"9999-12-04T15:30:07Z","version":1},"signature":"Eu47Je14rZU79iATUR0u8OxdzyXkQcuNQoMek8t+BGLwTUqOMMIVDntOcSPu6v0So2hsxyGUvv3BKNYI67Tt9r0ia10tfmE5MTkjVw1095+fDGge5AGrGGGZZkJnihOB5itFmK8XjEvQV9RQLCYSzAbBxIDeivLu7CnOJlPP54Gv+NdNs78dwMyMr0bsrbfWpAymb2Dmg0kLKMy+pvbWem2J/xv992n8QQDndUNbQCVbPSJjYl7YQDJwlR1EYkGtV88qe2HUqNwpyCNLLuQKxbqIRO2F2qt4+9Oifg+bmlsvEAF3ZIYnzYtTh8H8iJviQrs2oSnNvn0l6Cps+2W2gA=="}}`)
}

// licenseFile returns a valid license file for use in testing
func licenseFile(data []byte) *LicenseFile {
	wrapper := &types.Wrapper{}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		panic(err)
	}
	return wrapper.Value.(*LicenseFile)
}

func testMockLicenseFile() *LicenseFile {
	return &LicenseFile{
		License: License{
			Version:          1,
			Issuer:           "Sensu, Inc.",
			AccountName:      "Acme Corp.",
			AccountID:        573,
			Issued:           Timestamp(now),
			ValidUntil:       Timestamp(now.Add(time.Duration(60*24) * time.Hour)),
			Plan:             "Violent Blue",
			Features:         []string{"all"},
			SignatureOptions: mockedSignatureOptions,
		},
	}
}

// Test that serializing and deserializing a license produces the same object.
func TestLicenseDeserialization(t *testing.T) {
	file := licenseFile(licensePayload())
	file.Annotations = nil
	file.Labels = nil
	encodedFile, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}

	decodedFile := &LicenseFile{}
	err = json.Unmarshal(encodedFile, decodedFile)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, file, decodedFile, "deserialized license should be identical to original")
	assert.Equal(t, file.License, decodedFile.License, "deserialized license details should be identical to original")
}

// Test that signature verification fails on a bad public key
func TestVerifySignatureBadPublicKey(t *testing.T) {
	file := testMockLicenseFile()
	if err := SignLicenseFile(file, testPrivateKey); err != nil {
		t.Fatal(err)
	}

	badPublicKey := "nokey"
	data, err := json.Marshal(file.License)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifySignature(data, file.Signature, file.License.SignatureOptions, badPublicKey); err == nil {
		t.Fatal("expected non-nil error")
	}

	// SENSU_PUBLIC_SIGNING_KEY is a well formatted but incorrect public key
	if err := VerifySignature(data, file.Signature, file.License.SignatureOptions, SensuPublicSigningKey); err == nil {
		t.Fatal("expected non-nil error")
	}
}

// Test that license deserialization fails on bad or unsupported hash algo
func TestUnsupportedHashAlgo(t *testing.T) {
	ha := HashAlgorithm(crypto.MD5)

	_, err := ha.MarshalJSON()
	assert.NotNil(t, err)

	unsupportedHashAlgoJSON := []byte(`"MD5"`)
	err = ha.UnmarshalJSON(unsupportedHashAlgoJSON)
	assert.NotNil(t, err)
}

// Test that license deserialization succeeds on supported hash algo
func TestSupportedHashAlgo(t *testing.T) {
	ha := HashAlgorithm(crypto.SHA256)

	_, err := ha.MarshalJSON()
	assert.Nil(t, err)

	unsupportedHashAlgoJSON := []byte(`"SHA256"`)
	err = ha.UnmarshalJSON(unsupportedHashAlgoJSON)
	assert.Nil(t, err)
}

// Test that license signature verification fails on unsupported sig algo
func TestUnsupportedSignatureAlgo(t *testing.T) {
	badFile := testMockLicenseFile()
	badFile.License.SignatureOptions.Algorithm = "bad"

	if err := SignLicenseFile(badFile, testPrivateKey); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(badFile.License)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(data, badFile.Signature, badFile.License.SignatureOptions, testPublicKey); err == nil {
		t.Fatal("expected non-nil error")
	}
}

// Test license signature verification using a locally-generated license
func TestLicenseSignatureVerification(t *testing.T) {
	file := testMockLicenseFile()
	if err := SignLicenseFile(file, testPrivateKey); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(file.License)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifySignature(data, file.Signature, file.License.SignatureOptions, testPublicKey); err != nil {
		t.Fatal(err)
	}
}
