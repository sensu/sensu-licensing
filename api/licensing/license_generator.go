package licensing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
)

// hash generates the cryptographic hash of the given data
func hash(data []byte, hashAlgorithm crypto.Hash) ([]byte, error) {
	digest := hashAlgorithm.New()
	if _, err := digest.Write(data); err != nil {
		return nil, err
	}

	return digest.Sum(nil), nil
}

// SignLicenseFile signs the provided license file by using the signature
// options specified in the license, and fills the signature field with the
// computed signature
func SignLicenseFile(file *LicenseFile, privateKeyPem string) error {
	encodedLicense, err := json.Marshal(&file.License)
	if err != nil {
		return err
	}

	pk, err := loadPrivateKey(privateKeyPem)
	if err != nil {
		return err
	}

	signature, err := signData(encodedLicense, pk, &file.License.SignatureOptions)
	if err != nil {
		return err
	}

	file.Signature = signature
	return nil
}

// loadPrivateKey from PEM format
func loadPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	// get next pem encoded block, and throw away rest of input
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Unrecognized private key format")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key, err
}

// signData based on the given signature options
func signData(data []byte, pk *rsa.PrivateKey, so *SignatureOptions) ([]byte, error) {
	hashAlgorithm := crypto.Hash(so.Hash)
	hash, _ := hash(data, hashAlgorithm)

	pssOptions := rsa.PSSOptions{
		SaltLength: so.SaltLength,
		Hash:       hashAlgorithm,
	}
	return rsa.SignPSS(rand.Reader, pk, hashAlgorithm, hash, &pssOptions)
}
