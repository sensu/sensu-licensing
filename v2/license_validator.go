package licensing

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// SensuPublicSigningKey is a public RSA key used for license signature
// validation. The corresponding private key is used by Account Manager to
// generate signed licenses.
const SensuPublicSigningKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2DAERnXE52Cw6ukFuvQ
4ixaN608XHf45mW4pbvucKqCqfyLHDM3FC4wzZIuJSHpNcVw2OfZ5OCs6SDkFMhA
DfS0IxqoJoRX3dO1Yl4CcWKc3/6MZsFJ6jc5FrlQmTVprJMGZb5vuiYkSsJTNjdS
wI4FBmM0UlRdrg7z7kqVWBtRIN++AY01OshGc+GxzsYQKh2fCl3qrivrD9F0ger8
oHmcLz52u2NZBlDKvOXufKsO6FJxHEe8xgeLS9tbqYoQeiC3qfKbeB0EX2COl3xV
92xONQZ+mCmYim++ThAnqNjKPc0wdVX14hBhss6B3r/1PGLiUpkPwOOaakjyTyZJ
hwIDAQAB
-----END PUBLIC KEY-----`

// VerifySignature verifies that the license data matches its signature.
func VerifySignature(data, signature []byte, opts SignatureOptions, pubKeyPem string) error {
	if opts.Algorithm != "PSS" {
		return fmt.Errorf("Unsupported signature algorithm %q", opts.Algorithm)
	}
	pubKey, err := loadPublicKey(pubKeyPem)
	if err != nil {
		return err
	}

	hasher := crypto.Hash(opts.Hash)
	hash, err := hash(data, hasher)
	if err != nil {
		return fmt.Errorf("Could not compute the cryptographic hash of the license: %s", err)
	}

	pssOpts := rsa.PSSOptions{
		SaltLength: opts.SaltLength,
		Hash:       hasher,
	}

	return rsa.VerifyPSS(pubKey, hasher, hash, signature, &pssOpts)
}

// Load a PEM-encoded RSA public key into an rsa.PublicKey
func loadPublicKey(pemStr string) (*rsa.PublicKey, error) {
	// get next pem encoded block, and throw away rest of input
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("Unrecognized public key format")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Could not parse the public key: %s", err)
	}

	switch pub.(type) {
	case *rsa.PublicKey:
		break
	default:
		return nil, errors.New("Unsupported public key format, must be RSA")
	}

	return pub.(*rsa.PublicKey), err
}
