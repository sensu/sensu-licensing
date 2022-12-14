package licensing

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"

	corev2 "github.com/sensu/core/v2"
)

const (
	// SupportedLicenseVersion defines the currently supported license version
	SupportedLicenseVersion = 1

	// TimestampFormat is the string representation for the license timestamps e.g.
	// "2018-07-26T12:12:06-04:00"
	TimestampFormat = time.RFC3339
)

var (
	// ErrUnsupportedVersion means the license.Version is not supported.
	ErrUnsupportedVersion = errors.New("Unsupported license format version")
	// ErrExpired means the license has expired.
	ErrExpired = errors.New("License has expired")
)

// LicenseFile represents the content of a license file, which contains the
// license itself and its signature
type LicenseFile struct {
	// License contains the actual license
	License License `json:"license"`
	// Signature contains the cryptographical hash of the license
	Signature []byte `json:"signature"`

	// ObjectMeta contains the name, namespace, labels and annotations
	corev2.ObjectMeta `json:"metadata"`
}

// GetObjectMeta returns empty metadata because only a single license is
// supported
func (f *LicenseFile) GetObjectMeta() corev2.ObjectMeta {
	return f.ObjectMeta
}

// SetObjectMeta sets ObjectMeta to the provided metadata.
func (f *LicenseFile) SetObjectMeta(meta corev2.ObjectMeta) {
	// no-op
}

// GetTypeMeta sets the correct type meta of a license file.
func (f *LicenseFile) GetTypeMeta() corev2.TypeMeta {
	return corev2.TypeMeta{
		APIVersion: "licensing/v2",
		Type:       "LicenseFile",
	}
}

// SetNamespace sets the namespace of the resource.
func (f *LicenseFile) SetNamespace(namespace string) {
	return
}

// StorePrefix returns the path prefix to the license in the store
func (f *LicenseFile) StorePrefix() string {
	return path.Join(apiKeyPrefix, LicenseResource)
}

func (f *LicenseFile) StoreName() string {
	return "license_file"
}

func (f *LicenseFile) GetMetadata() *corev2.ObjectMeta {
	return &f.ObjectMeta
}

func (f *LicenseFile) SetMetadata(meta *corev2.ObjectMeta) {
	f.ObjectMeta = *meta
}

// URIPath returns the path component of the license
func (f *LicenseFile) URIPath() string {
	return LicenseURI()
}

// Validate checks that the content of the license is valid
func (f *LicenseFile) Validate() error {
	data, err := json.Marshal(f.License)
	if err != nil {
		return err
	}

	if err := VerifySignature(data, f.Signature, f.License.SignatureOptions, SensuPublicSigningKey); err != nil {
		return err
	}

	if f.License.Version != SupportedLicenseVersion {
		return ErrUnsupportedVersion
	}

	if err := f.ValidateEntityClasses(); err != nil {
		return err
	}

	now := time.Now()
	if now.After(time.Time(f.License.ValidUntil)) {
		return ErrExpired
	}
	return nil
}

// EntityLimit returns the entity limit of the license
func (f *LicenseFile) EntityLimit() int {
	return f.License.EntityLimit
}

// EntityClassLimits returns the entity class limits of the license
func (f *LicenseFile) EntityClassLimits() map[string]int {
	return f.License.EntityClassLimits
}

// License holds information about a user's enterprise software license,
// including duration of validity and enabled features.
type License struct {
	// Version is the license format version.
	Version int `json:"version"`
	// Issuer is the name of the account that issued the license.
	Issuer string `json:"issuer"`
	// AccountName is the name of the customer account.
	AccountName string `json:"accountName"`
	// AccountID is the ID of the customer account.
	AccountID uint64 `json:"accountID"`
	// Issued is the time at which the license was issued.
	Issued Timestamp `json:"issued"`
	// ValidUntil is the time at which the license will expire.
	ValidUntil Timestamp `json:"validUntil"`
	// Plan is the subscription plan the license is associated with.
	Plan string `json:"plan"`
	// Features are a list of features enabled by this license.
	Features FeatureList `json:"features"`
	// SignatureOptions contains signature algorithm and related parameters. This
	// signature metadata must be part of the signed license data to prevent
	// signature substitution attacks.
	SignatureOptions SignatureOptions `json:"signature"`
	// EntityLimit is the limit of the total number of entities allowed.
	EntityLimit int `json:"entityLimit,omitempty"`
	// AllowTessenOptOut is a special case to allow licensed users to opt out of Tessen.
	AllowTessenOptOut bool `json:"allowTessenOptOut,omitempty"`
	// EntityClassLimits is the limit of entities per entity class.
	EntityClassLimits map[string]int `json:"entityClassLimits,omitempty"`
}

// FeatureList is a list of features enabled for a license.
type FeatureList []string

// SignatureOptions contains signature algorithm and related parameters.
type SignatureOptions struct {
	Algorithm  string        `json:"algorithm"`
	Hash       HashAlgorithm `json:"hashAlgorithm"`
	SaltLength int           `json:"saltLength"`
}

// HashAlgorithm is a crypto.Hash with custom JSON marshal/unmarshal.
type HashAlgorithm crypto.Hash

// MarshalJSON implements the json.Marshaler interface.
func (ha HashAlgorithm) MarshalJSON() ([]byte, error) {
	hashAlgorithmEncoder := map[crypto.Hash]string{
		crypto.SHA256: "SHA256",
	}

	hashName, ok := hashAlgorithmEncoder[crypto.Hash(ha)]
	if !ok {
		return []byte{}, fmt.Errorf("Cannot serialize unsupported hash algorithm with id: %v", ha)
	}
	hashBytes := []byte(fmt.Sprintf("\"%s\"", hashName))
	return hashBytes, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (ha *HashAlgorithm) UnmarshalJSON(b []byte) error {
	// Unmarshal the underlying JSON string
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("Cannot unmarshal the license hash algorithm")
	}

	// Convert string to HashAlgorithm via map lookup
	var err error
	*ha, err = GetHashAlgorithm(name)
	if err != nil {
		return err
	}

	return nil
}

// GetHashAlgorithm returns the proper hash algorithm based on the provided name
func GetHashAlgorithm(name string) (HashAlgorithm, error) {
	hashAlgorithmDecoder := map[string]HashAlgorithm{
		// allow for upper or lowercase "sha"
		"SHA256": HashAlgorithm(crypto.SHA256),
		"sha256": HashAlgorithm(crypto.SHA256),
	}

	hashAlgorithm, ok := hashAlgorithmDecoder[name]
	if !ok {
		return 0, fmt.Errorf("Unknown or unsupported license hash algorithm '%s'", name)
	}

	return hashAlgorithm, nil
}

// Timestamp is an alias to time.Time with json Marshaling/Unmarshaling support
type Timestamp time.Time

// MarshalJSON implements the json.Marshaler interface.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("%q", time.Time(t).Format(TimestampFormat))
	return []byte(stamp), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return fmt.Errorf("Cannot unmarshal the license timestamp")
	}

	value, err := time.Parse(TimestampFormat, str)
	if err != nil {
		return err
	}

	*t = Timestamp(value)
	return nil
}

// String implements the time.Time string method
func (t Timestamp) String() string {
	return time.Time(t).String()
}

// RBACName returns the rbac name of the license file.
func (f *LicenseFile) RBACName() string {
	return LicenseResource
}

// ValidateEntityClasses validates the entity classes of the license file.
func (f *LicenseFile) ValidateEntityClasses() error {
	var sum int
	totalLimit := f.License.EntityLimit
	for entityClass, limit := range f.License.EntityClassLimits {
		if !(entityClass == corev2.EntityProxyClass || entityClass == corev2.EntityAgentClass) {
			return fmt.Errorf("unsupported entity class: %s", entityClass)
		}
		sum += limit
	}
	if totalLimit != 0 && sum > totalLimit {
		return fmt.Errorf("entity class limits exceed total entity limit: %d > %d", sum, totalLimit)
	}
	return nil
}
