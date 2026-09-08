// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keysutil

// secp256k1 (a.k.a. the Koblitz curve, SECG name secp256k1, RFC 8812 JWK crv
// "secp256k1") support for transit signing keys.
//
// Secret operations use secp256k1-voi/secec: its scalar multiplication,
// inversion, and low-S selection use constant-time arithmetic. Decred is used
// only for public-key parsing and signature verification. Decred v4.4.1's Sign
// and PrivateKey.PubKey use variable-time operations on secret values, including
// math/big.ModInverse on the nonce. Do not use them in the production path.
// Likewise, do not route this curve through crypto/ecdsa's legacy custom-curve
// support, whose timing and FIPS behavior differ from the NIST implementations.
//
// secp256k1-voi's authors explicitly state that it has not been independently
// audited. Constant-time arithmetic is a library property, not an audit or a
// FIPS claim. Its field/scalar arithmetic is generated with fiat-crypto.
// Private keys remain in Go-managed memory, including the persisted big.Int
// representation; neither this code nor the library guarantees memory erasure.
//
// Go's crypto/x509 has no secp256k1 curve OID either, so MarshalPKIXPublicKey,
// MarshalECPrivateKey, MarshalPKCS8PrivateKey and their Parse counterparts all
// reject this curve. That is why the ASN.1 encoding below is hand-rolled rather
// than delegated. The structures mirror crypto/x509's unexported ones so that
// output is byte-compatible with OpenSSL and with Go's own parsers for the
// curves they do support.

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

const (
	// secp256k1ScalarSize is the size, in bytes, of a secp256k1 field element
	// or group scalar. Private scalars and the X/Y affine coordinates are all
	// fixed-width at this size in the encodings below; see padScalarTo32.
	secp256k1ScalarSize = 32

	// secp256k1UncompressedSize is the size of an uncompressed SEC 1 point:
	// a 0x04 prefix followed by the X and Y coordinates.
	secp256k1UncompressedSize = 1 + 2*secp256k1ScalarSize

	// secp256k1SEC1Version is the version field of an RFC 5915 ECPrivateKey.
	secp256k1SEC1Version = 1

	// secp256k1PKCS8Version is the version field of an RFC 5208
	// PrivateKeyInfo.
	secp256k1PKCS8Version = 0
)

// oidNamedCurveSecp256k1 is the SECG object identifier for the secp256k1 curve
// (SEC 2, section 2.4.1). Note that crypto/x509 knows nothing about this OID,
// which is the reason this file exists.
var oidNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// pkixPublicKey reflects an ASN.1 SubjectPublicKeyInfo structure (RFC 5280).
//
// Copied from Go: crypto/x509/x509.go.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// sec1PrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure
// (RFC 5915 / SEC 1, section C.4).
//
// This differs from the ecPrivateKey type in util.go, which intentionally omits
// the optional public key because the Ed25519 encoding it handles does not use
// it. secp256k1 keys do carry it, and including it is required for output that
// matches crypto/x509 (and therefore OpenSSL) byte for byte.
//
// Copied from Go: crypto/x509/sec1.go.
type sec1PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// secp256k1AlgorithmIdentifier builds the AlgorithmIdentifier shared by the
// SubjectPublicKeyInfo and PrivateKeyInfo encodings: the id-ecPublicKey
// algorithm with the secp256k1 named curve as its parameter.
//
// pkix.AlgorithmIdentifier.Parameters is an asn1.RawValue, so the curve OID has
// to be marshaled separately and injected as FullBytes. This mirrors what
// crypto/x509's marshalPublicKey does internally.
func secp256k1AlgorithmIdentifier() (pkix.AlgorithmIdentifier, error) {
	paramBytes, err := asn1.Marshal(oidNamedCurveSecp256k1)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("keysutil: failed to marshal secp256k1 curve OID: %w", err)
	}

	return pkix.AlgorithmIdentifier{
		Algorithm:  oidPublicKeyECDSA,
		Parameters: asn1.RawValue{FullBytes: paramBytes},
	}, nil
}

// checkSecp256k1AlgorithmIdentifier verifies that an AlgorithmIdentifier names
// id-ecPublicKey with the secp256k1 named curve.
func checkSecp256k1AlgorithmIdentifier(algo pkix.AlgorithmIdentifier) error {
	if !algo.Algorithm.Equal(oidPublicKeyECDSA) {
		return fmt.Errorf("keysutil: unexpected public key algorithm OID %v, want id-ecPublicKey (%v)", algo.Algorithm, oidPublicKeyECDSA)
	}

	var namedCurveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(algo.Parameters.FullBytes, &namedCurveOID); err != nil {
		return fmt.Errorf("keysutil: failed to parse named curve OID: %w", err)
	}

	if !namedCurveOID.Equal(oidNamedCurveSecp256k1) {
		return fmt.Errorf("keysutil: unexpected curve OID %v, want secp256k1 (%v)", namedCurveOID, oidNamedCurveSecp256k1)
	}

	return nil
}

// padScalarTo32 renders a big.Int as a fixed-width 32-byte big-endian slice.
//
// This must never be replaced with a bare i.Bytes(). big.Int.Bytes() drops
// leading zero bytes, so roughly one key in 256 has a scalar below 2^248 and
// would emit a 31-byte (or shorter) octet string. Strict ASN.1 parsers reject
// that, and some tooling silently misreads it. Go itself had to fix exactly
// this bug in x509.MarshalECPrivateKey.
func padScalarTo32(i *big.Int, name string) ([]byte, error) {
	if i == nil {
		return nil, fmt.Errorf("keysutil: secp256k1 key component %s is missing", name)
	}

	if i.Sign() < 0 {
		return nil, fmt.Errorf("keysutil: secp256k1 key component %s is negative", name)
	}

	if i.BitLen() > secp256k1ScalarSize*8 {
		return nil, fmt.Errorf("keysutil: secp256k1 key component %s is %d bits, exceeding the %d-bit field", name, i.BitLen(), secp256k1ScalarSize*8)
	}

	out := make([]byte, secp256k1ScalarSize)
	i.FillBytes(out)

	return out, nil
}

// secp256k1UncompressedPoint renders an affine (x, y) coordinate pair as an
// uncompressed SEC 1 point and verifies that it actually lies on the curve.
func secp256k1UncompressedPoint(x, y *big.Int) ([]byte, error) {
	xBytes, err := padScalarTo32(x, "EC_X")
	if err != nil {
		return nil, err
	}

	yBytes, err := padScalarTo32(y, "EC_Y")
	if err != nil {
		return nil, err
	}

	point := make([]byte, 0, secp256k1UncompressedSize)
	point = append(point, 0x04)
	point = append(point, xBytes...)
	point = append(point, yBytes...)

	// ParsePubKey rejects points that are not on the curve, which catches both
	// corrupted storage and a caller that handed us coordinates from a
	// different curve.
	if _, err := secp256k1.ParsePubKey(point); err != nil {
		return nil, fmt.Errorf("keysutil: invalid secp256k1 public point: %w", err)
	}

	return point, nil
}

// secp256k1PrivateKeyFromScalar converts a private scalar into a secec private
// key, rejecting zero and out-of-range values.
func secp256k1PrivateKeyFromScalar(d *big.Int) (*secec.PrivateKey, error) {
	dBytes, err := padScalarTo32(d, "EC_D")
	if err != nil {
		return nil, err
	}

	defer clear(dBytes)
	return secec.NewPrivateKey(dBytes)
}

// generateSecp256k1Key samples a valid scalar using the injected entropy source.
func generateSecp256k1Key(random io.Reader) (*secec.PrivateKey, error) {
	var candidate [secec.PrivateKeySize]byte
	defer clear(candidate[:])
	for range 128 {
		if _, err := io.ReadFull(random, candidate[:]); err != nil {
			return nil, err
		}
		if key, err := secec.NewPrivateKey(candidate[:]); err == nil {
			return key, nil
		}
	}
	return nil, errors.New("keysutil: entropy source did not produce a valid secp256k1 scalar")
}

// secp256k1ScalarFromBigInt converts a signature component parsed out of DER
// into a ModNScalar, rejecting anything outside [1, N-1].
//
// The length check is load-bearing and must not be dropped as redundant.
// ModNScalar.SetByteSlice truncates its input to the FIRST 32 bytes rather than
// failing, so a DER signature carrying an over-long component -- which
// encoding/asn1 will happily unmarshal into a big.Int -- would otherwise be
// silently reinterpreted as a different, valid scalar.
func secp256k1ScalarFromBigInt(out *secp256k1.ModNScalar, v *big.Int, name string) error {
	if v == nil {
		return errutil.UserError{Err: fmt.Sprintf("supplied signature is missing component %s", name)}
	}

	if v.Sign() <= 0 {
		return errutil.UserError{Err: fmt.Sprintf("supplied signature component %s is not positive", name)}
	}

	if len(v.Bytes()) > secp256k1ScalarSize {
		return errutil.UserError{Err: fmt.Sprintf(
			"supplied signature component %s is %d bytes, exceeding %d",
			name, len(v.Bytes()), secp256k1ScalarSize)}
	}

	if overflow := out.SetByteSlice(v.FillBytes(make([]byte, secp256k1ScalarSize))); overflow {
		return errutil.UserError{Err: fmt.Sprintf("supplied signature component %s is not within the group order", name)}
	}

	if out.IsZero() {
		return errutil.UserError{Err: fmt.Sprintf("supplied signature component %s is zero", name)}
	}

	return nil
}

// MarshalSecp256k1PKIXPublicKey encodes an affine coordinate pair as a DER
// SubjectPublicKeyInfo structure, equivalent to what
// x509.MarshalPKIXPublicKey would produce if it supported this curve.
func MarshalSecp256k1PKIXPublicKey(x, y *big.Int) ([]byte, error) {
	point, err := secp256k1UncompressedPoint(x, y)
	if err != nil {
		return nil, err
	}

	algo, err := secp256k1AlgorithmIdentifier()
	if err != nil {
		return nil, err
	}

	der, err := asn1.Marshal(pkixPublicKey{
		Algo: algo,
		BitString: asn1.BitString{
			Bytes:     point,
			BitLength: 8 * len(point),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to marshal secp256k1 SubjectPublicKeyInfo: %w", err)
	}

	return der, nil
}

// ParseSecp256k1PKIXPublicKey parses a DER SubjectPublicKeyInfo structure
// holding a secp256k1 public key.
func ParseSecp256k1PKIXPublicKey(der []byte) (*secp256k1.PublicKey, error) {
	var spki pkixPublicKey
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to parse secp256k1 SubjectPublicKeyInfo: %w", err)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("keysutil: %d trailing bytes after secp256k1 SubjectPublicKeyInfo", len(rest))
	}

	if err := checkSecp256k1AlgorithmIdentifier(spki.Algo); err != nil {
		return nil, err
	}

	// ParsePubKey validates that the point is on the curve.
	pub, err := secp256k1.ParsePubKey(spki.BitString.RightAlign())
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to parse secp256k1 public point: %w", err)
	}

	return pub, nil
}

// MarshalSecp256k1SEC1PrivateKey encodes a private scalar and its public point
// as a DER RFC 5915 / SEC 1 ECPrivateKey structure, equivalent to what
// x509.MarshalECPrivateKey would produce if it supported this curve.
//
// This is the structure carried in a PEM block of type "EC PRIVATE KEY".
func MarshalSecp256k1SEC1PrivateKey(d, x, y *big.Int) ([]byte, error) {
	return marshalSecp256k1SEC1PrivateKey(d, x, y, true)
}

// marshalSecp256k1SEC1PrivateKey encodes the SEC 1 ECPrivateKey structure.
//
// includeCurveOID controls whether the optional NamedCurveOID field is present.
// It is present in a standalone SEC 1 key, and omitted when the structure is
// nested inside a PKCS#8 PrivateKeyInfo whose outer AlgorithmIdentifier already
// names the curve -- matching crypto/x509's behaviour exactly, so that our
// PKCS#8 output is byte-identical in shape to Go's for other curves.
func marshalSecp256k1SEC1PrivateKey(d, x, y *big.Int, includeCurveOID bool) ([]byte, error) {
	point, err := secp256k1UncompressedPoint(x, y)
	if err != nil {
		return nil, err
	}

	// Validate the scalar and confirm it actually corresponds to the supplied
	// public point. A mismatch means corrupted storage, and silently emitting
	// such a key would produce signatures that verify against nothing.
	priv, err := secp256k1PrivateKeyFromScalar(d)
	if err != nil {
		return nil, err
	}
	if derived := priv.PublicKey().Bytes(); !bytes.Equal(derived, point) {
		return nil, errors.New("keysutil: secp256k1 private scalar does not match the stored public point")
	}

	dBytes, err := padScalarTo32(d, "EC_D")
	if err != nil {
		return nil, err
	}

	key := sec1PrivateKey{
		Version:    secp256k1SEC1Version,
		PrivateKey: dBytes,
		PublicKey: asn1.BitString{
			Bytes:     point,
			BitLength: 8 * len(point),
		},
	}

	if includeCurveOID {
		key.NamedCurveOID = oidNamedCurveSecp256k1
	}

	der, err := asn1.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to marshal secp256k1 ECPrivateKey: %w", err)
	}

	return der, nil
}

// ParseSecp256k1SEC1PrivateKey parses a DER RFC 5915 / SEC 1 ECPrivateKey
// structure holding a secp256k1 private key.
func ParseSecp256k1SEC1PrivateKey(der []byte) (*secec.PrivateKey, error) {
	return parseSecp256k1SEC1PrivateKey(der, true)
}

// parseSecp256k1SEC1PrivateKey parses the SEC 1 ECPrivateKey structure.
//
// requireCurveOID is false when the structure came from inside a PKCS#8
// PrivateKeyInfo, where the curve is named by the outer AlgorithmIdentifier and
// the inner field is conventionally absent.
func parseSecp256k1SEC1PrivateKey(der []byte, requireCurveOID bool) (*secec.PrivateKey, error) {
	var key sec1PrivateKey
	rest, err := asn1.Unmarshal(der, &key)
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to parse secp256k1 ECPrivateKey: %w", err)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("keysutil: %d trailing bytes after secp256k1 ECPrivateKey", len(rest))
	}

	if key.Version != secp256k1SEC1Version {
		return nil, fmt.Errorf("keysutil: unsupported secp256k1 ECPrivateKey version %d, want %d", key.Version, secp256k1SEC1Version)
	}

	// The OID is ASN.1 OPTIONAL. When present it must name secp256k1; when
	// absent it may only be omitted in the nested PKCS#8 case.
	switch {
	case len(key.NamedCurveOID) != 0:
		if !key.NamedCurveOID.Equal(oidNamedCurveSecp256k1) {
			return nil, fmt.Errorf("keysutil: unexpected curve OID %v, want secp256k1 (%v)", key.NamedCurveOID, oidNamedCurveSecp256k1)
		}
	case requireCurveOID:
		return nil, errors.New("keysutil: secp256k1 ECPrivateKey is missing the named curve OID")
	}

	// Accept a short scalar by left-padding, as x509.ParseECPrivateKey does,
	// but never a long one -- see the truncation note on ModNScalar in
	// SetByteSlice's documentation.
	if len(key.PrivateKey) > secp256k1ScalarSize {
		return nil, fmt.Errorf("keysutil: secp256k1 private scalar is %d bytes, exceeding %d", len(key.PrivateKey), secp256k1ScalarSize)
	}

	priv, err := secp256k1PrivateKeyFromScalar(new(big.Int).SetBytes(key.PrivateKey))
	if err != nil {
		return nil, err
	}

	// If the optional public key is present, confirm it matches the scalar.
	if len(key.PublicKey.Bytes) != 0 {
		point := key.PublicKey.RightAlign()
		if derived := priv.PublicKey().Bytes(); !bytes.Equal(derived, point) {
			return nil, errors.New("keysutil: secp256k1 ECPrivateKey public key does not match its private scalar")
		}
	}

	return priv, nil
}

// MarshalSecp256k1PKCS8PrivateKey encodes a private scalar and its public point
// as a DER RFC 5208 PrivateKeyInfo structure, equivalent to what
// x509.MarshalPKCS8PrivateKey would produce if it supported this curve.
//
// This is the structure carried in a PEM block of type "PRIVATE KEY".
func MarshalSecp256k1PKCS8PrivateKey(d, x, y *big.Int) ([]byte, error) {
	algo, err := secp256k1AlgorithmIdentifier()
	if err != nil {
		return nil, err
	}

	// The curve OID lives in the outer AlgorithmIdentifier and is omitted from
	// the inner ECPrivateKey, matching crypto/x509.
	inner, err := marshalSecp256k1SEC1PrivateKey(d, x, y, false)
	if err != nil {
		return nil, err
	}

	der, err := asn1.Marshal(pkcs8{
		Version:    secp256k1PKCS8Version,
		Algo:       algo,
		PrivateKey: inner,
	})
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to marshal secp256k1 PrivateKeyInfo: %w", err)
	}

	return der, nil
}

// ParseSecp256k1PKCS8PrivateKey parses a DER RFC 5208 PrivateKeyInfo structure
// holding a secp256k1 private key.
func ParseSecp256k1PKCS8PrivateKey(der []byte) (*secec.PrivateKey, error) {
	var info pkcs8
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to parse secp256k1 PrivateKeyInfo: %w", err)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("keysutil: %d trailing bytes after secp256k1 PrivateKeyInfo", len(rest))
	}

	if info.Version != secp256k1PKCS8Version {
		return nil, fmt.Errorf("keysutil: unsupported secp256k1 PrivateKeyInfo version %d, want %d", info.Version, secp256k1PKCS8Version)
	}

	if err := checkSecp256k1AlgorithmIdentifier(info.Algo); err != nil {
		return nil, err
	}

	return parseSecp256k1SEC1PrivateKey(info.PrivateKey, false)
}

// FormatSecp256k1PublicKeyPEM renders an affine coordinate pair as a PEM
// "PUBLIC KEY" block, the form stored in KeyEntry.FormattedPublicKey.
//
// The result is deliberately NOT trimmed, so that the stored representation
// matches what RotateInMemory writes for the NIST curves (a PEM block with its
// trailing newline). Callers that want the trimmed form -- the transit export
// path does -- should apply strings.TrimSpace themselves, as the existing
// keyEntryToEC*Key helpers do.
func FormatSecp256k1PublicKeyPEM(x, y *big.Int) (string, error) {
	der, err := MarshalSecp256k1PKIXPublicKey(x, y)
	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	if len(pemBytes) == 0 {
		return "", errors.New("keysutil: failed to PEM-encode secp256k1 public key")
	}

	return string(pemBytes), nil
}

// Secp256k1PrivFromKeyEntry reconstructs a secp256k1 private key from a stored
// key version.
func Secp256k1PrivFromKeyEntry(ke *KeyEntry) (*secec.PrivateKey, error) {
	if ke == nil {
		return nil, errors.New("keysutil: nil key entry provided")
	}

	if ke.EC_D == nil {
		return nil, errors.New("keysutil: key version does not contain a private key")
	}

	priv, err := secp256k1PrivateKeyFromScalar(ke.EC_D)
	if err != nil {
		return nil, err
	}

	// Guard against a corrupted or mismatched stored public point: signing
	// with a key whose public half is wrong yields signatures that verify
	// against nothing, which is very hard to diagnose downstream.
	point, err := secp256k1UncompressedPoint(ke.EC_X, ke.EC_Y)
	if err != nil {
		return nil, err
	}

	if derived := priv.PublicKey().Bytes(); !bytes.Equal(derived, point) {
		return nil, errors.New("keysutil: stored secp256k1 public point does not match the private scalar")
	}

	return priv, nil
}

// Secp256k1PubFromKeyEntry reconstructs a secp256k1 public key from a stored
// key version.
func Secp256k1PubFromKeyEntry(ke *KeyEntry) (*secp256k1.PublicKey, error) {
	if ke == nil {
		return nil, errors.New("keysutil: nil key entry provided")
	}

	point, err := secp256k1UncompressedPoint(ke.EC_X, ke.EC_Y)
	if err != nil {
		return nil, err
	}

	pub, err := secp256k1.ParsePubKey(point)
	if err != nil {
		return nil, fmt.Errorf("keysutil: failed to parse stored secp256k1 public point: %w", err)
	}

	return pub, nil
}
