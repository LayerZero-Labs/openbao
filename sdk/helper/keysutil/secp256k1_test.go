// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keysutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
)

// Golden encodings for the fixed test scalar below.
//
// These were produced by this package and then confirmed BYTE-IDENTICAL to
// OpenSSL 3.6.4's own canonical output for the same key, via:
//
//	openssl pkey -pubin -in pub.pem -outform DER | cmp - ours_pub.der
//	openssl ec           -in sec1.pem -outform DER | cmp - ours_sec1.der
//	openssl pkey         -in p8.pem   -outform DER | cmp - ours_p8.der
//
// Do not regenerate these from our own output alone: their whole value is that
// an independent implementation agrees. If a change here is genuinely needed,
// re-run the OpenSSL comparison and say so in the commit message.
const (
	testSecp256k1ScalarHex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"

	testSecp256k1PointHex = "042c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645" +
		"64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085"

	testSecp256k1SPKIB64 = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELIwx/J+ZDGtV44ZaGEpM5Q4JSB8urrPm" +
		"DsHOoTpq5kVkuV5P22lIwDhuGJsAain2hnabARcEJ15EWYItwzKAhQ=="

	testSecp256k1SEC1B64 = "MHQCAQEEIMmvqdhFunUWa1whV2ex1pNOUMPbNuibEnuKYisSD2choAcGBSuBBAAK" +
		"oUQDQgAELIwx/J+ZDGtV44ZaGEpM5Q4JSB8urrPmDsHOoTpq5kVkuV5P22lIwDhu" +
		"GJsAain2hnabARcEJ15EWYItwzKAhQ=="

	testSecp256k1PKCS8B64 = "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgya+p2EW6dRZrXCFXZ7HW" +
		"k05Qw9s26JsSe4piKxIPZyGhRANCAAQsjDH8n5kMa1XjhloYSkzlDglIHy6us+YO" +
		"wc6hOmrmRWS5Xk/baUjAOG4YmwBqKfaGdpsBFwQnXkRZgi3DMoCF"
)

func testSecp256k1Key(t *testing.T) (d, x, y *big.Int) {
	t.Helper()

	d, ok := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	if !ok {
		t.Fatal("could not parse test scalar")
	}

	priv, err := secp256k1PrivateKeyFromScalar(d)
	if err != nil {
		t.Fatalf("could not build test key: %v", err)
	}
	defer priv.Zero()

	pub := priv.PubKey()

	// Sanity-check the derived point against the golden value, so a library
	// swap that changed key derivation would fail loudly here rather than
	// silently invalidating every other assertion in this file.
	wantPoint, err := hexBytes(testSecp256k1PointHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := pub.SerializeUncompressed(); !bytes.Equal(got, wantPoint) {
		t.Fatalf("derived point %x, want %x", got, wantPoint)
	}

	return d, pub.X(), pub.Y()
}

func hexBytes(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := range out {
		v, ok := new(big.Int).SetString(s[2*i:2*i+2], 16)
		if !ok {
			return nil, asn1.StructuralError{Msg: "bad hex in test constant"}
		}
		out[i] = byte(v.Uint64())
	}
	return out, nil
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64 test constant: %v", err)
	}
	return der
}

// TestSecp256k1EncodingGoldens asserts our marshalers reproduce the
// OpenSSL-verified bytes exactly.
func TestSecp256k1EncodingGoldens(t *testing.T) {
	d, x, y := testSecp256k1Key(t)

	for _, tc := range []struct {
		name string
		got  func() ([]byte, error)
		want []byte
	}{
		{
			name: "SPKI",
			got:  func() ([]byte, error) { return MarshalSecp256k1PKIXPublicKey(x, y) },
			want: mustB64(t, testSecp256k1SPKIB64),
		},
		{
			name: "SEC1",
			got:  func() ([]byte, error) { return MarshalSecp256k1SEC1PrivateKey(d, x, y) },
			want: mustB64(t, testSecp256k1SEC1B64),
		},
		{
			name: "PKCS8",
			got:  func() ([]byte, error) { return MarshalSecp256k1PKCS8PrivateKey(d, x, y) },
			want: mustB64(t, testSecp256k1PKCS8B64),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.got()
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("encoding drifted from the OpenSSL-verified golden\n got: %x\nwant: %x", got, tc.want)
			}
		})
	}
}

// TestSecp256k1ParseRoundTrip checks every parser against its marshaler.
func TestSecp256k1ParseRoundTrip(t *testing.T) {
	d, x, y := testSecp256k1Key(t)

	wantPoint, err := hexBytes(testSecp256k1PointHex)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("SPKI", func(t *testing.T) {
		pub, err := ParseSecp256k1PKIXPublicKey(mustB64(t, testSecp256k1SPKIB64))
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if got := pub.SerializeUncompressed(); !bytes.Equal(got, wantPoint) {
			t.Fatalf("got point %x, want %x", got, wantPoint)
		}
	})

	t.Run("SEC1", func(t *testing.T) {
		priv, err := ParseSecp256k1SEC1PrivateKey(mustB64(t, testSecp256k1SEC1B64))
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		defer priv.Zero()
		if got := priv.Key.Bytes(); !bytes.Equal(got[:], d.FillBytes(make([]byte, 32))) {
			t.Fatalf("scalar mismatch: got %x", got)
		}
	})

	t.Run("PKCS8", func(t *testing.T) {
		priv, err := ParseSecp256k1PKCS8PrivateKey(mustB64(t, testSecp256k1PKCS8B64))
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		defer priv.Zero()
		if got := priv.PubKey().SerializeUncompressed(); !bytes.Equal(got, wantPoint) {
			t.Fatalf("got point %x, want %x", got, wantPoint)
		}
	})

	t.Run("PEM", func(t *testing.T) {
		pemStr, err := FormatSecp256k1PublicKeyPEM(x, y)
		if err != nil {
			t.Fatalf("PEM encode failed: %v", err)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			t.Fatal("output is not a valid PEM block")
		}
		if block.Type != "PUBLIC KEY" {
			t.Fatalf("got PEM type %q, want %q", block.Type, "PUBLIC KEY")
		}
		if !bytes.Equal(block.Bytes, mustB64(t, testSecp256k1SPKIB64)) {
			t.Fatal("PEM body does not match the golden SPKI DER")
		}
	})
}

// TestSecp256k1ShortScalarIsPadded covers the ~1-in-256 case where the private
// scalar is below 2^248, so big.Int.Bytes() would yield fewer than 32 bytes.
// Emitting a short OCTET STRING is rejected by strict parsers and silently
// misread by some tooling; Go had to fix this exact bug in
// x509.MarshalECPrivateKey.
func TestSecp256k1ShortScalarIsPadded(t *testing.T) {
	// Deliberately 248 bits, i.e. 31 bytes unpadded.
	d, ok := new(big.Int).SetString("00afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 16)
	if !ok {
		t.Fatal("could not parse test scalar")
	}
	if len(d.Bytes()) != 31 {
		t.Fatalf("test scalar is %d bytes unpadded, want 31 to exercise the padding path", len(d.Bytes()))
	}

	priv, err := secp256k1PrivateKeyFromScalar(d)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zero()
	pub := priv.PubKey()

	der, err := MarshalSecp256k1SEC1PrivateKey(d, pub.X(), pub.Y())
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Assert the encoded OCTET STRING really is 32 bytes.
	var parsed sec1PrivateKey
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("could not re-parse our own output: %v", err)
	}
	if len(parsed.PrivateKey) != secp256k1ScalarSize {
		t.Fatalf("encoded private scalar is %d bytes, want %d (leading zero was dropped)", len(parsed.PrivateKey), secp256k1ScalarSize)
	}
	if parsed.PrivateKey[0] != 0x00 {
		t.Fatalf("expected a leading zero byte, got %#x", parsed.PrivateKey[0])
	}

	back, err := ParseSecp256k1SEC1PrivateKey(der)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	defer back.Zero()
	if !back.PubKey().IsEqual(pub) {
		t.Fatal("round-tripped key differs from the original")
	}
}

// TestSecp256k1StdlibRejectsOurSPKI documents that crypto/x509 cannot parse
// this curve. It exists so that nobody "fixes" a failing export test by routing
// it back through the standard library -- if this test ever starts failing,
// Go gained secp256k1 support and this package's approach can be revisited.
func TestSecp256k1StdlibRejectsOurSPKI(t *testing.T) {
	_, x, y := testSecp256k1Key(t)

	der, err := MarshalSecp256k1PKIXPublicKey(x, y)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := x509.ParsePKIXPublicKey(der); err == nil {
		t.Fatal("crypto/x509 unexpectedly parsed a secp256k1 SPKI; revisit this package's custom encoding")
	}
}

// TestSecp256k1MalformedInputs covers the rejection paths.
func TestSecp256k1MalformedInputs(t *testing.T) {
	d, x, y := testSecp256k1Key(t)

	t.Run("nil components", func(t *testing.T) {
		if _, err := MarshalSecp256k1PKIXPublicKey(nil, y); err == nil {
			t.Fatal("expected an error for a nil X")
		}
		if _, err := MarshalSecp256k1PKIXPublicKey(x, nil); err == nil {
			t.Fatal("expected an error for a nil Y")
		}
	})

	t.Run("point not on curve", func(t *testing.T) {
		bad := new(big.Int).Add(y, big.NewInt(1))
		if _, err := MarshalSecp256k1PKIXPublicKey(x, bad); err == nil {
			t.Fatal("expected an error for a point that is not on the curve")
		}
	})

	t.Run("scalar out of range", func(t *testing.T) {
		if _, err := secp256k1PrivateKeyFromScalar(big.NewInt(0)); err == nil {
			t.Fatal("expected an error for a zero scalar")
		}
		// 2^256 - 1 is comfortably above the group order.
		tooBig := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
		if _, err := secp256k1PrivateKeyFromScalar(tooBig); err == nil {
			t.Fatal("expected an error for a scalar at or above the group order")
		}
		if _, err := secp256k1PrivateKeyFromScalar(new(big.Int).Lsh(big.NewInt(1), 300)); err == nil {
			t.Fatal("expected an error for an oversized scalar")
		}
	})

	t.Run("scalar does not match point", func(t *testing.T) {
		other := new(big.Int).Add(d, big.NewInt(1))
		if _, err := MarshalSecp256k1SEC1PrivateKey(other, x, y); err == nil {
			t.Fatal("expected an error when the scalar does not match the public point")
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		der := append(mustB64(t, testSecp256k1SPKIB64), 0x00)
		if _, err := ParseSecp256k1PKIXPublicKey(der); err == nil {
			t.Fatal("expected an error for trailing bytes after the SPKI")
		}
	})

	t.Run("wrong curve OID", func(t *testing.T) {
		// Generate a real P-256 SPKI rather than hardcoding one: it must be
		// structurally valid so that the parse reaches -- and fails at -- the
		// curve OID check, rather than bailing out earlier on malformed ASN.1.
		// (Using crypto/ecdsa here is fine; the prohibition in secp256k1.go is
		// about the production path for this curve, not about test fixtures for
		// other curves.)
		p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p256SPKI, err := x509.MarshalPKIXPublicKey(&p256Key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		// Confirm the fixture really is well-formed, so a future change that
		// broke it could not make this test vacuous.
		if _, err := x509.ParsePKIXPublicKey(p256SPKI); err != nil {
			t.Fatalf("test fixture is not a valid SPKI: %v", err)
		}

		if _, err := ParseSecp256k1PKIXPublicKey(p256SPKI); err == nil {
			t.Fatal("expected an error for a non-secp256k1 curve OID")
		}
	})

	t.Run("nil key entry", func(t *testing.T) {
		if _, err := Secp256k1PrivFromKeyEntry(nil); err == nil {
			t.Fatal("expected an error for a nil key entry")
		}
		if _, err := Secp256k1PubFromKeyEntry(nil); err == nil {
			t.Fatal("expected an error for a nil key entry")
		}
		if _, err := Secp256k1PrivFromKeyEntry(&KeyEntry{}); err == nil {
			t.Fatal("expected an error for a key entry with no private scalar")
		}
	})
}

// TestSecp256k1KeyEntryBridges covers the KeyEntry helpers used by policy.go.
func TestSecp256k1KeyEntryBridges(t *testing.T) {
	d, x, y := testSecp256k1Key(t)

	ke := &KeyEntry{EC_D: d, EC_X: x, EC_Y: y}

	priv, err := Secp256k1PrivFromKeyEntry(ke)
	if err != nil {
		t.Fatalf("private bridge failed: %v", err)
	}
	defer priv.Zero()

	pub, err := Secp256k1PubFromKeyEntry(ke)
	if err != nil {
		t.Fatalf("public bridge failed: %v", err)
	}

	if !priv.PubKey().IsEqual(pub) {
		t.Fatal("private and public bridges disagree")
	}

	t.Run("mismatched stored point is rejected", func(t *testing.T) {
		// Swap in a different but valid on-curve point.
		otherPriv, err := secp256k1PrivateKeyFromScalar(new(big.Int).Add(d, big.NewInt(1)))
		if err != nil {
			t.Fatal(err)
		}
		defer otherPriv.Zero()
		otherPub := otherPriv.PubKey()

		bad := &KeyEntry{EC_D: d, EC_X: otherPub.X(), EC_Y: otherPub.Y()}
		if _, err := Secp256k1PrivFromKeyEntry(bad); err == nil {
			t.Fatal("expected an error when the stored point does not match the scalar")
		}
	})
}
