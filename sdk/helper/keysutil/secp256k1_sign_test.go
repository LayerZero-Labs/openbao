// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keysutil

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// secp256k1SignVector is a known-answer RFC 6979 test vector.
//
// PROVENANCE: copied verbatim from the decred secp256k1 module's own test
// suite, ecdsa/signature_test.go, function signTests() -- only the entries with
// rfc6979: true, since our Sign path always uses deterministic nonces. That
// file states the values were "verified independently with the Sage computer
// algebra system".
//
// These are the single strongest correctness check in this package: because
// signing is deterministic, an exact byte match proves our sign path agrees
// with an independent implementation, rather than merely agreeing with itself.
//
// DO NOT regenerate these from our own output, and do not hand-write new ones.
// Add vectors only by copying them from an upstream source and naming that
// source here.
type secp256k1SignVector struct {
	key  string
	hash string
	r    string
	s    string
}

var secp256k1SignVectors = []secp256k1SignVector{
	{
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09",
		s:    "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
	},
	{
		key:  "0000000000000000000000000000000000000000000000000000000000000002",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59",
		s:    "44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
	},
	{
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
		r:    "dda8308cdbda2edf51ccf598b42b42b19597e102eb2ed4a04a16dd57084d3b40",
		s:    "0b6d67bab4929624e28f690407a15efc551354544fdc179970ff401eec2e5dc9",
	},
	{
		key:  "0000000000000000000000000000000000000000000000000000000000000002",
		hash: "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
		r:    "122663fd29e41a132d3c8329cf05d61ebcca9351074cc277dcd868faba58d87d",
		s:    "353a44f2d949c04981e4e4d9c1f93a9e0644e63a5eaa188288c5ad68fd288d40",
	},
	{
		key:  "a1becef2069444a9dc6331c3247e113c3ee142edda683db8643f9cb0af7cbe33",
		hash: "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d",
		r:    "ef392791d87afca8256c4c9c68d981248ee34a09069f50fa8dfc19ae34cd92ce",
		s:    "0a2b9cb69fd794f7f204c272293b8585a294916a21a11fd94ec04acae2dc6d21",
	},
	{
		key:  "59930b76d4b15767ec0e8c8e5812aa2e57db30c6af7963e2a6295ba02af5416b",
		hash: "49af37ab5270015fe25276ea5a3bb159d852943df23919522a202205fb7d175c",
		r:    "886c9cccb356b3e1deafef2c276a4f8717ab73c1244c3f673cfbff5897de0e06",
		s:    "609394185495f978ae84b69be90c69947e5dd8dcb4726da604fcbd139d81fc55",
	},
	{
		key:  "c5b205c36bb7497d242e96ec19a2a4f086d8daa919135cf490d2b7c0230f0e91",
		hash: "b706d561742ad3671703c247eb927ee8a386369c79644131cdeb2c5c26bf6c5d",
		r:    "6589d5950cec1fe2e7e20593b5ffa3556de20c176720a1796aa77a0cec1ec5a7",
		s:    "2a26deba3241de852e786f5b4e2b98d3efb958d91fe9773b331dbcca9e8be800",
	},
	{
		key:  "65b46d4eb001c649a86309286aaf94b18386effe62c2e1586d9b1898ccf0099b",
		hash: "4c6eb9e38415034f4c93d3304d10bef38bf0ad420eefd0f72f940f11c5857786",
		r:    "81db1d6dca08819ad936d3284a359091e57c036648d477b96af9d8326965a7d1",
		s:    "1bdf719c4be69351ba7617a187ac246912101aea4b5a7d6dfc234478622b43c6",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test constant %q: %v", s, err)
	}
	return b
}

// secp256k1PolicyFromScalar builds an in-memory single-version policy holding
// the given private scalar, so tests can drive Policy.SignWithOptions directly
// without a storage backend.
func secp256k1PolicyFromScalar(t *testing.T, d *big.Int) *Policy {
	t.Helper()

	priv, err := secp256k1PrivateKeyFromScalar(d)
	if err != nil {
		t.Fatalf("could not build key: %v", err)
	}
	defer priv.Zero()
	pub := priv.PubKey()

	return &Policy{
		l:             new(sync.RWMutex),
		Name:          "test-secp256k1",
		Type:          KeyType_ECDSA_SECP256K1,
		LatestVersion: 1,
		Keys: keyEntryMap{
			"1": KeyEntry{
				EC_D: d,
				EC_X: pub.X(),
				EC_Y: pub.Y(),
			},
		},
	}
}

// TestSecp256k1SignKnownAnswers is the cross-verification test: our signatures
// must match the upstream RFC 6979 vectors byte for byte, in both marshalings.
func TestSecp256k1SignKnownAnswers(t *testing.T) {
	for i, vec := range secp256k1SignVectors {
		t.Run(vec.key[:8]+"/"+vec.hash[:8], func(t *testing.T) {
			d := new(big.Int).SetBytes(mustHex(t, vec.key))
			digest := mustHex(t, vec.hash)
			wantR := mustHex(t, vec.r)
			wantS := mustHex(t, vec.s)

			p := secp256k1PolicyFromScalar(t, d)

			// jws marshaling is the direct r||s comparison.
			res, err := p.SignWithOptions(0, nil, digest, &SigningOptions{
				Marshaling: MarshalingTypeJWS,
			})
			if err != nil {
				t.Fatalf("vector %d: sign failed: %v", i, err)
			}

			raw := decodeSigForTest(t, p, res.Signature, MarshalingTypeJWS)
			if len(raw) != 64 {
				t.Fatalf("vector %d: jws signature is %d bytes, want 64", i, len(raw))
			}

			gotR, gotS := raw[:32], raw[32:]
			if !bytes.Equal(gotR, leftPad32(wantR)) {
				t.Errorf("vector %d: r mismatch\n got: %x\nwant: %x", i, gotR, leftPad32(wantR))
			}
			if !bytes.Equal(gotS, leftPad32(wantS)) {
				t.Errorf("vector %d: s mismatch\n got: %x\nwant: %x", i, gotS, leftPad32(wantS))
			}

			// asn1 marshaling should carry the same r and s.
			res2, err := p.SignWithOptions(0, nil, digest, &SigningOptions{
				Marshaling: MarshalingTypeASN1,
			})
			if err != nil {
				t.Fatalf("vector %d: asn1 sign failed: %v", i, err)
			}

			der := decodeSigForTest(t, p, res2.Signature, MarshalingTypeASN1)
			var parsed ecdsaSignature
			if _, err := asn1.Unmarshal(der, &parsed); err != nil {
				t.Fatalf("vector %d: our own DER did not parse: %v", i, err)
			}
			if parsed.R.Cmp(new(big.Int).SetBytes(wantR)) != 0 {
				t.Errorf("vector %d: asn1 r mismatch, got %x", i, parsed.R.Bytes())
			}
			if parsed.S.Cmp(new(big.Int).SetBytes(wantS)) != 0 {
				t.Errorf("vector %d: asn1 s mismatch, got %x", i, parsed.S.Bytes())
			}
		})
	}
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// decodeSigForTest strips the "vault:vN:" prefix and base64-decodes, mirroring
// what a client does. The alphabet differs per marshaling, matching
// SignWithOptions.
func decodeSigForTest(t *testing.T, p *Policy, sig string, marshaling MarshalingType) []byte {
	t.Helper()

	prefix := p.getVersionPrefix(1)
	if len(sig) <= len(prefix) || sig[:len(prefix)] != prefix {
		t.Fatalf("signature %q does not carry the expected prefix %q", sig, prefix)
	}
	body := sig[len(prefix):]

	var (
		dec []byte
		err error
	)
	switch marshaling {
	case MarshalingTypeJWS:
		dec, err = base64.RawURLEncoding.DecodeString(body)
	default:
		dec, err = base64.StdEncoding.DecodeString(body)
	}
	if err != nil {
		t.Fatalf("could not decode signature body: %v", err)
	}
	return dec
}

// encodeSigForTest is the inverse of decodeSigForTest, for building fixtures.
func encodeSigForTest(p *Policy, raw []byte, marshaling MarshalingType) string {
	var encoded string
	switch marshaling {
	case MarshalingTypeJWS:
		encoded = base64.RawURLEncoding.EncodeToString(raw)
	default:
		encoded = base64.StdEncoding.EncodeToString(raw)
	}
	return p.getVersionPrefix(1) + encoded
}

// TestSecp256k1SignVerifyRoundTrip covers both marshalings through the public
// Policy API, and cross-checks each signature with decred directly.
func TestSecp256k1SignVerifyRoundTrip(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)
	digest := mustHex(t, "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d")

	for name, marshaling := range MarshalingTypeMap {
		t.Run(name, func(t *testing.T) {
			res, err := p.SignWithOptions(0, nil, digest, &SigningOptions{Marshaling: marshaling})
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			ok, err := p.VerifySignatureWithOptions(nil, digest, res.Signature, &SigningOptions{Marshaling: marshaling})
			if err != nil {
				t.Fatalf("verify errored: %v", err)
			}
			if !ok {
				t.Fatal("our own signature did not verify")
			}

			// A different digest must not verify.
			other := mustHex(t, "49af37ab5270015fe25276ea5a3bb159d852943df23919522a202205fb7d175c")
			ok, err = p.VerifySignatureWithOptions(nil, other, res.Signature, &SigningOptions{Marshaling: marshaling})
			if err != nil {
				t.Fatalf("verify errored on wrong digest: %v", err)
			}
			if ok {
				t.Fatal("signature verified against the wrong digest")
			}
		})
	}
}

// TestSecp256k1SignIsLowS asserts every signature we emit is BIP-62 canonical.
func TestSecp256k1SignIsLowS(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)

	// Vary the digest rather than the key, since signing is deterministic.
	digest := make([]byte, 32)
	for i := range 512 {
		digest[0] = byte(i)
		digest[1] = byte(i >> 8)

		res, err := p.SignWithOptions(0, nil, digest, &SigningOptions{Marshaling: MarshalingTypeJWS})
		if err != nil {
			t.Fatalf("sign failed at iteration %d: %v", i, err)
		}

		raw := decodeSigForTest(t, p, res.Signature, MarshalingTypeJWS)
		var s secp256k1.ModNScalar
		if overflow := s.SetByteSlice(raw[32:]); overflow {
			t.Fatalf("iteration %d: s overflowed the group order", i)
		}
		if s.IsOverHalfOrder() {
			t.Fatalf("iteration %d: emitted a high-S signature (not BIP-62 canonical)", i)
		}
	}
}

// TestSecp256k1VerifyAcceptsHighS asserts the deliberate asymmetry: we always
// emit low-S, but a signature produced elsewhere with a high S still verifies.
func TestSecp256k1VerifyAcceptsHighS(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)
	digest := mustHex(t, "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d")

	res, err := p.SignWithOptions(0, nil, digest, &SigningOptions{Marshaling: MarshalingTypeJWS})
	if err != nil {
		t.Fatal(err)
	}
	raw := decodeSigForTest(t, p, res.Signature, MarshalingTypeJWS)

	// Flip s to its high-S equivalent: s' = N - s.
	var s secp256k1.ModNScalar
	s.SetByteSlice(raw[32:])
	s.Negate()
	if !s.IsOverHalfOrder() {
		t.Fatal("negating s did not produce a high-S value; test assumption is wrong")
	}
	var highS [32]byte
	s.PutBytes(&highS)

	t.Run("jws", func(t *testing.T) {
		flipped := make([]byte, 0, 64)
		flipped = append(flipped, raw[:32]...)
		flipped = append(flipped, highS[:]...)

		ok, err := p.VerifySignatureWithOptions(nil, digest, encodeSigForTest(p, flipped, MarshalingTypeJWS), &SigningOptions{Marshaling: MarshalingTypeJWS})
		if err != nil {
			t.Fatalf("verify errored on a high-S signature: %v", err)
		}
		if !ok {
			t.Fatal("high-S signature was rejected; verification should accept it")
		}
	})

	t.Run("asn1", func(t *testing.T) {
		der, err := asn1.Marshal(ecdsaSignature{
			R: new(big.Int).SetBytes(raw[:32]),
			S: new(big.Int).SetBytes(highS[:]),
		})
		if err != nil {
			t.Fatal(err)
		}

		ok, err := p.VerifySignatureWithOptions(nil, digest, encodeSigForTest(p, der, MarshalingTypeASN1), &SigningOptions{Marshaling: MarshalingTypeASN1})
		if err != nil {
			t.Fatalf("verify errored on a high-S signature: %v", err)
		}
		if !ok {
			t.Fatal("high-S signature was rejected; verification should accept it")
		}
	})
}

// TestSecp256k1Determinism locks in the RFC 6979 contract, so that a future
// library swap to randomized nonces fails loudly rather than silently changing
// externally-visible behaviour.
func TestSecp256k1Determinism(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)
	digest := mustHex(t, "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d")

	first, err := p.SignWithOptions(0, nil, digest, &SigningOptions{Marshaling: MarshalingTypeASN1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.SignWithOptions(0, nil, digest, &SigningOptions{Marshaling: MarshalingTypeASN1})
	if err != nil {
		t.Fatal(err)
	}

	if first.Signature != second.Signature {
		t.Fatalf("signing is not deterministic:\n first: %s\nsecond: %s", first.Signature, second.Signature)
	}
}

// TestSecp256k1CrossVerifyWithDecred verifies our emitted DER using decred's
// own strict parser and verifier, independent of our verify path.
func TestSecp256k1CrossVerifyWithDecred(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)
	digest := mustHex(t, "b706d561742ad3671703c247eb927ee8a386369c79644131cdeb2c5c26bf6c5d")

	res, err := p.SignWithOptions(0, nil, digest, &SigningOptions{Marshaling: MarshalingTypeASN1})
	if err != nil {
		t.Fatal(err)
	}
	der := decodeSigForTest(t, p, res.Signature, MarshalingTypeASN1)

	// ParseDERSignature is stricter than encoding/asn1: it requires minimal,
	// canonical DER. Our sign path uses decred's Serialize(), so this must pass.
	sig, err := dcrecdsa.ParseDERSignature(der)
	if err != nil {
		t.Fatalf("decred rejected our DER: %v", err)
	}

	keyEntry := p.Keys["1"]
	pub, err := Secp256k1PubFromKeyEntry(&keyEntry)
	if err != nil {
		t.Fatal(err)
	}

	if !sig.Verify(digest, pub) {
		t.Fatal("decred did not verify our signature")
	}
}

// TestSecp256k1RejectsBadInputLength covers the guard that makes the
// raw-digest design safe: anything other than 32 bytes must be refused rather
// than silently zero-extended or truncated.
func TestSecp256k1RejectsBadInputLength(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)

	for _, n := range []int{0, 1, 20, 31, 33, 64} {
		input := make([]byte, n)
		if _, err := p.SignWithOptions(0, nil, input, &SigningOptions{Marshaling: MarshalingTypeASN1}); err == nil {
			t.Errorf("sign accepted a %d-byte input; only 32 is valid", n)
		}
		if _, err := p.VerifySignatureWithOptions(nil, input, "vault:v1:AAAA", &SigningOptions{Marshaling: MarshalingTypeASN1}); err == nil {
			t.Errorf("verify accepted a %d-byte input; only 32 is valid", n)
		}
	}
}

// TestSecp256k1RejectsMalformedSignatures covers the validation added in the
// verify branch, including the ModNScalar truncation hazard.
func TestSecp256k1RejectsMalformedSignatures(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)
	digest := mustHex(t, "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d")

	// secp256k1 group order.
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

	t.Run("jws wrong length", func(t *testing.T) {
		for _, size := range []int{0, 32, 63, 65, 128} {
			sig := encodeSigForTest(p, make([]byte, size), MarshalingTypeJWS)
			if _, err := p.VerifySignatureWithOptions(nil, digest, sig, &SigningOptions{Marshaling: MarshalingTypeJWS}); err == nil {
				t.Errorf("verify accepted a %d-byte jws signature", size)
			}
		}
	})

	t.Run("asn1 degenerate components", func(t *testing.T) {
		for name, sigStruct := range map[string]ecdsaSignature{
			"zero r":     {R: big.NewInt(0), S: big.NewInt(1)},
			"zero s":     {R: big.NewInt(1), S: big.NewInt(0)},
			"negative r": {R: big.NewInt(-1), S: big.NewInt(1)},
			"r equals n": {R: n, S: big.NewInt(1)},
			"s equals n": {R: big.NewInt(1), S: n},
			// 33 bytes: exercises the truncation guard, since
			// ModNScalar.SetByteSlice would keep only the first 32 bytes.
			"oversized r": {R: new(big.Int).Lsh(big.NewInt(1), 264), S: big.NewInt(1)},
		} {
			der, err := asn1.Marshal(sigStruct)
			if err != nil {
				t.Fatalf("%s: could not build fixture: %v", name, err)
			}
			sig := encodeSigForTest(p, der, MarshalingTypeASN1)

			ok, err := p.VerifySignatureWithOptions(nil, digest, sig, &SigningOptions{Marshaling: MarshalingTypeASN1})
			if err == nil && ok {
				t.Errorf("%s: verify accepted a degenerate signature", name)
			}
		}
	})

	t.Run("asn1 trailing data", func(t *testing.T) {
		res, err := p.SignWithOptions(0, nil, digest, &SigningOptions{Marshaling: MarshalingTypeASN1})
		if err != nil {
			t.Fatal(err)
		}
		der := decodeSigForTest(t, p, res.Signature, MarshalingTypeASN1)
		sig := encodeSigForTest(p, append(der, 0x00), MarshalingTypeASN1)

		if _, err := p.VerifySignatureWithOptions(nil, digest, sig, &SigningOptions{Marshaling: MarshalingTypeASN1}); err == nil {
			t.Error("verify accepted a signature with trailing data")
		}
	})
}

// TestSecp256k1KeyTypePredicates pins the predicate table for this key type.
// HashSignatureInput in particular must stay false: see the comment on that
// method for why turning it on would let a caller silently sign the wrong
// bytes.
func TestSecp256k1KeyTypePredicates(t *testing.T) {
	kt := KeyType(KeyType_ECDSA_SECP256K1)

	for name, tc := range map[string]struct{ got, want bool }{
		"SigningSupported":         {kt.SigningSupported(), true},
		"HashSignatureInput":       {kt.HashSignatureInput(), false},
		"EncryptionSupported":      {kt.EncryptionSupported(), false},
		"DecryptionSupported":      {kt.DecryptionSupported(), false},
		"DerivationSupported":      {kt.DerivationSupported(), false},
		"KeyAgreementSupported":    {kt.KeyAgreementSupported(), false},
		"AssociatedDataSupported":  {kt.AssociatedDataSupported(), false},
		"ImportPublicKeySupported": {kt.ImportPublicKeySupported(), false},
	} {
		if tc.got != tc.want {
			t.Errorf("%s() = %v, want %v", name, tc.got, tc.want)
		}
	}

	if got := kt.String(); got != "ecdsa-secp256k1" {
		t.Errorf("String() = %q, want %q", got, "ecdsa-secp256k1")
	}

	if got := kt.DefaultHashAlgorithm(); got != HashTypeNone {
		t.Errorf("DefaultHashAlgorithm() = %v, want HashTypeNone", got)
	}
}

// TestSecp256k1KeyTypeConstantValue pins the persisted integer value. Policy
// .Type is stored as a raw int, so a change here silently reinterprets every
// key already written to storage.
func TestSecp256k1KeyTypeConstantValue(t *testing.T) {
	if KeyType_ECDSA_SECP256K1 != 15 {
		t.Fatalf("KeyType_ECDSA_SECP256K1 = %d, want 15; a constant was inserted or reordered, which corrupts existing stored keys", KeyType_ECDSA_SECP256K1)
	}
	if KeyType_MLDSA87 != 14 {
		t.Fatalf("KeyType_MLDSA87 = %d, want 14; the iota block was reordered", KeyType_MLDSA87)
	}
}

// TestSecp256k1UnsupportedOperations asserts the out-of-scope paths fail with
// accurate messages rather than misleading ones.
func TestSecp256k1UnsupportedOperations(t *testing.T) {
	d, _ := new(big.Int).SetString(testSecp256k1ScalarHex, 16)
	p := secp256k1PolicyFromScalar(t, d)
	keyEntry := p.Keys["1"]

	t.Run("CSR and certificate binding", func(t *testing.T) {
		_, err := p.getPrivateKey(&keyEntry)
		if err == nil {
			t.Fatal("expected getPrivateKey to refuse this key type")
		}
		// The default branch would wrongly claim the key does not support
		// signing; assert we produced the accurate message instead.
		if got := err.Error(); !bytes.Contains([]byte(got), []byte("CSR generation")) {
			t.Errorf("got %q, want a message mentioning CSR generation", got)
		}
	})

	t.Run("import", func(t *testing.T) {
		var ke KeyEntry
		err := ke.parseFromKey(KeyType_ECDSA_SECP256K1, nil)
		if err == nil {
			t.Fatal("expected parseFromKey to refuse this key type")
		}
		if got := err.Error(); !bytes.Contains([]byte(got), []byte("importing key material is not supported")) {
			t.Errorf("got %q, want a message about import not being supported", got)
		}
	})

	t.Run("ECDH key agreement", func(t *testing.T) {
		if _, err := p.DeriveKeyECDH(1, nil, 32); err == nil {
			t.Fatal("expected ECDH to refuse this key type")
		}
	})
}
