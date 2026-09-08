// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// A fixed 32-byte digest, standing in for the Keccak-256 hash a blockchain
// client would compute (e.g. an EIP-191 personal_sign digest).
const testSecp256k1DigestB64 = "SmxBmh4lyFMnEVxKzlht7N3+KZDtjz1NgBhxFYM4UB0="

func secp256k1CreateKey(t *testing.T, b *backend, s logical.Storage, name string) {
	t.Helper()

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "keys/" + name,
		Data:      map[string]any{"type": "ecdsa-secp256k1"},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "key creation failed: %#v", resp)
}

// TestTransit_Secp256k1_CreateAndRead covers key creation and the read path,
// including the two things a DVN client depends on: the curve name and a
// parseable public key.
func TestTransit_Secp256k1_CreateAndRead(t *testing.T) {
	b, s := createBackendWithStorage(t)
	secp256k1CreateKey(t, b, s, "dvn")

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "keys/dvn",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "%#v", resp)

	require.Equal(t, "ecdsa-secp256k1", resp.Data["type"])

	// formatKeyPolicy's outer switch has no default branch, so a missing case
	// arm would silently produce a response with no "keys" at all.
	keys, ok := resp.Data["keys"].(map[string]map[string]any)
	require.True(t, ok, "response has no keys map: %#v", resp.Data)
	require.Contains(t, keys, "1")

	require.Equal(t, "secp256k1", keys["1"]["name"], "curve name should be the RFC 8812 JWK crv value")

	pubPEM, ok := keys["1"]["public_key"].(string)
	require.True(t, ok, "no public_key in response")
	require.NotEmpty(t, pubPEM)

	block, _ := pem.Decode([]byte(pubPEM))
	require.NotNil(t, block, "public_key is not valid PEM")
	require.Equal(t, "PUBLIC KEY", block.Type)

	pub, err := keysutil.ParseSecp256k1PKIXPublicKey(block.Bytes)
	require.NoError(t, err, "public_key did not parse as a secp256k1 SPKI")

	// The uncompressed point is what a client slices to get X||Y in order to
	// derive a blockchain address.
	require.Len(t, pub.SerializeUncompressed(), 65)
	require.Equal(t, byte(0x04), pub.SerializeUncompressed()[0])
}

// TestTransit_Secp256k1_SignVerify covers the round trip through the HTTP-level
// paths for both marshalings.
func TestTransit_Secp256k1_SignVerify(t *testing.T) {
	b, s := createBackendWithStorage(t)
	secp256k1CreateKey(t, b, s, "dvn")

	for _, marshaling := range []string{"asn1", "jws"} {
		t.Run(marshaling, func(t *testing.T) {
			signResp, err := b.HandleRequest(t.Context(), &logical.Request{
				Storage:   s,
				Operation: logical.UpdateOperation,
				Path:      "sign/dvn",
				Data: map[string]any{
					"input":                testSecp256k1DigestB64,
					"marshaling_algorithm": marshaling,
				},
			})
			require.NoError(t, err)
			require.NotNil(t, signResp)
			require.False(t, signResp.IsError(), "%#v", signResp)

			sig, ok := signResp.Data["signature"].(string)
			require.True(t, ok)
			require.True(t, strings.HasPrefix(sig, "vault:v1:"), "unexpected signature prefix: %s", sig)

			verifyResp, err := b.HandleRequest(t.Context(), &logical.Request{
				Storage:   s,
				Operation: logical.UpdateOperation,
				Path:      "verify/dvn",
				Data: map[string]any{
					"input":                testSecp256k1DigestB64,
					"signature":            sig,
					"marshaling_algorithm": marshaling,
				},
			})
			require.NoError(t, err)
			require.NotNil(t, verifyResp)
			require.False(t, verifyResp.IsError(), "%#v", verifyResp)
			require.Equal(t, true, verifyResp.Data["valid"])

			if marshaling == "jws" {
				raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sig, "vault:v1:"))
				require.NoError(t, err)
				require.Len(t, raw, 64, "jws signature must be exactly r||s")
			}
		})
	}
}

// TestTransit_Secp256k1_NoImplicitHashing is the regression test for the design
// decision that makes this key type safe to use: the caller's 32 bytes must be
// signed verbatim, and any other length must be refused rather than hashed.
func TestTransit_Secp256k1_NoImplicitHashing(t *testing.T) {
	b, s := createBackendWithStorage(t)
	secp256k1CreateKey(t, b, s, "dvn")

	t.Run("32-byte digest needs no prehashed flag", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "sign/dvn",
			Data:      map[string]any{"input": testSecp256k1DigestB64},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "signing a bare 32-byte digest should just work: %#v", resp)
	})

	t.Run("wrong input length is refused", func(t *testing.T) {
		// If HashSignatureInput() were true for this type, transit would hash
		// this to 32 bytes and happily sign it -- a valid signature over bytes
		// the caller never chose.
		for _, plaintext := range []string{
			base64.StdEncoding.EncodeToString([]byte("this is a message, not a digest")),
			base64.StdEncoding.EncodeToString(make([]byte, 20)),
			base64.StdEncoding.EncodeToString(make([]byte, 64)),
			"",
		} {
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Storage:   s,
				Operation: logical.UpdateOperation,
				Path:      "sign/dvn",
				Data:      map[string]any{"input": plaintext},
			})
			isError := err != nil || (resp != nil && resp.IsError())
			require.True(t, isError, "signing a non-32-byte input should fail, got %#v", resp)
		}
	})
}

// TestTransit_Secp256k1_Export covers both export types and all formats.
func TestTransit_Secp256k1_Export(t *testing.T) {
	b, s := createBackendWithStorage(t)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "keys/exportable",
		Data: map[string]any{
			"type":       "ecdsa-secp256k1",
			"exportable": true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "%#v", resp)

	t.Run("public-key", func(t *testing.T) {
		for _, format := range []string{"", "pem", "der"} {
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Storage:   s,
				Operation: logical.ReadOperation,
				Path:      "export/public-key/exportable",
				Data:      map[string]any{"format": format},
			})
			require.NoError(t, err, "format %q", format)
			require.NotNil(t, resp)
			require.False(t, resp.IsError(), "format %q: %#v", format, resp)

			keys := resp.Data["keys"].(map[string]string)
			out := keys["1"]
			require.NotEmpty(t, out)

			der := derFromExport(t, out, format)
			_, err = keysutil.ParseSecp256k1PKIXPublicKey(der)
			require.NoError(t, err, "format %q did not yield a parseable SPKI", format)
		}
	})

	t.Run("signing-key", func(t *testing.T) {
		for _, format := range []string{"", "pem", "der"} {
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Storage:   s,
				Operation: logical.ReadOperation,
				Path:      "export/signing-key/exportable",
				Data:      map[string]any{"format": format},
			})
			require.NoError(t, err, "format %q", format)
			require.NotNil(t, resp)
			require.False(t, resp.IsError(), "format %q: %#v", format, resp)

			keys := resp.Data["keys"].(map[string]string)
			out := keys["1"]
			require.NotEmpty(t, out)

			der := derFromExport(t, out, format)

			// "" yields SEC1, "pem"/"der" yield PKCS#8, mirroring the existing
			// keyEntryToECPrivateKey semantics.
			if format == "" {
				_, err = keysutil.ParseSecp256k1SEC1PrivateKey(der)
			} else {
				_, err = keysutil.ParseSecp256k1PKCS8PrivateKey(der)
			}
			require.NoError(t, err, "format %q did not yield a parseable private key", format)
		}
	})

	t.Run("raw format is refused", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.ReadOperation,
			Path:      "export/signing-key/exportable",
			Data:      map[string]any{"format": "raw"},
		})
		isError := err != nil || (resp != nil && resp.IsError())
		require.True(t, isError, "raw format should be refused, got %#v", resp)
	})
}

func derFromExport(t *testing.T, out, format string) []byte {
	t.Helper()

	if format == "der" {
		der, err := base64.StdEncoding.DecodeString(out)
		require.NoError(t, err, "der export was not base64")
		return der
	}

	block, _ := pem.Decode([]byte(out))
	require.NotNil(t, block, "export for format %q was not valid PEM: %s", format, out)
	return block.Bytes
}

// TestTransit_Secp256k1_Rotation covers multiple key versions.
func TestTransit_Secp256k1_Rotation(t *testing.T) {
	b, s := createBackendWithStorage(t)
	secp256k1CreateKey(t, b, s, "dvn")

	for range 2 {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "keys/dvn/rotate",
		})
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "%#v", resp)
	}

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "keys/dvn",
	})
	require.NoError(t, err)
	keys := resp.Data["keys"].(map[string]map[string]any)
	require.Len(t, keys, 3)

	// Every version must have a distinct public key, and each must be usable.
	seen := map[string]bool{}
	for ver := range keys {
		pub := keys[ver]["public_key"].(string)
		require.False(t, seen[pub], "version %s reuses another version's public key", ver)
		seen[pub] = true
	}

	for _, ver := range []int{1, 2, 3} {
		signResp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "sign/dvn",
			Data: map[string]any{
				"input":       testSecp256k1DigestB64,
				"key_version": ver,
			},
		})
		require.NoError(t, err)
		require.False(t, signResp.IsError(), "version %d: %#v", ver, signResp)

		verifyResp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "verify/dvn",
			Data: map[string]any{
				"input":     testSecp256k1DigestB64,
				"signature": signResp.Data["signature"],
			},
		})
		require.NoError(t, err)
		require.Equal(t, true, verifyResp.Data["valid"], "version %d signature did not verify", ver)
	}
}

// TestTransit_Secp256k1_BackupRestore is the persistence test: it proves the
// stored key type integer and the big.Int EC fields survive a full
// marshal/unmarshal cycle, and that a signature made before the backup still
// verifies afterwards.
func TestTransit_Secp256k1_BackupRestore(t *testing.T) {
	b, s := createBackendWithStorage(t)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "keys/dvn",
		Data: map[string]any{
			"type":                   "ecdsa-secp256k1",
			"allow_plaintext_backup": true,
			"exportable":             true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "%#v", resp)

	signResp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "sign/dvn",
		Data:      map[string]any{"input": testSecp256k1DigestB64},
	})
	require.NoError(t, err)
	require.False(t, signResp.IsError(), "%#v", signResp)
	sigBefore := signResp.Data["signature"].(string)

	backupResp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "backup/dvn",
	})
	require.NoError(t, err)
	require.False(t, backupResp.IsError(), "%#v", backupResp)
	backup := backupResp.Data["backup"].(string)

	restoreResp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "restore/restored",
		Data:      map[string]any{"backup": backup},
	})
	require.NoError(t, err)
	require.False(t, restoreResp != nil && restoreResp.IsError(), "%#v", restoreResp)

	// The restored key must still be recognised as secp256k1...
	readResp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "keys/restored",
	})
	require.NoError(t, err)
	require.Equal(t, "ecdsa-secp256k1", readResp.Data["type"], "restored key lost its type")

	// ...and must still verify the signature made before the backup.
	verifyResp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "verify/restored",
		Data: map[string]any{
			"input":     testSecp256k1DigestB64,
			"signature": sigBefore,
		},
	})
	require.NoError(t, err)
	require.Equal(t, true, verifyResp.Data["valid"], "signature made before backup did not verify after restore")

	// Signing proves the private scalar survived, not just the public key.
	signAfter, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage: s, Operation: logical.UpdateOperation, Path: "sign/restored",
		Data: map[string]any{"input": testSecp256k1DigestB64},
	})
	require.NoError(t, err)
	require.False(t, signAfter.IsError())
	require.Equal(t, sigBefore, signAfter.Data["signature"])
}

// TestTransit_Secp256k1_UnsupportedOperations asserts every out-of-scope
// operation fails, and fails with an accurate message rather than a misleading
// "unknown key type".
func TestTransit_Secp256k1_UnsupportedOperations(t *testing.T) {
	b, s := createBackendWithStorage(t)
	secp256k1CreateKey(t, b, s, "dvn")

	t.Run("import", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "keys/imported/import",
			Data: map[string]any{
				"type":       "ecdsa-secp256k1",
				"ciphertext": "irrelevant",
			},
		})
		require.True(t, err != nil || resp.IsError(), "import should be refused")
		require.Contains(t, resp.Error().Error(), "importing key material is not supported",
			"error should say why, not claim the type is unknown")
	})

	t.Run("derive_key", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "derive-key/derived",
			Data: map[string]any{
				"base_key_name":   "dvn",
				"peer_public_key": "unused: key agreement must be rejected before parsing",
			},
		})
		require.ErrorIs(t, err, logical.ErrInvalidRequest)
		require.Contains(t, resp.Error().Error(), "does not support key agreement")
	})

	t.Run("certificate binding", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.UpdateOperation, Path: "keys/dvn/set-certificate",
			Data: map[string]any{"certificate_chain": "unused: binding must be rejected before parsing"},
		})
		require.ErrorIs(t, err, logical.ErrInvalidRequest)
		require.Contains(t, resp.Error().Error(), "do not support certificate binding")
	})

	t.Run("BYOK export", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.UpdateOperation, Path: "keys/wrapping",
			Data: map[string]any{"type": "rsa-2048"},
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		resp, err = b.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.UpdateOperation, Path: "keys/dvn/config",
			Data: map[string]any{"exportable": true},
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		resp, err = b.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.ReadOperation, Path: "byok-export/wrapping/dvn",
		})
		require.ErrorIs(t, err, logical.ErrInvalidRequest)
		require.Contains(t, resp.Error().Error(), "BYOK export is not supported")
	})

	t.Run("csr", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "keys/dvn/csr",
		})
		require.True(t, err != nil || (resp != nil && resp.IsError()), "CSR generation should be refused")
		if resp != nil && resp.IsError() {
			require.Contains(t, resp.Error().Error(), "CSR generation",
				"error should not claim the key does not support signing")
		}
	})

	t.Run("encryption", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "encrypt/dvn",
			Data:      map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("hello"))},
		})
		require.True(t, err != nil || (resp != nil && resp.IsError()), "encryption should be refused")
	})
}

// TestTransit_Secp256k1_AutoRotateRejected covers both ways auto-rotation could
// be enabled. Rotation changes the derived blockchain address, so allowing it
// silently breaks on-chain signer enrolment.
func TestTransit_Secp256k1_AutoRotateRejected(t *testing.T) {
	b, s := createBackendWithStorage(t)

	t.Run("at creation", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "keys/autorotate",
			Data: map[string]any{
				"type":               "ecdsa-secp256k1",
				"auto_rotate_period": "24h",
			},
		})
		require.True(t, err != nil || (resp != nil && resp.IsError()),
			"auto_rotate_period should be refused at creation, got %#v", resp)
	})

	// The creation-time guard alone is not enough: without a matching check on
	// keys/config it could be bypassed by enabling rotation after the fact.
	t.Run("via keys/config", func(t *testing.T) {
		secp256k1CreateKey(t, b, s, "dvn")

		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage:   s,
			Operation: logical.UpdateOperation,
			Path:      "keys/dvn/config",
			Data:      map[string]any{"auto_rotate_period": "24h"},
		})
		require.True(t, err != nil || (resp != nil && resp.IsError()),
			"auto_rotate_period should be refused via keys/config, got %#v", resp)

		// A rejected write must leave both cached and persisted state intact.
		read, err := b.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.ReadOperation, Path: "keys/dvn",
		})
		require.NoError(t, err)
		require.EqualValues(t, 0, read.Data["auto_rotate_period"])

		resp, err = b.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.UpdateOperation, Path: "keys/dvn/config",
			Data: map[string]any{"deletion_allowed": true},
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		fresh := createBackendWithForceNoCacheWithSysViewWithStorage(t, s)
		read, err = fresh.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.ReadOperation, Path: "keys/dvn",
		})
		require.NoError(t, err)
		require.EqualValues(t, 0, read.Data["auto_rotate_period"])

		p, _, err := b.GetPolicyExclusive(t.Context(), keysutil.PolicyRequest{Storage: s, Name: "dvn"}, b.GetRandomReader())
		require.NoError(t, err)
		entry := p.Keys["1"]
		entry.CreationTime = time.Now().Add(-48 * time.Hour)
		p.Keys["1"] = entry
		p.Unlock()
		require.NoError(t, b.autoRotateKeys(t.Context(), &logical.Request{Storage: s}))
		read, err = b.HandleRequest(t.Context(), &logical.Request{
			Storage: s, Operation: logical.ReadOperation, Path: "keys/dvn",
		})
		require.NoError(t, err)
		require.Equal(t, 1, read.Data["latest_version"])
	})
}

// TestTransit_Secp256k1_HMAC confirms HMAC still works, since HMACKey is
// populated before the key-type switch in RotateInMemory.
func TestTransit_Secp256k1_HMAC(t *testing.T) {
	b, s := createBackendWithStorage(t)
	secp256k1CreateKey(t, b, s, "dvn")

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "hmac/dvn",
		Data:      map[string]any{"input": testSecp256k1DigestB64},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "%#v", resp)
	require.NotEmpty(t, resp.Data["hmac"])
}

// TestTransit_Secp256k1_TypeAlias covers the input alias.
func TestTransit_Secp256k1_TypeAlias(t *testing.T) {
	b, s := createBackendWithStorage(t)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      "keys/aliased",
		Data:      map[string]any{"type": "ecdsa-p256k1"},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "%#v", resp)

	readResp, err := b.HandleRequest(t.Context(), &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "keys/aliased",
	})
	require.NoError(t, err)
	require.Equal(t, "ecdsa-secp256k1", readResp.Data["type"],
		"the alias should normalise to the canonical name")
}
