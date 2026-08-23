// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newTransportIdentityTestNode(t *testing.T, trustedKeys ...ed25519.PublicKey) *SamNode {
	t.Helper()
	privateKey, _, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("generate node identity: %v", err)
	}
	keys := make([]TrustedKey, 0, len(trustedKeys))
	for _, key := range trustedKeys {
		keys = append(keys, TrustedKey{Key: key, ReceivedAt: time.Now()})
	}
	return &SamNode{
		config:      Options{PrivKey: privateKey},
		trustedKeys: keys,
	}
}

func decodeTransportIdentityResponse(t *testing.T, result *mcp.CallToolResult) transportIdentityResponse {
	t.Helper()
	if result == nil || len(result.Content) != 1 {
		t.Fatalf("expected one transport identity content item")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %T", result.Content[0])
	}
	var response transportIdentityResponse
	if err := json.Unmarshal([]byte(text.Text), &response); err != nil {
		t.Fatalf("decode transport identity: %v", err)
	}
	return response
}

func mustEd25519SPKIFingerprint(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	fingerprint, err := ed25519SPKIFingerprint(publicKey)
	if err != nil {
		t.Fatalf("fingerprint Ed25519 key: %v", err)
	}
	return fingerprint
}

func TestHandleGetTransportIdentitySignsPinnedTrustedKey(t *testing.T) {
	controlPlanePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate control-plane key: %v", err)
	}
	node := newTransportIdentityTestNode(t, controlPlanePublic)
	nonce := strings.Repeat("a1", 32)
	controlPlaneFingerprint := mustEd25519SPKIFingerprint(t, controlPlanePublic)

	result, _, err := node.handleGetTransportIdentity(
		context.Background(),
		nil,
		GetTransportIdentityParams{
			Nonce:                   nonce,
			ControlPlaneFingerprint: controlPlaneFingerprint,
		},
	)
	if err != nil {
		t.Fatalf("handle transport identity: %v", err)
	}
	response := decodeTransportIdentityResponse(t, result)
	if response.Schema != transportIdentitySchema || response.Nonce != nonce {
		t.Fatalf("unexpected identity response: %+v", response)
	}
	if response.ControlPlaneFingerprint != controlPlaneFingerprint {
		t.Fatalf("control-plane fingerprint mismatch")
	}
	if response.SignatureAlgorithm != "ed25519" {
		t.Fatalf("unexpected signature algorithm %q", response.SignatureAlgorithm)
	}
	nodePublicDER, err := base64.StdEncoding.DecodeString(response.NodePublicKeySPKIBase64)
	if err != nil {
		t.Fatalf("decode node public key: %v", err)
	}
	if sha256Fingerprint(nodePublicDER) != response.NodeKeyFingerprint {
		t.Fatalf("node key fingerprint mismatch")
	}
	parsedPublicKey, err := x509.ParsePKIXPublicKey(nodePublicDER)
	if err != nil {
		t.Fatalf("parse node public key: %v", err)
	}
	nodePublicKey, ok := parsedPublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected Ed25519 public key, got %T", parsedPublicKey)
	}
	signature, err := base64.StdEncoding.DecodeString(response.SignatureBase64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(nodePublicKey, transportIdentityPayload(
		nonce,
		response.NodeKeyFingerprint,
		controlPlaneFingerprint,
	), signature) {
		t.Fatalf("transport identity signature did not verify")
	}
	if strings.Contains(string(mustJSONMarshal(t, response)), base64.StdEncoding.EncodeToString(controlPlanePublic)) {
		t.Fatalf("response must not disclose the control-plane public key")
	}
}

func mustJSONMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	return encoded
}

func TestHandleGetTransportIdentitySelectsExpectedRotationKey(t *testing.T) {
	first, _, _ := ed25519.GenerateKey(rand.Reader)
	second, _, _ := ed25519.GenerateKey(rand.Reader)
	node := newTransportIdentityTestNode(t, first, second)
	expected := mustEd25519SPKIFingerprint(t, second)

	result, _, err := node.handleGetTransportIdentity(context.Background(), nil, GetTransportIdentityParams{
		Nonce:                   strings.Repeat("02", 32),
		ControlPlaneFingerprint: expected,
	})
	if err != nil {
		t.Fatalf("select trusted rotation key: %v", err)
	}
	if response := decodeTransportIdentityResponse(t, result); response.ControlPlaneFingerprint != expected {
		t.Fatalf("signed the wrong trusted control-plane key")
	}
}

func TestHandleGetTransportIdentityFailsClosed(t *testing.T) {
	controlPlanePublic, _, _ := ed25519.GenerateKey(rand.Reader)
	node := newTransportIdentityTestNode(t, controlPlanePublic)
	validFingerprint := mustEd25519SPKIFingerprint(t, controlPlanePublic)
	for _, tc := range []struct {
		name        string
		nonce       string
		fingerprint string
	}{
		{name: "short nonce", nonce: "00", fingerprint: validFingerprint},
		{name: "uppercase nonce", nonce: strings.Repeat("AF", 32), fingerprint: validFingerprint},
		{name: "malformed fingerprint", nonce: strings.Repeat("03", 32), fingerprint: "sha256:no"},
		{name: "untrusted fingerprint", nonce: strings.Repeat("04", 32), fingerprint: sha256Fingerprint([]byte("other"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := node.handleGetTransportIdentity(context.Background(), nil, GetTransportIdentityParams{
				Nonce:                   tc.nonce,
				ControlPlaneFingerprint: tc.fingerprint,
			}); err == nil {
				t.Fatalf("expected request to fail closed")
			}
		})
	}

	withoutTrustedKey := newTransportIdentityTestNode(t)
	if _, _, err := withoutTrustedKey.handleGetTransportIdentity(
		context.Background(),
		nil,
		GetTransportIdentityParams{
			Nonce:                   strings.Repeat("05", 32),
			ControlPlaneFingerprint: validFingerprint,
		},
	); err == nil {
		t.Fatalf("node without a trusted control-plane key must fail closed")
	}
}
