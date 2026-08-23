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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const transportIdentitySchema = "sam.transport-identity.v1"

// GetTransportIdentityParams identifies the trusted control-plane key that the
// caller expects this local node to attest.
type GetTransportIdentityParams struct {
	Nonce                   string `json:"nonce" jsonschema:"A fresh 32-byte lowercase hexadecimal challenge nonce."`
	ControlPlaneFingerprint string `json:"control_plane_fingerprint" jsonschema:"SHA-256 over canonical SPKI DER for an Ed25519 control-plane public key the node must currently trust."`
}

type transportIdentityResponse struct {
	Schema                  string `json:"schema"`
	Nonce                   string `json:"nonce"`
	NodePublicKeySPKIBase64 string `json:"node_public_key_spki_base64"`
	NodeKeyFingerprint      string `json:"node_key_fingerprint"`
	ControlPlaneFingerprint string `json:"control_plane_fingerprint"`
	SignatureAlgorithm      string `json:"signature_algorithm"`
	SignatureBase64         string `json:"signature_base64"`
}

func sha256Fingerprint(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func ed25519SPKIFingerprint(publicKey ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return sha256Fingerprint(der), nil
}

func validSHA256Fingerprint(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexValue := strings.TrimPrefix(value, "sha256:")
	if hexValue != strings.ToLower(hexValue) {
		return false
	}
	decoded, err := hex.DecodeString(hexValue)
	return err == nil && len(decoded) == sha256.Size
}

func validTransportIdentityNonce(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func transportIdentityPayload(nonce, nodeKeyFingerprint, controlPlaneFingerprint string) []byte {
	return []byte("sam-transport-identity-v1\n" +
		"nonce:" + nonce + "\n" +
		"node_key_fingerprint:" + nodeKeyFingerprint + "\n" +
		"control_plane_fingerprint:" + controlPlaneFingerprint + "\n")
}

func (n *SamNode) trustsControlPlaneFingerprint(expected string) bool {
	if !validSHA256Fingerprint(expected) {
		return false
	}
	n.keysMu.RLock()
	trustedKeys := make([]ed25519.PublicKey, 0, len(n.trustedKeys))
	for _, trusted := range n.trustedKeys {
		if len(trusted.Key) != ed25519.PublicKeySize {
			continue
		}
		keyCopy := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(keyCopy, trusted.Key)
		trustedKeys = append(trustedKeys, keyCopy)
	}
	n.keysMu.RUnlock()

	for _, trusted := range trustedKeys {
		fingerprint, err := ed25519SPKIFingerprint(trusted)
		if err == nil && fingerprint == expected {
			return true
		}
	}
	return false
}

func (n *SamNode) handleGetTransportIdentity(
	ctx context.Context,
	req *mcp.CallToolRequest,
	params GetTransportIdentityParams,
) (*mcp.CallToolResult, any, error) {
	if n == nil || n.config.PrivKey == nil {
		return nil, nil, fmt.Errorf("node identity is not initialized")
	}
	if n.config.PrivKey.Type() != libp2pcrypto.Ed25519 {
		return nil, nil, fmt.Errorf("node identity must use Ed25519")
	}
	if !validTransportIdentityNonce(params.Nonce) {
		return nil, nil, fmt.Errorf("nonce must be 32-byte lowercase hexadecimal")
	}
	if !n.trustsControlPlaneFingerprint(params.ControlPlaneFingerprint) {
		return nil, nil, fmt.Errorf("requested control-plane key is not trusted")
	}

	nodePublicRaw, err := n.config.PrivKey.GetPublic().Raw()
	if err != nil {
		return nil, nil, fmt.Errorf("read Ed25519 node public key: %w", err)
	}
	if len(nodePublicRaw) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid Ed25519 node public key size: %d", len(nodePublicRaw))
	}
	nodePublicDER, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(nodePublicRaw))
	if err != nil {
		return nil, nil, fmt.Errorf("encode node public key: %w", err)
	}
	nodeKeyFingerprint, err := ed25519SPKIFingerprint(ed25519.PublicKey(nodePublicRaw))
	if err != nil {
		return nil, nil, fmt.Errorf("fingerprint node public key: %w", err)
	}
	signature, err := n.config.PrivKey.Sign(transportIdentityPayload(
		params.Nonce,
		nodeKeyFingerprint,
		params.ControlPlaneFingerprint,
	))
	if err != nil {
		return nil, nil, fmt.Errorf("sign transport identity: %w", err)
	}

	responseBytes, err := json.Marshal(transportIdentityResponse{
		Schema:                  transportIdentitySchema,
		Nonce:                   params.Nonce,
		NodePublicKeySPKIBase64: base64.StdEncoding.EncodeToString(nodePublicDER),
		NodeKeyFingerprint:      nodeKeyFingerprint,
		ControlPlaneFingerprint: params.ControlPlaneFingerprint,
		SignatureAlgorithm:      "ed25519",
		SignatureBase64:         base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("encode transport identity: %w", err)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: string(responseBytes)},
	}}, nil, nil
}
