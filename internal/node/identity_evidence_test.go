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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p"
)

func newIdentityEvidenceTestNode(t *testing.T, labels map[string]string) (*SamNode, ed25519.PrivateKey, time.Time) {
	t.Helper()
	host, err := libp2p.New()
	if err != nil {
		t.Fatalf("create libp2p host: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })
	controlPlanePublic, controlPlanePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate control-plane key: %v", err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	biscuitBytes, err := identity.MintBootstrapBiscuitToken(controlPlanePrivate, host.ID(), api.RoleNode, expiresAt, nil, labels)
	if err != nil {
		t.Fatalf("mint identity biscuit: %v", err)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveIdentity(biscuitBytes); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	if err := store.SaveControlPlaneURL("https://cp.example"); err != nil {
		t.Fatalf("save control-plane URL: %v", err)
	}
	revokedPeers, err := lru.New[string, int64](16)
	if err != nil {
		t.Fatalf("create revocation cache: %v", err)
	}
	node := &SamNode{
		Host:           host,
		Store:          store,
		trustedKeys:    []TrustedKey{{Key: controlPlanePublic, ReceivedAt: time.Now().UTC().Add(-time.Minute)}},
		revokedPeers:   revokedPeers,
		BiscuitTimeout: time.Second,
	}
	node.SetIdentityCache(biscuitBytes)
	return node, controlPlanePrivate, expiresAt
}

func localSocketRequest(method, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	return request.WithContext(context.WithValue(request.Context(), localSocketContextKey{}, true))
}

func TestIdentityEvidenceRequiresStrongTransport(t *testing.T) {
	node, _, _ := newIdentityEvidenceTestNode(t, nil)
	handler := requireIdentityEvidenceTransport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleIdentityEvidence(node, w, r)
	}))

	plainRecorder := httptest.NewRecorder()
	handler.ServeHTTP(plainRecorder, httptest.NewRequest(http.MethodGet, "/sam/identity", nil))
	if plainRecorder.Code != http.StatusForbidden {
		t.Fatalf("plain TCP status = %d, want %d", plainRecorder.Code, http.StatusForbidden)
	}

	socketRecorder := httptest.NewRecorder()
	handler.ServeHTTP(socketRecorder, localSocketRequest(http.MethodGet, "/sam/identity"))
	if socketRecorder.Code != http.StatusOK {
		t.Fatalf("socket status = %d, body = %s", socketRecorder.Code, socketRecorder.Body.String())
	}

	mtlsRequest := httptest.NewRequest(http.MethodGet, "/sam/identity", nil)
	mtlsRequest.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
	mtlsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(mtlsRecorder, mtlsRequest)
	if mtlsRecorder.Code != http.StatusOK {
		t.Fatalf("mTLS status = %d, body = %s", mtlsRecorder.Code, mtlsRecorder.Body.String())
	}
}

func TestIdentityEvidenceReturnsVerifiableClosedResponse(t *testing.T) {
	node, _, expiresAt := newIdentityEvidenceTestNode(t, map[string]string{"region": "us-east-1"})
	recorder := httptest.NewRecorder()
	handleIdentityEvidence(node, recorder, localSocketRequest(http.MethodGet, "/sam/identity"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response identityEvidenceResponse
	decoder := json.NewDecoder(recorder.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Schema != identityEvidenceSchema || response.PeerID != node.Host.ID().String() || !response.PeerBindingVerified || !response.Enrolled {
		t.Fatalf("unexpected identity response: %+v", response)
	}
	if response.BiscuitExpiresAt != expiresAt.Format(time.RFC3339Nano) || len(response.TrustedControlPlaneKeys) != 1 {
		t.Fatalf("unexpected expiry or key set: %+v", response)
	}
	der, err := base64.StdEncoding.DecodeString(response.TrustedControlPlaneKeys[0].SPKIDERBase64)
	if err != nil {
		t.Fatalf("decode SPKI: %v", err)
	}
	if sha256Fingerprint(der) != response.SelectedVerifyingKeyFingerprint {
		t.Fatalf("selected key fingerprint does not match returned SPKI")
	}
}

func TestBuildPeerEvidenceBindsRequestedConnectionAndBiscuitPeers(t *testing.T) {
	node, controlPlanePrivate, expiresAt := newIdentityEvidenceTestNode(t, nil)
	provider, err := libp2p.New()
	if err != nil {
		t.Fatalf("create provider host: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	providerBiscuit, err := identity.MintBootstrapBiscuitToken(controlPlanePrivate, provider.ID(), api.RoleNode, expiresAt, nil, map[string]string{"region": "us-east-1"})
	if err != nil {
		t.Fatalf("mint provider biscuit: %v", err)
	}
	fetchedAt := time.Now().UTC().Add(-time.Second)
	response, err := node.buildPeerEvidence(provider.ID(), peerBiscuitObservation{
		Biscuit:        providerBiscuit,
		ConnectionPeer: provider.ID(),
		FetchedAt:      fetchedAt,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("build peer evidence: %v", err)
	}
	if !response.Verified || !response.PeerBindingVerified || response.RequestedPeerID != provider.ID().String() || response.ConnectionPeerID != provider.ID().String() || response.BiscuitPeerID != provider.ID().String() {
		t.Fatalf("unexpected peer binding: %+v", response)
	}
	if response.Attested.Labels["region"] != "us-east-1" || len(response.Revocation.RevocationIDs) == 0 || response.Freshness.CacheHit {
		t.Fatalf("missing attestation, revocation, or freshness evidence: %+v", response)
	}
	if sha256Fingerprint(mustDecodeBase64(t, response.VerifyingKeySPKIDERBase64)) != response.VerifyingKeyFingerprint {
		t.Fatalf("verifying key fingerprint does not match returned SPKI")
	}
}

func TestBuildPeerEvidenceFailsClosedOnBindingRevocationAndKeyRotation(t *testing.T) {
	node, controlPlanePrivate, expiresAt := newIdentityEvidenceTestNode(t, nil)
	provider, _ := libp2p.New()
	t.Cleanup(func() { _ = provider.Close() })
	other, _ := libp2p.New()
	t.Cleanup(func() { _ = other.Close() })
	providerBiscuit, err := identity.MintBootstrapBiscuitToken(controlPlanePrivate, provider.ID(), api.RoleNode, expiresAt, nil, nil)
	if err != nil {
		t.Fatalf("mint provider biscuit: %v", err)
	}
	observation := peerBiscuitObservation{Biscuit: providerBiscuit, ConnectionPeer: provider.ID(), FetchedAt: time.Now().UTC()}
	if _, err := node.buildPeerEvidence(other.ID(), observation, time.Now().UTC()); err == nil {
		t.Fatalf("requested/connection mismatch must fail closed")
	}

	node.revokedPeers.Add(provider.ID().String(), time.Now().Unix())
	if _, err := node.buildPeerEvidence(provider.ID(), observation, time.Now().UTC()); err == nil {
		t.Fatalf("revoked peer must fail closed")
	}
	node.revokedPeers.Remove(provider.ID().String())

	newPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	node.keysMu.Lock()
	node.trustedKeys = []TrustedKey{{Key: newPublic, ReceivedAt: time.Now().UTC()}}
	node.keysMu.Unlock()
	if _, err := node.buildPeerEvidence(provider.ID(), observation, time.Now().UTC()); err == nil {
		t.Fatalf("untrusted signing key must fail closed")
	}
}

func mustDecodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return decoded
}
