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

package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
)

type operatorIdentityEvidence struct {
	Schema                  string `json:"schema"`
	PeerID                  string `json:"peer_id"`
	BiscuitPeerID           string `json:"biscuit_peer_id"`
	PeerBindingVerified     bool   `json:"peer_binding_verified"`
	ControlPlaneURL         string `json:"control_plane_url"`
	TrustedControlPlaneKeys []struct {
		Fingerprint   string `json:"fingerprint"`
		SPKIDERBase64 string `json:"spki_der_base64"`
		ReceivedAt    string `json:"received_at"`
	} `json:"trusted_control_plane_keys"`
	SelectedVerifyingKeyFingerprint string `json:"selected_verifying_key_fingerprint"`
	Enrolled                        bool   `json:"enrolled"`
	Biscuit                         string `json:"biscuit"`
	BiscuitExpiresAt                string `json:"biscuit_expires_at"`
	CheckedAt                       string `json:"checked_at"`
}

type operatorPeerEvidence struct {
	Schema                    string `json:"schema"`
	RequestedPeerID           string `json:"requested_peer_id"`
	ConnectionPeerID          string `json:"connection_peer_id"`
	BiscuitPeerID             string `json:"biscuit_peer_id"`
	PeerBindingVerified       bool   `json:"peer_binding_verified"`
	Verified                  bool   `json:"verified"`
	Biscuit                   string `json:"biscuit"`
	VerifyingKeyFingerprint   string `json:"verifying_key_fingerprint"`
	VerifyingKeySPKIDERBase64 string `json:"verifying_key_spki_der_base64"`
	VerifyingKeyReceivedAt    string `json:"verifying_key_received_at"`
	Attested                  struct {
		Role   []string          `json:"role"`
		Labels map[string]string `json:"labels"`
	} `json:"attested"`
	Expiration string `json:"expiration"`
	Revocation struct {
		PeerRevoked   bool     `json:"peer_revoked"`
		RevocationIDs []string `json:"revocation_ids"`
		CheckedAt     string   `json:"checked_at"`
		Source        string   `json:"source"`
	} `json:"revocation"`
	Freshness struct {
		FetchedAt      string  `json:"fetched_at"`
		CheckedAt      string  `json:"checked_at"`
		CacheHit       bool    `json:"cache_hit"`
		CacheExpiresAt *string `json:"cache_expires_at"`
	} `json:"freshness"`
}

// TestIdentityEvidenceOperatorFlow exercises the same owner-side sequence as
// an external receipt verifier: trust the local Unix socket, identify this
// node, connect to an exact peer, and collect fresh independently verifiable
// peer evidence before any provider request.
func TestIdentityEvidenceOperatorFlow(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, controlPlaneURL := startMockRouter(t)

	ownerHome := t.TempDir()
	providerHome := t.TempDir()
	socketDir, err := os.MkdirTemp("", "sam-evidence-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	ownerSocket := filepath.Join(socketDir, "owner.sock")

	_ = startBackgroundNode(t, nodeBin, controlPlaneURL, ownerHome,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--socket-path", ownerSocket,
	)
	_ = startBackgroundNode(t, nodeBin, controlPlaneURL, providerHome,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
	)

	ownerAPI := waitForMCPAddr(t, filepath.Join(ownerHome, "node.log"))
	providerAPI := waitForMCPAddr(t, filepath.Join(providerHome, "node.log"))
	waitForAPI(t, ownerAPI)
	waitForAPI(t, providerAPI)

	providerAddr := waitForPeerInfoInLog(t, filepath.Join(providerHome, "node.log"))
	providerPeerID := getPeerIDFromAddr(providerAddr)
	if providerPeerID == "" {
		t.Fatalf("provider address %q has no PeerID", providerAddr)
	}
	callMCP(t, ownerAPI, "connect_peer", map[string]any{"peer_addr": providerAddr})

	client := identityEvidenceSocketClient(ownerSocket)
	waitForIdentityEvidenceSocket(t, client)

	var local operatorIdentityEvidence
	getIdentityEvidenceJSON(t, client, "/sam/identity", &local)
	if local.Schema != "sam.identity.v1" || !local.Enrolled || !local.PeerBindingVerified {
		t.Fatalf("local identity evidence is not verified: schema=%q peer=%q enrolled=%t binding=%t keys=%d", local.Schema, local.PeerID, local.Enrolled, local.PeerBindingVerified, len(local.TrustedControlPlaneKeys))
	}
	if local.PeerID == "" || local.PeerID != local.BiscuitPeerID {
		t.Fatalf("local PeerID binding mismatch: peer=%q biscuit=%q", local.PeerID, local.BiscuitPeerID)
	}
	if local.ControlPlaneURL != controlPlaneURL {
		t.Fatalf("control plane URL = %q, want %q", local.ControlPlaneURL, controlPlaneURL)
	}
	if len(mustDecodeEvidenceBase64(t, local.Biscuit, "local biscuit")) == 0 {
		t.Fatal("local identity returned an empty biscuit")
	}
	assertEvidenceTimeOrder(t, local.CheckedAt, local.BiscuitExpiresAt, "local identity")

	selectedSPKI := selectedEvidenceSPKI(t, local)
	if got := evidenceFingerprint(selectedSPKI); got != local.SelectedVerifyingKeyFingerprint {
		t.Fatalf("local selected-key fingerprint = %q, recomputed %q", local.SelectedVerifyingKeyFingerprint, got)
	}

	var remote operatorPeerEvidence
	getIdentityEvidenceJSON(t, client, "/sam/peer/"+url.PathEscape(providerPeerID.String())+"/evidence", &remote)
	if remote.Schema != "sam.peer-evidence.v1" || !remote.Verified || !remote.PeerBindingVerified {
		t.Fatalf("remote peer evidence is not verified: schema=%q requested=%q connection=%q biscuit_peer=%q verified=%t binding=%t", remote.Schema, remote.RequestedPeerID, remote.ConnectionPeerID, remote.BiscuitPeerID, remote.Verified, remote.PeerBindingVerified)
	}
	for field, got := range map[string]string{
		"requested":  remote.RequestedPeerID,
		"connection": remote.ConnectionPeerID,
		"biscuit":    remote.BiscuitPeerID,
	} {
		if got != providerPeerID.String() {
			t.Fatalf("remote %s PeerID = %q, want %q", field, got, providerPeerID)
		}
	}
	if len(mustDecodeEvidenceBase64(t, remote.Biscuit, "remote biscuit")) == 0 {
		t.Fatal("remote evidence returned an empty biscuit")
	}
	remoteSPKI := mustDecodeEvidenceBase64(t, remote.VerifyingKeySPKIDERBase64, "remote verifying key")
	if got := evidenceFingerprint(remoteSPKI); got != remote.VerifyingKeyFingerprint {
		t.Fatalf("remote selected-key fingerprint = %q, recomputed %q", remote.VerifyingKeyFingerprint, got)
	}
	if remote.VerifyingKeyFingerprint != local.SelectedVerifyingKeyFingerprint || !bytes.Equal(remoteSPKI, selectedSPKI) {
		t.Fatal("remote evidence was not verified by the local node's selected trusted control-plane key")
	}
	if !containsEvidenceRole(remote.Attested.Role, api.RoleNode) {
		t.Fatalf("remote attested roles %v do not include %q", remote.Attested.Role, api.RoleNode)
	}
	if remote.Revocation.PeerRevoked || remote.Revocation.Source != "local_event_cache_and_store" || len(remote.Revocation.RevocationIDs) == 0 {
		t.Fatalf("unexpected revocation evidence: %+v", remote.Revocation)
	}
	if remote.Freshness.CacheHit || remote.Freshness.CacheExpiresAt != nil {
		t.Fatalf("peer evidence was not fetched fresh: %+v", remote.Freshness)
	}
	assertEvidenceTimeOrder(t, remote.Freshness.FetchedAt, remote.Freshness.CheckedAt, "remote fetch")
	assertEvidenceTimeOrder(t, remote.Freshness.CheckedAt, remote.Expiration, "remote evidence")
}

func identityEvidenceSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
}

func waitForIdentityEvidenceSocket(t *testing.T, client *http.Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://localhost/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timeout waiting for owner Unix socket")
}

func getIdentityEvidenceJSON(t *testing.T, client *http.Client, path string, target any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		t.Fatalf("build evidence request: %v", err)
	}
	resp, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s over owner socket: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		t.Fatalf("GET %s status = %d, body = %q", path, resp.StatusCode, body)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET %s returned unsafe response headers: %v", path, resp.Header)
	}
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode closed response from %s: %v", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("GET %s returned trailing JSON: %v", path, err)
	}
}

func selectedEvidenceSPKI(t *testing.T, evidence operatorIdentityEvidence) []byte {
	t.Helper()
	for _, key := range evidence.TrustedControlPlaneKeys {
		if key.Fingerprint == evidence.SelectedVerifyingKeyFingerprint {
			if _, err := time.Parse(time.RFC3339Nano, key.ReceivedAt); err != nil {
				t.Fatalf("parse trusted-key received_at: %v", err)
			}
			return mustDecodeEvidenceBase64(t, key.SPKIDERBase64, "trusted control-plane key")
		}
	}
	t.Fatalf("selected key %q is absent from trusted key set", evidence.SelectedVerifyingKeyFingerprint)
	return nil
}

func mustDecodeEvidenceBase64(t *testing.T, value, field string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return decoded
}

func evidenceFingerprint(der []byte) string {
	digest := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func assertEvidenceTimeOrder(t *testing.T, earlier, later, field string) {
	t.Helper()
	earlierAt, err := time.Parse(time.RFC3339Nano, earlier)
	if err != nil {
		t.Fatalf("parse %s earlier timestamp %q: %v", field, earlier, err)
	}
	laterAt, err := time.Parse(time.RFC3339Nano, later)
	if err != nil {
		t.Fatalf("parse %s later timestamp %q: %v", field, later, err)
	}
	if earlierAt.After(laterAt) {
		t.Fatalf("%s timestamps out of order: %s after %s", field, earlier, later)
	}
}

func containsEvidenceRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}
