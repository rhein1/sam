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
	"context"
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
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

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

	var local api.IdentityEvidenceResponse
	getIdentityEvidenceJSON(t, client, "/sam/identity", &local)
	if local.PeerId == "" || len(local.Biscuit) == 0 || len(local.TrustedControlPlaneKeys) == 0 {
		t.Fatalf("local identity evidence is incomplete: peer=%q biscuit=%d keys=%d", local.PeerId, len(local.Biscuit), len(local.TrustedControlPlaneKeys))
	}
	if local.ControlPlaneUrl != controlPlaneURL {
		t.Fatalf("control plane URL = %q, want %q", local.ControlPlaneUrl, controlPlaneURL)
	}

	var remote api.PeerEvidenceResponse
	getIdentityEvidenceJSON(t, client, "/sam/peer/"+url.PathEscape(providerPeerID.String())+"/evidence", &remote)
	if remote.PeerId != providerPeerID.String() || len(remote.Biscuit) == 0 || len(remote.VerifyingKey) == 0 {
		t.Fatalf("remote handshake evidence is incomplete: peer=%q biscuit=%d key=%d", remote.PeerId, len(remote.Biscuit), len(remote.VerifyingKey))
	}
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

func getIdentityEvidenceJSON(t *testing.T, client *http.Client, path string, target proto.Message) {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read response from %s: %v", path, err)
	}
	if err := protojson.Unmarshal(body, target); err != nil {
		t.Fatalf("decode closed response from %s: %v", path, err)
	}
}
