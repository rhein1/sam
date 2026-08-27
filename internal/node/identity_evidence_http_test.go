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
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
)

func TestIdentityEvidenceRoutesHaveOwnMetricClass(t *testing.T) {
	for _, path := range []string{
		"/sam/identity",
		"/sam/identity/",
		"/sam/identity/extra",
		"/sam/peer/12D3KooWpeer/evidence",
	} {
		if got := classifyRoute(path); got != "identity-evidence" {
			t.Errorf("classifyRoute(%q) = %q, want %q", path, got, "identity-evidence")
		}
	}
}

func TestIdentityEvidenceTrailingSlashReturnsNotFound(t *testing.T) {
	node := &SamNode{
		BiscuitTimeout: 500 * time.Millisecond,
		services:       NewServiceRegistry(&fakeDHT{}),
	}
	socketPath := filepath.Join(t.TempDir(), "sam.sock")

	srv, err := StartSidecarServer(node, "", socketPath, "", "", "", "")
	if err != nil {
		t.Fatalf("start socket-only sidecar: %v", err)
	}
	defer func() { _ = srv.Close() }()

	client := waitForSocket(t, socketPath)
	resp, err := client.Get("http://localhost/sam/identity/")
	if err != nil {
		t.Fatalf("GET /sam/identity/: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, body = %q, want %d", resp.StatusCode, body, http.StatusNotFound)
	}
	if got := strings.TrimSpace(string(body)); got != "Not found" {
		t.Fatalf("body = %q, want %q", got, "Not found")
	}
}

func TestHandlePeerEvidenceErrorContract(t *testing.T) {
	node, _, _ := newIdentityEvidenceTestNode(t, nil)
	provider, err := libp2p.New()
	if err != nil {
		t.Fatalf("create provider host: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	validPath := "/sam/peer/" + provider.ID().String() + "/evidence"
	tests := []struct {
		name       string
		method     string
		path       string
		setup      func()
		cleanup    func()
		wantStatus int
		wantBody   string
		wantAllow  string
	}{
		{
			name:       "bad peer ID",
			method:     http.MethodGet,
			path:       "/sam/peer/not-a-peer/evidence",
			wantStatus: http.StatusBadRequest,
			wantBody:   "Invalid peer ID",
		},
		{
			name:   "pre-fetch revoked",
			method: http.MethodGet,
			path:   validPath,
			setup: func() {
				node.revokedPeers.Add(provider.ID().String(), time.Now().Unix())
			},
			cleanup: func() {
				node.revokedPeers.Remove(provider.ID().String())
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "Peer is revoked",
		},
		{
			name:       "non-GET",
			method:     http.MethodPost,
			path:       validPath,
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
			wantAllow:  http.MethodGet,
		},
		{
			name:       "wrong path shape",
			method:     http.MethodGet,
			path:       "/sam/peer/" + provider.ID().String(),
			wantStatus: http.StatusNotFound,
			wantBody:   "Not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			if tc.cleanup != nil {
				defer tc.cleanup()
			}

			recorder := httptest.NewRecorder()
			handlePeerEvidence(node, recorder, httptest.NewRequest(tc.method, tc.path, nil))

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, body = %q, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
			if got := strings.TrimSpace(recorder.Body.String()); got != tc.wantBody {
				t.Fatalf("body = %q, want %q", got, tc.wantBody)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
			}
			if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
				t.Fatalf("Content-Type = %q, want text/plain", got)
			}
			if got := recorder.Header().Get("Allow"); got != tc.wantAllow {
				t.Fatalf("Allow = %q, want %q", got, tc.wantAllow)
			}
		})
	}
}
