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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	identityEvidenceSchema = "sam.identity.v1"
	peerEvidenceSchema     = "sam.peer-evidence.v1"
	evidenceErrorSchema    = "sam.evidence-error.v1"
)

type controlPlaneKeyEvidence struct {
	Fingerprint   string `json:"fingerprint"`
	SPKIDERBase64 string `json:"spki_der_base64"`
	ReceivedAt    string `json:"received_at"`
}

type identityEvidenceResponse struct {
	Schema                          string                    `json:"schema"`
	PeerID                          string                    `json:"peer_id"`
	BiscuitPeerID                   string                    `json:"biscuit_peer_id"`
	PeerBindingVerified             bool                      `json:"peer_binding_verified"`
	ControlPlaneURL                 string                    `json:"control_plane_url"`
	TrustedControlPlaneKeys         []controlPlaneKeyEvidence `json:"trusted_control_plane_keys"`
	SelectedVerifyingKeyFingerprint string                    `json:"selected_verifying_key_fingerprint"`
	Enrolled                        bool                      `json:"enrolled"`
	Biscuit                         string                    `json:"biscuit"`
	BiscuitExpiresAt                string                    `json:"biscuit_expires_at"`
	CheckedAt                       string                    `json:"checked_at"`
}

type peerAttestationEvidence struct {
	Role   []string          `json:"role"`
	Labels map[string]string `json:"labels"`
}

type peerRevocationEvidence struct {
	PeerRevoked   bool     `json:"peer_revoked"`
	RevocationIDs []string `json:"revocation_ids"`
	CheckedAt     string   `json:"checked_at"`
	Source        string   `json:"source"`
}

type peerFreshnessEvidence struct {
	FetchedAt      string  `json:"fetched_at"`
	CheckedAt      string  `json:"checked_at"`
	CacheHit       bool    `json:"cache_hit"`
	CacheExpiresAt *string `json:"cache_expires_at"`
}

type peerEvidenceResponse struct {
	Schema                    string                  `json:"schema"`
	RequestedPeerID           string                  `json:"requested_peer_id"`
	ConnectionPeerID          string                  `json:"connection_peer_id"`
	BiscuitPeerID             string                  `json:"biscuit_peer_id"`
	PeerBindingVerified       bool                    `json:"peer_binding_verified"`
	Verified                  bool                    `json:"verified"`
	Biscuit                   string                  `json:"biscuit"`
	VerifyingKeyFingerprint   string                  `json:"verifying_key_fingerprint"`
	VerifyingKeySPKIDERBase64 string                  `json:"verifying_key_spki_der_base64"`
	VerifyingKeyReceivedAt    string                  `json:"verifying_key_received_at"`
	Attested                  peerAttestationEvidence `json:"attested"`
	Expiration                string                  `json:"expiration"`
	Revocation                peerRevocationEvidence  `json:"revocation"`
	Freshness                 peerFreshnessEvidence   `json:"freshness"`
}

type evidenceErrorResponse struct {
	Schema string `json:"schema"`
	Code   string `json:"code"`
}

type trustedKeySnapshot struct {
	Key        ed25519.PublicKey
	ReceivedAt time.Time
	Evidence   controlPlaneKeyEvidence
}

func sha256Fingerprint(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func snapshotControlPlaneKey(key ed25519.PublicKey, receivedAt time.Time) (trustedKeySnapshot, error) {
	if len(key) != ed25519.PublicKeySize {
		return trustedKeySnapshot{}, fmt.Errorf("invalid Ed25519 key size %d", len(key))
	}
	keyCopy := append(ed25519.PublicKey(nil), key...)
	der, err := x509.MarshalPKIXPublicKey(keyCopy)
	if err != nil {
		return trustedKeySnapshot{}, fmt.Errorf("marshal Ed25519 SPKI: %w", err)
	}
	return trustedKeySnapshot{
		Key:        keyCopy,
		ReceivedAt: receivedAt,
		Evidence: controlPlaneKeyEvidence{
			Fingerprint:   sha256Fingerprint(der),
			SPKIDERBase64: base64.StdEncoding.EncodeToString(der),
			ReceivedAt:    receivedAt.UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (n *SamNode) trustedKeySnapshot() ([]trustedKeySnapshot, error) {
	n.keysMu.RLock()
	trusted := append([]TrustedKey(nil), n.trustedKeys...)
	n.keysMu.RUnlock()

	snapshots := make([]trustedKeySnapshot, 0, len(trusted))
	for _, candidate := range trusted {
		snapshot, err := snapshotControlPlaneKey(candidate.Key, candidate.ReceivedAt)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Evidence.Fingerprint < snapshots[j].Evidence.Fingerprint
	})
	return snapshots, nil
}

func keysFromSnapshot(snapshots []trustedKeySnapshot) []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(snapshots))
	for _, snapshot := range snapshots {
		keys = append(keys, snapshot.Key)
	}
	return keys
}

func findSelectedKey(snapshots []trustedKeySnapshot, selected ed25519.PublicKey) (trustedKeySnapshot, bool) {
	for _, snapshot := range snapshots {
		if snapshot.Key.Equal(selected) {
			return snapshot, true
		}
	}
	return trustedKeySnapshot{}, false
}

func (n *SamNode) stillTrustsKey(selected trustedKeySnapshot) bool {
	current, err := n.trustedKeySnapshot()
	if err != nil {
		return false
	}
	for _, candidate := range current {
		if candidate.Evidence.Fingerprint == selected.Evidence.Fingerprint && candidate.Key.Equal(selected.Key) {
			return true
		}
	}
	return false
}

func requireIdentityEvidenceTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fromLocalSocket(r) && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
			writeEvidenceError(w, http.StatusForbidden, "sam_evidence_strong_transport_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeEvidenceJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		logger.Errorf("[IdentityEvidence] Failed to encode response: %v", err)
	}
}

func writeEvidenceError(w http.ResponseWriter, status int, code string) {
	writeEvidenceJSON(w, status, evidenceErrorResponse{Schema: evidenceErrorSchema, Code: code})
}

func handleIdentityEvidence(n *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeEvidenceError(w, http.StatusMethodNotAllowed, "sam_evidence_method_not_allowed")
		return
	}
	response, err := n.buildIdentityEvidence(time.Now().UTC())
	if err != nil {
		logger.Warnf("[IdentityEvidence] Local identity unavailable: %v", err)
		writeEvidenceError(w, http.StatusServiceUnavailable, "sam_identity_evidence_unavailable")
		return
	}
	writeEvidenceJSON(w, http.StatusOK, response)
}

func handlePeerEvidence(n *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeEvidenceError(w, http.StatusMethodNotAllowed, "sam_evidence_method_not_allowed")
		return
	}
	const prefix = "/sam/peer/"
	remainder := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(remainder, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "evidence" {
		writeEvidenceError(w, http.StatusNotFound, "sam_peer_evidence_not_found")
		return
	}
	requestedPeer, err := peer.Decode(parts[0])
	if err != nil || requestedPeer.String() != parts[0] {
		writeEvidenceError(w, http.StatusBadRequest, "sam_peer_id_invalid")
		return
	}
	if n.peerIsRevoked(requestedPeer) {
		writeEvidenceError(w, http.StatusForbidden, "sam_peer_revoked")
		return
	}

	observation, err := n.fetchPeerBiscuitEvidence(r.Context(), requestedPeer)
	if err != nil {
		logger.Warnf("[IdentityEvidence] Peer evidence fetch failed for %s: %v", requestedPeer, err)
		writeEvidenceError(w, http.StatusBadGateway, "sam_peer_evidence_fetch_failed")
		return
	}
	response, err := n.buildPeerEvidence(requestedPeer, observation, time.Now().UTC())
	if err != nil {
		logger.Warnf("[IdentityEvidence] Peer evidence verification failed for %s: %v", requestedPeer, err)
		writeEvidenceError(w, http.StatusUnprocessableEntity, "sam_peer_evidence_unverifiable")
		return
	}
	writeEvidenceJSON(w, http.StatusOK, response)
}

func (n *SamNode) buildIdentityEvidence(checkedAt time.Time) (identityEvidenceResponse, error) {
	if n == nil || n.Host == nil || n.Store == nil {
		return identityEvidenceResponse{}, fmt.Errorf("node identity store is unavailable")
	}
	biscuitBytes := n.GetIdentity()
	if len(biscuitBytes) == 0 {
		return identityEvidenceResponse{}, fmt.Errorf("node is not enrolled")
	}
	snapshots, err := n.trustedKeySnapshot()
	if err != nil || len(snapshots) == 0 {
		return identityEvidenceResponse{}, fmt.Errorf("trusted control-plane keys unavailable: %w", err)
	}
	b, selectedKey, err := identity.VerifyBiscuitAndGetKey(biscuitBytes, n.Host.ID(), keysFromSnapshot(snapshots), n.BiscuitTimeout)
	if err != nil {
		return identityEvidenceResponse{}, err
	}
	selected, ok := findSelectedKey(snapshots, selectedKey)
	if !ok || !n.stillTrustsKey(selected) {
		return identityEvidenceResponse{}, fmt.Errorf("selected verification key is no longer trusted")
	}
	claims, err := extractBiscuitClaims(b, selectedKey, n.BiscuitTimeout, checkedAt)
	if err != nil {
		return identityEvidenceResponse{}, err
	}
	if claims.PeerID != n.Host.ID().String() {
		return identityEvidenceResponse{}, fmt.Errorf("biscuit peer binding mismatch")
	}
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil {
		return identityEvidenceResponse{}, fmt.Errorf("control-plane URL unavailable: %w", err)
	}
	keyEvidence := make([]controlPlaneKeyEvidence, 0, len(snapshots))
	for _, snapshot := range snapshots {
		keyEvidence = append(keyEvidence, snapshot.Evidence)
	}
	return identityEvidenceResponse{
		Schema:                          identityEvidenceSchema,
		PeerID:                          n.Host.ID().String(),
		BiscuitPeerID:                   claims.PeerID,
		PeerBindingVerified:             true,
		ControlPlaneURL:                 controlPlaneURL,
		TrustedControlPlaneKeys:         keyEvidence,
		SelectedVerifyingKeyFingerprint: selected.Evidence.Fingerprint,
		Enrolled:                        true,
		Biscuit:                         base64.StdEncoding.EncodeToString(biscuitBytes),
		BiscuitExpiresAt:                claims.Expiration.Format(time.RFC3339Nano),
		CheckedAt:                       checkedAt.Format(time.RFC3339Nano),
	}, nil
}

func (n *SamNode) buildPeerEvidence(requested peer.ID, observation peerBiscuitObservation, checkedAt time.Time) (peerEvidenceResponse, error) {
	if requested == "" || observation.ConnectionPeer == "" || requested != observation.ConnectionPeer {
		return peerEvidenceResponse{}, fmt.Errorf("requested and connection PeerIDs differ")
	}
	if n.peerIsRevoked(requested) {
		return peerEvidenceResponse{}, fmt.Errorf("peer is revoked")
	}
	snapshots, err := n.trustedKeySnapshot()
	if err != nil || len(snapshots) == 0 {
		return peerEvidenceResponse{}, fmt.Errorf("trusted control-plane keys unavailable: %w", err)
	}
	b, selectedKey, err := identity.VerifyBiscuitAndGetKey(observation.Biscuit, observation.ConnectionPeer, keysFromSnapshot(snapshots), n.BiscuitTimeout)
	if err != nil {
		return peerEvidenceResponse{}, err
	}
	selected, ok := findSelectedKey(snapshots, selectedKey)
	if !ok {
		return peerEvidenceResponse{}, fmt.Errorf("selected verification key is not in the trusted snapshot")
	}
	claims, err := extractBiscuitClaims(b, selectedKey, n.BiscuitTimeout, checkedAt)
	if err != nil {
		return peerEvidenceResponse{}, err
	}
	if claims.PeerID != requested.String() || n.peerIsRevoked(requested) || !n.stillTrustsKey(selected) {
		return peerEvidenceResponse{}, fmt.Errorf("peer binding, revocation, or trust state changed during verification")
	}

	revocationIDs := make([]string, 0, len(b.RevocationIds()))
	for _, id := range b.RevocationIds() {
		revocationIDs = append(revocationIDs, hex.EncodeToString(id))
	}
	return peerEvidenceResponse{
		Schema:                    peerEvidenceSchema,
		RequestedPeerID:           requested.String(),
		ConnectionPeerID:          observation.ConnectionPeer.String(),
		BiscuitPeerID:             claims.PeerID,
		PeerBindingVerified:       true,
		Verified:                  true,
		Biscuit:                   base64.StdEncoding.EncodeToString(observation.Biscuit),
		VerifyingKeyFingerprint:   selected.Evidence.Fingerprint,
		VerifyingKeySPKIDERBase64: selected.Evidence.SPKIDERBase64,
		VerifyingKeyReceivedAt:    selected.Evidence.ReceivedAt,
		Attested: peerAttestationEvidence{
			Role:   claims.Roles,
			Labels: claims.Labels,
		},
		Expiration: claims.Expiration.Format(time.RFC3339Nano),
		Revocation: peerRevocationEvidence{
			PeerRevoked:   false,
			RevocationIDs: revocationIDs,
			CheckedAt:     checkedAt.Format(time.RFC3339Nano),
			Source:        "local_event_cache_and_store",
		},
		Freshness: peerFreshnessEvidence{
			FetchedAt:      observation.FetchedAt.UTC().Format(time.RFC3339Nano),
			CheckedAt:      checkedAt.Format(time.RFC3339Nano),
			CacheHit:       false,
			CacheExpiresAt: nil,
		},
	}, nil
}

func (n *SamNode) peerIsRevoked(peerID peer.ID) bool {
	if n.revokedPeers != nil && n.revokedPeers.Contains(peerID.String()) {
		return true
	}
	return n.Store != nil && n.Store.IsBanned(peerID)
}

type biscuitClaims struct {
	PeerID     string
	Roles      []string
	Labels     map[string]string
	Expiration time.Time
}

func extractBiscuitClaims(b *biscuit.Biscuit, key ed25519.PublicKey, timeout time.Duration, checkedAt time.Time) (biscuitClaims, error) {
	authorizer, err := b.Authorizer(key, identity.AuthorizerOptions(timeout)...)
	if err != nil {
		return biscuitClaims{}, err
	}
	authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTime,
		IDs:  []biscuit.Term{biscuit.Date(checkedAt)},
	}})
	authorizer.AddCheck(api.ControlPlaneStaticTimeCheck)
	authorizer.AddPolicy(api.AllowIfTruePolicy)
	if err := authorizer.Authorize(); err != nil {
		return biscuitClaims{}, err
	}

	peerIDs, err := queryStringFacts(authorizer, api.FactNode)
	if err != nil || len(peerIDs) != 1 {
		return biscuitClaims{}, fmt.Errorf("expected exactly one node fact")
	}
	roles, err := queryStringFacts(authorizer, api.FactRole)
	if err != nil {
		return biscuitClaims{}, err
	}
	labels, err := queryLabelFacts(authorizer)
	if err != nil {
		return biscuitClaims{}, err
	}
	expiration, err := queryExpiration(authorizer)
	if err != nil {
		return biscuitClaims{}, err
	}
	sort.Strings(roles)
	return biscuitClaims{PeerID: peerIDs[0], Roles: roles, Labels: labels, Expiration: expiration.UTC()}, nil
}

func queryStringFacts(authorizer biscuit.Authorizer, factName string) ([]string, error) {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: factName, IDs: []biscuit.Term{biscuit.Variable("v")}}},
	})
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(facts))
	for _, fact := range facts {
		if len(fact.IDs) != 1 {
			return nil, fmt.Errorf("unexpected %s fact shape", factName)
		}
		value, ok := fact.IDs[0].(biscuit.String)
		if !ok {
			return nil, fmt.Errorf("unexpected %s fact type", factName)
		}
		values = append(values, string(value))
	}
	return values, nil
}

func queryLabelFacts(authorizer biscuit.Authorizer) (map[string]string, error) {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("k"), biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: api.FactLabel, IDs: []biscuit.Term{biscuit.Variable("k"), biscuit.Variable("v")}}},
	})
	if err != nil {
		return nil, err
	}
	labels := make(map[string]string, len(facts))
	for _, fact := range facts {
		if len(fact.IDs) != 2 {
			return nil, fmt.Errorf("unexpected label fact shape")
		}
		key, keyOK := fact.IDs[0].(biscuit.String)
		value, valueOK := fact.IDs[1].(biscuit.String)
		if !keyOK || !valueOK {
			return nil, fmt.Errorf("unexpected label fact type")
		}
		if previous, exists := labels[string(key)]; exists && previous != string(value) {
			return nil, fmt.Errorf("conflicting attested label %q", key)
		}
		labels[string(key)] = string(value)
	}
	return labels, nil
}

func queryExpiration(authorizer biscuit.Authorizer) (time.Time, error) {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Variable("v")}}},
	})
	if err != nil || len(facts) != 1 || len(facts[0].IDs) != 1 {
		return time.Time{}, fmt.Errorf("expected exactly one expiration fact")
	}
	expiration, ok := facts[0].IDs[0].(biscuit.Date)
	if !ok {
		return time.Time{}, fmt.Errorf("unexpected expiration fact type")
	}
	return time.Time(expiration), nil
}
