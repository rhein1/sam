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

package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

// DefaultAuthorizerTimeout bounds Datalog evaluation when no timeout is configured.
// biscuit-go defaults to 2ms of wall-clock time, of which a single authorization of
// a realistic token already spends ~0.14ms (~1.1ms under -race), so ordinary
// scheduling noise turns into a spurious denial. The amount of work is bounded by
// the fact and iteration limits; this deadline only caps how long the caller waits.
const DefaultAuthorizerTimeout = 1 * time.Second

// AuthorizerOptions returns the authorizer options enforcing a Datalog evaluation
// budget. A non-positive timeout falls back to DefaultAuthorizerTimeout.
func AuthorizerOptions(timeout time.Duration) []biscuit.AuthorizerOption {
	if timeout <= 0 {
		timeout = DefaultAuthorizerTimeout
	}
	return []biscuit.AuthorizerOption{biscuit.WithWorldOptions(datalog.WithMaxDuration(timeout))}
}

// MintBiscuitToken generates a signed Biscuit token for a peer with policy rules based on JWT claims.
// labels are control-plane-attested key=value claims (canonical, pre-validated); empty means no claims.
func MintBiscuitToken(signingKey ed25519.PrivateKey, claims jwt.MapClaims, token *oidc.IDToken, remotePeer peer.ID, biscuitExpiry time.Time, roles []string, policyRoles []*api.PolicyRole, labels map[string]string) ([]byte, []string, error) {
	if claims == nil {
		return nil, nil, fmt.Errorf("claims cannot be nil")
	}

	biscuitBytes, err := mintBiscuit(signingKey, remotePeer, roles, biscuitExpiry, claims, policyRoles, labels)
	if err != nil {
		return nil, nil, err
	}
	return biscuitBytes, roles, nil
}

func mintBiscuit(signingKey ed25519.PrivateKey, remotePeer peer.ID, roles []string, expiration time.Time, claims jwt.MapClaims, policyRoles []*api.PolicyRole, labels map[string]string) ([]byte, error) {
	builder := biscuit.NewBuilder(signingKey)
	addedFacts := make(map[string]bool)
	addFact := func(fact biscuit.Fact) error {
		factStr := fact.String()
		if addedFacts[factStr] {
			return nil
		}
		if err := builder.AddAuthorityFact(fact); err != nil {
			return err
		}
		addedFacts[factStr] = true
		return nil
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(expiration)},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add expiration fact: %w", err)
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add node fact: %w", err)
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactClientPeerID,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add client_peer_id fact: %w", err)
	}

	// One signed fact per declared label so a requirement is a single exact
	// match (see api.FactLabel).
	for _, fact := range api.LabelFacts(labels) {
		if err := addFact(fact); err != nil {
			return nil, fmt.Errorf("failed to add label fact: %w", err)
		}
	}

	if claims != nil {
		if err := translateClaimsToFacts(addFact, claims); err != nil {
			return nil, err
		}
	}

	rolesMap := make(map[string]*api.PolicyRole)
	for _, pr := range policyRoles {
		if pr != nil {
			rolesMap[pr.Name] = pr
		}
	}

	hasTargets := false
	hasServices := false
	sort.Strings(roles)
	var errs []error
	// Collected across every matched role and merged into Set facts once below: a token's
	// authorization is the union of its resolved roles' grants, so exact entries don't need to
	// stay siloed per role, and merging keeps fact counts flat regardless of how many roles match.
	var allServices []string
	var allTargets []string
	for _, role := range roles {
		if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactRole,
			IDs:  []biscuit.Term{biscuit.String(role)},
		}}); err != nil {
			errs = append(errs, fmt.Errorf("failed to add role fact for %s: %w", role, err))
			continue
		}

		if role == api.RoleRouter {
			if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactRight,
				IDs:  []biscuit.Term{biscuit.String(api.RightRelay)},
			}}); err != nil {
				errs = append(errs, fmt.Errorf("failed to add relay right: %w", err))
			}
			if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactTargetUnrestricted,
				IDs:  []biscuit.Term{},
			}}); err != nil {
				errs = append(errs, fmt.Errorf("failed to add target unrestricted: %w", err))
			}
			hasTargets = true
			hasServices = true
			continue
		}

		if pr, ok := rolesMap[role]; ok {
			if len(pr.AllowedServices) > 0 {
				hasServices = true
				allServices = append(allServices, pr.AllowedServices...)
			}

			if len(pr.AllowedTargets) > 0 {
				hasTargets = true
				allTargets = append(allTargets, pr.AllowedTargets...)
			}

			for _, customFact := range pr.CustomDatalog {
				trimmed := strings.TrimRight(strings.TrimSpace(customFact), ";")
				if trimmed == "" {
					continue
				}
				fact, err := parser.FromStringFact(trimmed)
				if err != nil {
					errs = append(errs, fmt.Errorf("failed to parse custom Datalog fact %q for role %s: %w", customFact, role, err))
				} else if err := addFact(fact); err != nil {
					errs = append(errs, fmt.Errorf("failed to add custom Datalog fact %q for role %s: %w", customFact, role, err))
				}
			}
		}
	}

	for _, fact := range api.BuildServiceDatalogFacts(allServices) {
		if err := addFact(fact); err != nil {
			errs = append(errs, fmt.Errorf("failed to add service fact: %w", err))
		}
	}
	for _, fact := range api.BuildTargetDatalogFacts(allTargets) {
		if err := addFact(fact); err != nil {
			errs = append(errs, fmt.Errorf("failed to add target fact: %w", err))
		}
	}

	if !hasServices && len(policyRoles) == 0 {
		if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactGrantedServiceAllTypes,
			IDs:  []biscuit.Term{},
		}}); err != nil {
			errs = append(errs, fmt.Errorf("failed to add fallback service fact: %w", err))
		}
	}
	if !hasTargets && len(policyRoles) == 0 {
		if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactTargetUnrestricted,
			IDs:  []biscuit.Term{},
		}}); err != nil {
			errs = append(errs, fmt.Errorf("failed to add fallback target fact: %w", err))
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("biscuit policy validation failed: %w", errors.Join(errs...))
	}

	t, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build biscuit: %w", err)
	}

	bBytes, err := t.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize biscuit: %w", err)
	}

	return bBytes, nil
}

// VerifyBiscuit verifies the validity of a Biscuit token.
// It ensures that:
// 1. The token is cryptographically signed by one of the trustedPublicKeys.
// 2. The token is not expired.
// 3. The token is securely bound to the expected remotePeer.
func VerifyBiscuit(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (*biscuit.Biscuit, error) {
	b, _, err := VerifyBiscuitAndGetKey(biscuitData, expectedPeer, trustedPublicKeys, timeout)
	return b, err
}

func VerifyBiscuitAndGetKey(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (*biscuit.Biscuit, ed25519.PublicKey, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return nil, nil, fmt.Errorf("malformed biscuit: %w", err)
	}

	authOpts := AuthorizerOptions(timeout)

	var lastErr error
	var authorized bool
	var verifyingKey ed25519.PublicKey
	for _, pubKey := range trustedPublicKeys {
		authorizer, err := b.Authorizer(pubKey, authOpts...)
		if err != nil {
			lastErr = err
			continue
		}

		authorizer.AddFact(biscuit.Fact{
			Predicate: biscuit.Predicate{
				Name: api.FactTime,
				IDs:  []biscuit.Term{biscuit.Date(time.Now())},
			},
		})

		authorizer.AddCheck(api.ControlPlaneStaticTimeCheck)
		authorizer.AddPolicy(api.AllowIfTruePolicy)

		if err := authorizer.Authorize(); err == nil {
			authorized = true
			verifyingKey = pubKey
			break
		} else {
			lastErr = err
		}
	}

	if !authorized {
		return nil, nil, fmt.Errorf("no valid key found for verification: %v", lastErr)
	}

	// Enforce hardware binding
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(expectedPeer.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		return nil, nil, fmt.Errorf("token is not bound to peer %s: %w", expectedPeer, err)
	}

	return b, verifyingKey, nil
}

func translateClaimsToFacts(addFact func(biscuit.Fact) error, claims map[string]any) error {
	claimMap := api.OIDCClaimToFact()
	keys := make([]string, 0, len(claimMap))
	for k := range claimMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, claimKey := range keys {
		factName := claimMap[claimKey]
		val, ok := claims[claimKey]
		if !ok || val == nil {
			continue
		}
		switch factName {
		case api.FactUser, api.FactEmail:
			if strVal, ok := val.(string); ok && strVal != "" {
				if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: factName,
					IDs:  []biscuit.Term{biscuit.String(strVal)},
				}}); err != nil {
					return fmt.Errorf("failed to add %s fact: %w", factName, err)
				}
			}
		case api.FactGroup, api.FactRole:
			items := toStringSlice(val)
			seen := make(map[string]bool)
			for _, item := range items {
				if seen[item] {
					continue
				}
				seen[item] = true
				if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: factName,
					IDs:  []biscuit.Term{biscuit.String(item)},
				}}); err != nil {
					return fmt.Errorf("failed to add %s fact: %w", factName, err)
				}
			}
		}
	}
	return nil
}

func toStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []string:
		return v
	case []any:
		var res []string
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				res = append(res, str)
			}
		}
		return res
	}
	return nil
}

// MintBootstrapBiscuitToken generates a signed Biscuit token for a peer using a bootstrap role.
// labels are control-plane-attested key=value claims (canonical, pre-validated); empty means no claims.
func MintBootstrapBiscuitToken(signingKey ed25519.PrivateKey, remotePeer peer.ID, role string, expiration time.Time, policyRoles []*api.PolicyRole, labels map[string]string) ([]byte, error) {
	return mintBiscuit(signingKey, remotePeer, []string{role}, expiration, nil, policyRoles, labels)
}

// VerifyAndExtractPeerID checks that the biscuit is signed by one of the trusted keys and returns the peer ID.
// This function does NOT perform time checks, making it suitable for token refresh flows.
func VerifyAndExtractPeerID(trustedPublicKeys []ed25519.PublicKey, biscuitData []byte, timeout time.Duration) (peer.ID, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return "", fmt.Errorf("malformed biscuit: %w", err)
	}

	authOpts := AuthorizerOptions(timeout)

	var authorizer biscuit.Authorizer
	var verified bool
	var lastErr error

	for _, pubKey := range trustedPublicKeys {
		auth, err := b.Authorizer(pubKey, authOpts...)
		if err != nil {
			lastErr = err
			continue
		}
		if err := auth.Authorize(); err == nil || errors.Is(err, biscuit.ErrNoMatchingPolicy) {
			authorizer = auth
			verified = true
			break
		} else {
			lastErr = err
		}
	}

	if !verified {
		return "", fmt.Errorf("signature verification failed: %v", lastErr)
	}

	// Extract the peer ID using Datalog query
	peerRule, err := parser.FromStringRule(`get_peer($p) <- node($p)`)
	if err != nil {
		return "", fmt.Errorf("failed to parse query rule: %w", err)
	}

	facts, err := authorizer.Query(peerRule)
	if err != nil {
		return "", fmt.Errorf("query failed: %w", err)
	}

	if len(facts) == 0 {
		return "", fmt.Errorf("no node fact found in biscuit. Authorizer state: %s", authorizer.PrintWorld())
	}

	// Extract value from fact
	pred := facts[0].Predicate
	if len(pred.IDs) != 1 {
		return "", fmt.Errorf("unexpected fact structure")
	}

	strVal, ok := pred.IDs[0].(biscuit.String)
	if !ok {
		return "", fmt.Errorf("node fact value is not a string")
	}

	pID, err := peer.Decode(string(strVal))
	if err != nil {
		return "", fmt.Errorf("invalid peer ID in biscuit: %w", err)
	}

	return pID, nil
}

// VerifyBiscuitRole checks that the biscuit is signed by the control plane's public key
// and contains the specified role fact.
func VerifyBiscuitRole(biscuitData []byte, controlPlanePubKey ed25519.PublicKey, expectedRole string, timeout time.Duration) error {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return fmt.Errorf("malformed biscuit: %w", err)
	}

	authorizer, err := b.Authorizer(controlPlanePubKey, AuthorizerOptions(timeout)...)
	if err != nil {
		return fmt.Errorf("failed to create authorizer: %w", err)
	}

	authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(expectedRole)}},
			},
		},
	}})
	authorizer.AddPolicy(api.AllowIfTruePolicy)

	if err := authorizer.Authorize(); err != nil {
		return fmt.Errorf("biscuit lacks expected role %q: %w", expectedRole, err)
	}
	return nil
}
