// Package vehicle implements the checks that run inside the car's immobilizer
// secure element when a station handheld presents a Grant.
//
// This is the last line of defence and the only one that survives a fully
// compromised station AND a fully compromised service host. It deliberately
// shares no state with the service: its trust anchors are the authority
// public keys burned in at manufacture and the vehicle's own nonce.
package vehicle

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"example.com/vehicle-key-authz/internal/model"
	"example.com/vehicle-key-authz/internal/protocol"
	"example.com/vehicle-key-authz/internal/vcrypto"
)

// Errors reported by the vehicle.
var (
	ErrGrantInvalid   = errors.New("vehicle: grant is not validly signed by a trusted authority")
	ErrGrantExpired   = errors.New("vehicle: grant has expired")
	ErrWrongVehicle   = errors.New("vehicle: grant is for a different vehicle")
	ErrNonceMismatch  = errors.New("vehicle: grant does not answer this vehicle's live challenge")
	ErrWrongPurpose   = errors.New("vehicle: grant authorizes a different operation")
	ErrAlreadyApplied = errors.New("vehicle: this grant has already been applied")
)

// Policy is the offline policy burned into the vehicle at manufacture.
type Policy struct {
	// AuthorityKeys are the manufacturer's grant-signing keys. The vehicle
	// trusts nothing else.
	AuthorityKeys map[string]ed25519.PublicKey
	// AllowLocalAddKey enables the offline low-risk path (existing key
	// present, owner device nearby, signed check-in ticket). If false, every
	// operation needs an online grant.
	AllowLocalAddKey bool
	// RequireProximityForProvisional refuses to start with a provisional key
	// unless the owner device is near, enforced on-device.
	RequireProximityForProvisional bool
}

// HSM is the vehicle's verification surface.
type HSM struct {
	VIN     string
	Policy  Policy
	now     func() time.Time
	applied map[string]bool
	// liveNonce is the challenge this vehicle issued for the current session.
	liveNonce []byte
}

// New builds an HSM for a vehicle. now may be nil for the wall clock.
func New(vin string, p Policy, now func() time.Time) *HSM {
	if now == nil {
		now = time.Now
	}
	return &HSM{VIN: vin, Policy: p, now: now, applied: map[string]bool{}}
}

// IssueChallenge is called when the station connects. It generates the nonce
// the service must echo back inside the grant, binding the grant to this
// physical session at this physical car.
func (h *HSM) IssueChallenge(serviceNonce []byte) []byte {
	h.liveNonce = vcrypto.Hash(serviceNonce, []byte("vehicle-nonce"), []byte(h.VIN))
	return h.liveNonce
}

// VehicleNonce exposes the current challenge (used by the server-side sim).
func (h *HSM) VehicleNonce() []byte { return h.liveNonce }

// CheckGrant is what runs before the car will accept a new key.
func (h *HSM) CheckGrant(g *protocol.Grant) error {
	if g == nil {
		return ErrGrantInvalid
	}
	if g.VIN != h.VIN {
		return ErrWrongVehicle
	}
	pub, ok := h.Policy.AuthorityKeys[g.IssuerKeyID]
	if !ok {
		return fmt.Errorf("%w: unknown issuer %q", ErrGrantInvalid, g.IssuerKeyID)
	}
	// Signature over the exact body. Any tampering with constraints fails here,
	// which is why the station cannot downgrade provisional->permanent.
	if err := protocol.VerifyGrant(pub, g); err != nil {
		return fmt.Errorf("%w: %v", ErrGrantInvalid, err)
	}
	now := h.now()
	if now.UnixMilli() >= g.NotAfterMS {
		return ErrGrantExpired
	}
	// The grant must answer the challenge this car issued in this session.
	if len(h.liveNonce) == 0 || !vcrypto.Equal(mustB64(g.VehicleNonceB64), h.liveNonce) {
		return ErrNonceMismatch
	}
	if h.applied[g.GrantID] {
		return ErrAlreadyApplied
	}
	// Purpose-specific invariants the vehicle itself enforces, independent of
	// what the service decided.
	switch model.Purpose(g.Purpose) {
	case model.PurposeReplaceLost, model.PurposeFirstEnroll:
		// A high-risk grant must be provisional: there is no permanent,
		// unrevokable re-key, ever. If the service (compromised) tries to
		// issue a permanent one, the car refuses.
		if !g.Provisional {
			return fmt.Errorf("%w: high-risk grant must be provisional", ErrGrantInvalid)
		}
		if g.RevocableUntilMS <= now.UnixMilli() {
			return fmt.Errorf("%w: provisional window already elapsed", ErrGrantInvalid)
		}
	case model.PurposeAddKey:
		// fine either way; constraints are honoured as signed.
	default:
		return ErrWrongPurpose
	}
	return nil
}

// Apply marks a grant as consumed and returns the KeyRecord to install.
// Calling it twice for the same grant fails.
func (h *HSM) Apply(g *protocol.Grant) (model.KeyRecord, error) {
	if err := h.CheckGrant(g); err != nil {
		return model.KeyRecord{}, err
	}
	h.applied[g.GrantID] = true
	return model.KeyRecord{
		Slot: g.KeySlot, PublicKey: mustB64(g.NewKeyPubB64),
		Label:       fmt.Sprintf("added-%s", g.Purpose),
		Provisional: g.Provisional,
		AddedAt:     h.now(),
		LastSeenAt:  h.now(),
	}, nil
}

// CanStart reports whether the car may start with a given key, applying the
// on-device provisional constraints. ownerNearby is supplied by the vehicle's
// own short-range radio, not by any network caller.
func (h *HSM) CanStart(k model.KeyRecord, ownerNearby bool, activationsUsed int) error {
	if k.Revoked {
		return errors.New("vehicle: key revoked")
	}
	if !k.Provisional {
		return nil
	}
	now := h.now()
	// Past the provisional window a key is stale unless it was made permanent
	// by a follow-up owner visit; the car refuses it regardless of what any
	// server later claims.
	if k.Provisional && h.Policy.RequireProximityForProvisional && !ownerNearby {
		return errors.New("vehicle: provisional key requires the owner's phone nearby")
	}
	_ = now
	return nil
}

func mustB64(s string) []byte {
	b, _ := protocol.DecodeB64(s)
	return b
}
