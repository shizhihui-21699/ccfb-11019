// Package model holds the domain types shared by the authorization service,
// the station-side diagnostic software, the vehicle HSM and the owner app.
//
// All wire timestamps are Unix milliseconds (int64) rather than formatted
// strings so that canonical encoding is unambiguous across languages.
package model

import "time"

// Purpose is the kind of key operation being authorized.
type Purpose string

const (
	// PurposeAddKey adds an additional key while at least one working key
	// still exists. Lowest risk.
	PurposeAddKey Purpose = "add_key"
	// PurposeReplaceLost re-programs the vehicle after every key was lost.
	// There is no old key available to prove possession, so this is the
	// highest-risk purpose.
	PurposeReplaceLost Purpose = "replace_all_keys_lost"
	// PurposeFirstEnroll binds the first owner device to a vehicle. Also
	// high risk: whoever completes this owns the vehicle in our system.
	PurposeFirstEnroll Purpose = "first_owner_enrollment"
)

// Valid reports whether p is a known purpose.
func (p Purpose) Valid() bool {
	switch p {
	case PurposeAddKey, PurposeReplaceLost, PurposeFirstEnroll:
		return true
	}
	return false
}

// RiskTier is the outcome of policy evaluation.
type RiskTier string

const (
	TierLow      RiskTier = "low"
	TierElevated RiskTier = "elevated"
	TierHigh     RiskTier = "high"
)

// VehicleStatus is the lifecycle state of a vehicle record.
type VehicleStatus string

const (
	VehicleActive  VehicleStatus = "active"
	VehicleFlagged VehicleStatus = "flagged"
	VehicleStolen  VehicleStatus = "reported_stolen"
)

// StationStatus is the lifecycle state of an authorized repair station.
type StationStatus string

const (
	StationActive    StationStatus = "active"
	StationSuspended StationStatus = "suspended"
)

// Geo is a coarse location report. Used only as corroborating evidence; it is
// never trusted on its own because both GPS and cell data can be spoofed.
type Geo struct {
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	AccuracyM int     `json:"accuracy_m"`
}

// Vehicle is the manufacturer-side record of a car.
type Vehicle struct {
	VIN string
	// HSMPublicKey is provisioned at manufacture into the immobilizer unit
	// and pinned here. It is the vehicle's own signing identity. The private
	// half never leaves the vehicle's secure element.
	HSMPublicKey []byte
	OwnerSubject string
	// OwnerContacts are the owner's registered notification channels
	// (secondary phone, email, second driver). Any of them can veto.
	OwnerContacts []string

	BoundDevices []BoundDevice
	Keys         []KeyRecord
	MaxKeys      int

	Status         VehicleStatus
	OwnershipSince time.Time
	LastTransferAt time.Time
}

// BoundDevice is an owner device (phone) that has been enrolled for a vehicle.
type BoundDevice struct {
	DeviceID   string
	PublicKey  []byte
	Subject    string
	EnrolledAt time.Time
	Revoked    bool
}

// KeyRecord is a key currently provisioned into the vehicle.
type KeyRecord struct {
	Slot        int
	PublicKey   []byte
	Label       string
	Provisional bool
	AddedAt     time.Time
	LastSeenAt  time.Time
	Revoked     bool
}

// WorkingKeys returns the number of non-revoked keys.
func (v *Vehicle) WorkingKeys() int {
	n := 0
	for _, k := range v.Keys {
		if !k.Revoked {
			n++
		}
	}
	return n
}

// FindBoundDevice returns the enrolled, non-revoked device with the given ID.
func (v *Vehicle) FindBoundDevice(deviceID string) (*BoundDevice, bool) {
	for i := range v.BoundDevices {
		if v.BoundDevices[i].DeviceID == deviceID && !v.BoundDevices[i].Revoked {
			return &v.BoundDevices[i], true
		}
	}
	return nil, false
}

// Station is an authorized repair facility.
type Station struct {
	ID     string
	Name   string
	Status StationStatus
	Geo    Geo
	// BackOfficePublicKey signs check-in assertions from the shop management
	// system (service advisor writes a repair order when the car arrives).
	// It lives in the station's back-office machine, not in the handheld
	// diagnostic device, so a stolen handheld cannot mint check-ins.
	BackOfficePublicKey []byte
	// TwoStaffAttested records whether this station has been audited for the
	// two-person rule on high-risk operations.
	TwoStaffAttested bool
	Watchlisted      bool
}

// Technician is a station employee.
type Technician struct {
	ID        string
	StationID string
	Name      string
	Active    bool
	// DeviceIDs are the diagnostic handsets currently assigned to this tech.
	DeviceIDs []string
}

// DiagnosticDevice is a station handheld.
type DiagnosticDevice struct {
	ID        string
	StationID string
	// PublicKey authenticates the device over mTLS. It proves "this is a
	// station device" but NOT "a human is present", so it is used for
	// routing and rate limiting only, never as authorization.
	PublicKey []byte
	Revoked   bool
}

// CheckIn is a signed assertion from the station back office that a given VIN
// physically arrived at the facility. It is one of the two independent
// "the car is here" signals (the other being the vehicle HSM itself).
type CheckIn struct {
	ID        string
	VIN       string
	StationID string
	Bay       string
	ArrivedAt time.Time
	ExpiresAt time.Time
	IssuedAt  time.Time
	Signature []byte
	Revoked   bool
	RepairRef string
	AdvisorID string
}

// ValidAt reports whether the check-in is usable at time t.
func (c *CheckIn) ValidAt(t time.Time) bool {
	return !c.Revoked && t.After(c.ArrivedAt.Add(-time.Minute)) && t.Before(c.ExpiresAt)
}

// SessionState tracks the authorization handshake.
type SessionState string

const (
	StateOpen      SessionState = "open"
	StateProven    SessionState = "proven" // proofs collected, awaiting decision
	StateGranted   SessionState = "granted"
	StateDenied    SessionState = "denied"
	StateExpired   SessionState = "expired"
	StateCancelled SessionState = "cancelled"
)

// Session is one key-authorization attempt.
type Session struct {
	ID           string
	ServerNonce  []byte
	VIN          string
	StationID    string
	TechnicianID string
	DeviceID     string
	Purpose      Purpose
	KeySlot      int
	NewKeyPublic []byte
	CheckInID    string

	OpenedAt  time.Time
	ExpiresAt time.Time
	State     SessionState

	// RecoveryStartedAt is when the cooling-off clock began for the
	// no-phone/no-key path. Zero means it was never started.
	RecoveryStartedAt time.Time
	// ContactsNotified counts owner contacts reached with an alert.
	ContactsNotified int
	// OwnerDeviceID/OwnerDevicePub record the verified owner device for the
	// issued grant.
	OwnerDeviceID  string
	OwnerDevicePub []byte

	Decision   *Decision
	GrantID    string
	DenyReason string
}

// Decision is the policy outcome for a session.
type Decision struct {
	Allow         bool        `json:"allow"`
	Tier          RiskTier    `json:"tier"`
	Unmet         []string    `json:"unmet,omitempty"`
	Reasons       []string    `json:"reasons"`
	Constraints   Constraints `json:"constraints"`
	PolicyVersion string      `json:"policy_version"`
}

// Constraints travel inside the grant and are enforced by the vehicle HSM,
// not just by the service. A compromised station device therefore cannot
// widen them.
type Constraints struct {
	// Provisional keys can be revoked by the owner within the revocation
	// window without any station involvement.
	Provisional bool `json:"provisional"`
	// OwnerProximityRequiredPerUse makes each start during the provisional
	// window require the owner's phone nearby. Used when confidence in
	// ownership is lower (e.g. all keys lost with no owner device).
	OwnerProximityRequiredPerUse bool `json:"owner_proximity_required_per_use"`
	// MaxActivations limits starts for a provisional key (0 = unlimited).
	MaxActivations int `json:"max_activations"`
	// RevocableUntilMS is the end of the owner's unilateral veto window.
	RevocableUntilMS int64 `json:"revocable_until_ms"`
	// NotAfterMS is the hard expiry of the authorization itself.
	NotAfterMS int64 `json:"not_after_ms"`
}
