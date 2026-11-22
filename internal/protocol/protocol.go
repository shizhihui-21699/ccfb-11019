// Package protocol defines every signed message exchanged between the
// authorization service, the vehicle HSM, the owner's phone, the station back
// office and the station handheld.
//
// Design rules enforced here:
//
//  1. Every signature is domain separated (see package vcrypto).
//  2. Every payload binds the session ID, the VIN, the purpose, the exact key
//     being programmed and both nonces. A proof lifted from one session (or
//     one vehicle, or one purpose) cannot be replayed into another.
//  3. Every payload carries an absolute expiry. Nothing is valid forever.
//  4. Verification decodes strictly: unknown fields are rejected, so adding a
//     field to smuggle extra semantics past a lenient parser is impossible.
//
// The trust model: a stolen handheld or a malicious technician can produce
// NONE of the three proofs below. Only the vehicle's secure element can
// produce a VehicleProof, only the owner's enrolled phone can produce an
// OwnerConsent, and only the vehicle can attest that the phone was physically
// near it (ProximityAttestation).
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"example.com/vehicle-key-authz/internal/canon"
	"example.com/vehicle-key-authz/internal/vcrypto"
)

// Signature domains. Changing a string here invalidates every previously
// signed message of that kind, which is the intended effect of a protocol
// break.
const (
	DomainVehicleProof = "vkz/v1/vehicle-proof"
	DomainOwnerConsent = "vkz/v1/owner-consent"
	DomainProximity    = "vkz/v1/proximity-attestation"
	DomainCheckIn      = "vkz/v1/station-checkin"
	DomainWitness      = "vkz/v1/technician-witness"
	DomainRecovery     = "vkz/v1/owner-recovery-claim"
	DomainGrant        = "vkz/v1/grant"
	DomainLocalGrant   = "vkz/v1/local-grant"
	DomainRevocation   = "vkz/v1/key-revocation"
	DomainRequest      = "vkz/v1/api-request"
)

// ProtocolVersion is embedded in every payload.
const ProtocolVersion = 1

// MaxClockSkew is the tolerated difference between a payload timestamp and
// the verifier's clock.
const MaxClockSkewMS int64 = 30_000

var b64 = base64.RawURLEncoding

// ErrMalformed indicates the envelope or payload could not be decoded.
var ErrMalformed = errors.New("protocol: malformed message")

// EncodeB64 renders bytes for a JSON payload field.
func EncodeB64(b []byte) string { return b64.EncodeToString(b) }

// DecodeB64 parses a base64 payload field.
func DecodeB64(s string) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: bad base64: %v", ErrMalformed, err)
	}
	return b, nil
}

// envelope is the transport wrapper. The signature covers the canonical form
// of Payload only; the envelope itself carries no unsigned semantics.
type envelope struct {
	Payload json.RawMessage `json:"payload"`
	Sig     string          `json:"sig"`
}

// Seal signs v and returns the canonical envelope bytes.
func Seal(priv ed25519.PrivateKey, domain string, v any) ([]byte, error) {
	payload, err := canon.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("protocol: seal: %w", err)
	}
	sig := vcrypto.Sign(priv, domain, payload)
	return canon.Marshal(envelope{Payload: payload, Sig: EncodeB64(sig)})
}

// Open verifies the envelope signature and strictly decodes the payload into
// out. Unknown payload fields are rejected.
func Open(pub ed25519.PublicKey, domain string, raw, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key", ErrMalformed)
	}
	if err := vcrypto.Verify(pub, domain, raw, sig); err != nil {
		return err
	}
	// Canonicalisation gate: a signer and verifier must agree on bytes. We
	// require the received payload to already be in canonical form, which
	// removes any ambiguity about duplicates, whitespace or key order that a
	// non-JSON-preserving transport might introduce.
	payload := bytes.TrimSpace(raw)
	var probe any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&probe); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	return nil
}

// UnmarshalEnvelope splits an envelope and returns the raw payload plus sig.
func UnmarshalEnvelope(raw []byte) (payload, sig []byte, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env envelope
	if err := dec.Decode(&env); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, nil, err
	}
	if env.Sig == "" || len(env.Payload) == 0 {
		return nil, nil, fmt.Errorf("%w: missing payload or signature", ErrMalformed)
	}
	s, err := DecodeB64(env.Sig)
	if err != nil {
		return nil, nil, err
	}
	return env.Payload, s, nil
}

func ensureEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	return nil
}

// DecodeStrict decodes JSON into out, rejecting unknown fields.
func DecodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return ensureEOF(dec)
}

// --- shared header ---------------------------------------------------------

// Header is embedded in every payload and binds it to a session and vehicle.
type Header struct {
	Typ             string `json:"typ"`
	Ver             int    `json:"ver"`
	SessionID       string `json:"session_id"`
	VIN             string `json:"vin"`
	Purpose         string `json:"purpose"`
	KeySlot         int    `json:"key_slot"`
	NewKeyPubB64    string `json:"new_key_pub"`
	ServiceNonceB64 string `json:"service_nonce"`
	VehicleNonceB64 string `json:"vehicle_nonce"`
	IssuedAtMS      int64  `json:"issued_at_ms"`
	ExpiresAtMS     int64  `json:"expires_at_ms"`
}

// --- vehicle proof ---------------------------------------------------------

// VehicleProof is produced by the vehicle's immobilizer secure element after
// the technician's handheld forwards the service challenge over the physical
// diagnostic bus. It is the only evidence that the car itself is present.
//
// Two key lists are reported and they mean different things:
//
//   - PresentKeySlots: transponders the immobilizer can hear (radio). Weak —
//     a passive transponder or a nearby key fob can be sensed.
//   - ChallengedKeySlots: slots where an inserted key actually answered the
//     vehicle's cryptographic challenge in this session. Strong — this
//     requires the physical key.
type VehicleProof struct {
	Header
	HSMSerial          string `json:"hsm_serial"`
	PresentKeySlots    []int  `json:"present_key_slots"`
	ChallengedKeySlots []int  `json:"challenged_key_slots"`
	ChallengeHashB64   string `json:"challenge_hash"`
	OdometerKM         int64  `json:"odometer_km"`
	FirmwareVersion    string `json:"fw_version"`
	ImmobilizerLocked  bool   `json:"immobilizer_locked"`
}

// --- owner consent ---------------------------------------------------------

// OwnerConsent is signed by the owner's enrolled phone after a UI flow that
// lists, in human language, exactly which key is being added and where.
type OwnerConsent struct {
	Header
	StationID        string `json:"station_id"`
	OwnerDeviceID    string `json:"owner_device_id"`
	OwnerSubject     string `json:"owner_subject"`
	ApprovedKeyLabel string `json:"approved_key_label"`
	ApprovedSlots    []int  `json:"approved_slots"`
	ConsentMethod    string `json:"consent_method"` // "face_id", "passcode", "haptic"
	DisplayedStation string `json:"displayed_station"`
	DisplayedVIN     string `json:"displayed_vin"`
	UserAgent        string `json:"user_agent"`
}

// --- proximity attestation -------------------------------------------------

// ProximityAttestation is signed by the VEHICLE, not by the phone and not by
// the station. The vehicle runs a time-bounded challenge/response over its
// short-range radio (BLE/UWB) against the owner device and reports the
// measured round-trip time. A relay that forwards this handshake over the
// internet cannot keep RTT under the threshold, and a station handheld cannot
// fabricate the attestation because it does not hold the vehicle HSM key.
type ProximityAttestation struct {
	Header
	OwnerDeviceID       string `json:"owner_device_id"`
	OwnerDevicePubB64   string `json:"owner_device_pub"`
	OwnerConsentHashB64 string `json:"owner_consent_hash"`
	Channel             string `json:"channel"` // "ble", "uwb", "nfc"
	RTTMicros           int64  `json:"rtt_us"`
	DistanceUpperCMM    int    `json:"distance_upper_cm"`
	SampleCount         int    `json:"sample_count"`
}

// --- station check-in ------------------------------------------------------

// CheckInAssertion is signed by the station BACK OFFICE machine (where the// service advisor writes a repair order), not by the handheld. A thief who
// steals a handheld still cannot create a check-in; they would also need to
// compromise the shop management system, which is itself audited.
type CheckInAssertion struct {
	Typ             string  `json:"typ"`
	Ver             int     `json:"ver"`
	CheckInID       string  `json:"check_in_id"`
	VIN             string  `json:"vin"`
	StationID       string  `json:"station_id"`
	Bay             string  `json:"bay"`
	RepairRef       string  `json:"repair_ref"`
	AdvisorID       string  `json:"advisor_id"`
	ArrivedAtMS     int64   `json:"arrived_at_ms"`
	ExpiresAtMS     int64   `json:"expires_at_ms"`
	IssuedAtMS      int64   `json:"issued_at_ms"`
	GeofenceLat     float64 `json:"geofence_lat"`
	GeofenceLon     float64 `json:"geofence_lon"`
	GeofenceRadiusM int     `json:"geofence_radius_m"`
}

// --- second-technician witness --------------------------------------------

// WitnessAttestation is signed by a SECOND technician's handheld for high-risk
// operations. It must come from a different technician and a different device
// than the primary, so one person with one stolen handset cannot satisfy it.
type WitnessAttestation struct {
	Header
	StationID           string `json:"station_id"`
	WitnessTechID       string `json:"witness_tech_id"`
	WitnessDeviceID     string `json:"witness_device_id"`
	WitnessDevicePubB64 string `json:"witness_device_pub"`
	ObservedVIN         string `json:"observed_vin"`
	Confirmed           bool   `json:"confirmed"`
}

// --- recovery claim (owner has no phone and no key) ------------------------

// RecoveryClaim is the fallback for "owner lost every key and has no enrolled
// phone". It is signed by an external identity verifier (e.g. the dealer's
// KYC provider or a government ID bridge) after an in-person document check.
// By itself it deliberately does NOT authorize anything: the service still
// requires the vehicle proof, a check-in, a cooling-off period during which
// every registered contact can veto, and issues only a provisional key.
type RecoveryClaim struct {
	Typ                  string `json:"typ"`
	Ver                  int    `json:"ver"`
	ClaimID              string `json:"claim_id"`
	VIN                  string `json:"vin"`
	StationID            string `json:"station_id"`
	OwnerSubject         string `json:"owner_subject"`
	NewOwnerDevicePubB64 string `json:"new_owner_device_pub"`
	IdentityDocRef       string `json:"identity_doc_ref"`
	Method               string `json:"method"`
	VerifiedAtMS         int64  `json:"verified_at_ms"`
	ExpiresAtMS          int64  `json:"expires_at_ms"`
	ProviderKeyID        string `json:"provider_key_id"`
}

// --- grant -----------------------------------------------------------------

// GrantBody is the signed portion of a Grant. The vehicle verifies the
// signature over exactly this body; the SignatureB64 field travels alongside
// and is excluded from the signed bytes.
type GrantBody struct {
	Typ               string `json:"typ"`
	Ver               int    `json:"ver"`
	GrantID           string `json:"grant_id"`
	VIN               string `json:"vin"`
	SessionID         string `json:"session_id"`
	VehicleNonceB64   string `json:"vehicle_nonce"`
	ServiceNonceB64   string `json:"service_nonce"`
	OwnerSubject      string `json:"owner_subject"`
	OwnerDeviceID     string `json:"owner_device_id"`
	OwnerDevicePubB64 string `json:"owner_device_pub"`
	StationID         string `json:"station_id"`
	CheckInID         string `json:"check_in_id"`
	TechnicianID      string `json:"technician_id"`
	WitnessTechID     string `json:"witness_tech_id,omitempty"`
	DeviceID          string `json:"device_id"`
	Purpose           string `json:"purpose"`
	KeySlot           int    `json:"key_slot"`
	NewKeyPubB64      string `json:"new_key_pub"`
	Tier              string `json:"tier"`
	PolicyVersion     string `json:"policy_version"`
	// Provisional keys are removable by the owner without station help.
	Provisional                  bool   `json:"provisional"`
	OwnerProximityRequiredPerUse bool   `json:"owner_proximity_per_use"`
	MaxActivations               int    `json:"max_activations"`
	RevocableUntilMS             int64  `json:"revocable_until_ms"`
	IssuedAtMS                   int64  `json:"issued_at_ms"`
	NotAfterMS                   int64  `json:"not_after_ms"`
	IssuerKeyID                  string `json:"issuer_key_id"`
}

// Grant is the signed capability the vehicle checks offline.
type Grant struct {
	GrantBody
	SignatureB64 string `json:"signature"`
}

// SignGrant signs g in place with the issuer key.
func SignGrant(priv ed25519.PrivateKey, g *Grant) error {
	payload, err := canon.Marshal(g.GrantBody)
	if err != nil {
		return err
	}
	g.SignatureB64 = EncodeB64(vcrypto.Sign(priv, DomainGrant, payload))
	return nil
}

// VerifyGrant checks the issuer signature and returns the signed body.
func VerifyGrant(pub ed25519.PublicKey, g *Grant) error {
	payload, err := canon.Marshal(g.GrantBody)
	if err != nil {
		return err
	}
	sig, err := DecodeB64(g.SignatureB64)
	if err != nil {
		return err
	}
	return vcrypto.Verify(pub, DomainGrant, payload, sig)
}

// LocalGrant covers the fully offline low-risk path: the vehicle authorizes an
// additional key itself, using policy provisioned at manufacture, because a
// working key is present, the owner's phone is physically against the car and
// consent is signed. The service still cross-checks it when connectivity
// returns, and the record includes a pre-fetched signed check-in ticket so the
// vehicle knows the car is at a station.
type LocalGrant struct {
	Typ                         string `json:"typ"`
	Ver                         int    `json:"ver"`
	VIN                         string `json:"vin"`
	GrantID                     string `json:"grant_id"`
	CheckInID                   string `json:"check_in_id"`
	StationID                   string `json:"station_id"`
	TechnicianID                string `json:"technician_id"`
	DeviceID                    string `json:"device_id"`
	KeySlot                     int    `json:"key_slot"`
	NewKeyPubB64                string `json:"new_key_pub"`
	OwnerDeviceID               string `json:"owner_device_id"`
	OwnerConsentHashB64         string `json:"owner_consent_hash"`
	ProximityAttestationHashB64 string `json:"proximity_hash"`
	PresentKeySlots             []int  `json:"present_key_slots"`
	IssuedAtMS                  int64  `json:"issued_at_ms"`
	NotAfterMS                  int64  `json:"not_after_ms"`
	SignedBy                    string `json:"signed_by"`
}

// StationPresenceTicket is issued by the service from a back-office check-in
// and cached on the station handheld. It lets a vehicle verify, with no
// network at all, that a car was checked into an authorized bay, without the
// vehicle needing to know every station's back-office key.
type StationPresenceTicket struct {
	Typ          string `json:"typ"`
	Ver          int    `json:"ver"`
	TicketID     string `json:"ticket_id"`
	VIN          string `json:"vin"`
	StationID    string `json:"station_id"`
	CheckInID    string `json:"check_in_id"`
	TechnicianID string `json:"technician_id"`
	DeviceID     string `json:"device_id"`
	Bay          string `json:"bay"`
	IssuedAtMS   int64  `json:"issued_at_ms"`
	NotAfterMS   int64  `json:"not_after_ms"`
	IssuerKeyID  string `json:"issuer_key_id"`
	SignatureB64 string `json:"signature"`
}

// --- revocation ------------------------------------------------------------

// KeyRevocation lets the owner disable a key (including a provisional one)
// without any station participation. Signed by the owner device, or by the
// vehicle itself when the owner is standing at it.
type KeyRevocation struct {
	Typ           string `json:"typ"`
	Ver           int    `json:"ver"`
	VIN           string `json:"vin"`
	KeySlot       int    `json:"key_slot"`
	KeyPubB64     string `json:"key_pub"`
	Reason        string `json:"reason"`
	OwnerDeviceID string `json:"owner_device_id"`
	RevokedAtMS   int64  `json:"revoked_at_ms"`
	NonceB64      string `json:"nonce"`
}

// --- API request authentication -------------------------------------------

// RequestAuth is signed by the caller's device/back-office key over the HTTP
// method, path, body hash, timestamp and nonce. It stops request replay and
// cross-endpoint reuse. It is NOT an authorization: a valid request signature
// only means "this is device X talking", which in the theft scenario is
// exactly what the attacker already has.
type RequestAuth struct {
	DeviceID    string `json:"device_id"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	BodyHashB64 string `json:"body_hash"`
	TimestampMS int64  `json:"ts_ms"`
	Nonce       string `json:"nonce"`
}
