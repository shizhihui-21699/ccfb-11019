// Package service orchestrates the authorization handshake.
//
// The service is the only party that decides, and the only party that can mint
// a Grant. The station handheld can carry a Grant to the car; it cannot create
// one. The vehicle additionally verifies the Grant's issuer signature against
// authority keys provisioned at manufacture, so even a fully compromised
// service host cannot widen a vehicle's policy without the authority key,
// which lives in an HSM.
//
// Every step writes to the audit log, including refused proofs, because the
// failed attempts are the interesting ones in an investigation.
package service

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"example.com/vehicle-key-authz/internal/audit"
	"example.com/vehicle-key-authz/internal/canon"
	"example.com/vehicle-key-authz/internal/model"
	"example.com/vehicle-key-authz/internal/policy"
	"example.com/vehicle-key-authz/internal/protocol"
	"example.com/vehicle-key-authz/internal/vcrypto"
)

// Errors returned to callers. They are coarse on purpose: an attacker probing
// the service learns whether their cryptography failed, never which specific
// policy gate they would need to satisfy.
var (
	ErrNotFound     = errors.New("service: not found")
	ErrState        = errors.New("service: invalid state for this operation")
	ErrExpired      = errors.New("service: session expired")
	ErrProof        = errors.New("service: proof rejected")
	ErrDenied       = errors.New("service: authorization denied")
	ErrReplay       = errors.New("service: replayed or duplicate message")
	ErrUnauthorized = errors.New("service: caller not authorized for this action")
)

// Store is the persistence boundary. The reference implementation is in
// memory; a production store must make session state transitions
// transactional and the audit log durable.
type Store interface {
	Vehicle(vin string) (*model.Vehicle, error)
	Station(id string) (*model.Station, error)
	Tech(id string) (*model.Technician, error)
	Device(id string) (*model.DiagnosticDevice, error)
	CheckIn(id string) (*model.CheckIn, error)
	PutCheckIn(*model.CheckIn)
	Session(id string) (*model.Session, error)
	PutSession(*model.Session)
	HighRiskCounts(vin, stationID string, now time.Time) (vehicle, station int)
	RecordGrant(vin, stationID string, tier model.RiskTier, at time.Time)
	// SeenNonce records a nonce and returns true if it had already been
	// used. The first call for a given (scope, nonce) returns false.
	SeenNonce(scope, nonce string) bool
}

// IssuerKey is an authority signing key. In production the private half lives
// in an HSM and Sign is an RPC.
type IssuerKey struct {
	KeyID   string
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Service wires the store, policy and audit log together.
type Service struct {
	Store  Store
	Cfg    policy.Config
	Log    *audit.Log
	Issuer IssuerKey
	Now    func() time.Time
	// SessionTTL bounds a handshake. A technician who walks away from a
	// half-finished operation does not leave a live authorization behind.
	SessionTTL time.Duration
	// ClockSkew is the tolerated message timestamp drift.
	ClockSkew time.Duration
	// MaxProofLifetime bounds how long any single signed proof may be valid.
	MaxProofLifetime time.Duration
	// RecoveryProviders maps identity-verifier key IDs to public keys.
	RecoveryProviders map[string]ed25519.PublicKey

	mu       sync.Mutex
	veto     map[string]map[string]bool   // recoveryID -> contact -> vetoed
	notify   map[string]map[string]string // recoveryID -> contact -> token
	tokenIdx map[string]string            // token -> recoveryID+"\x00"+contact
	// recoveries tracks open no-phone recoveries by VIN. A recovery's
	// cooling-off outlives any single session, because a session is short
	// by design and the cooling-off is deliberately long.
	recoveries map[string]*recovery
}

// recovery is the durable state of a no-phone/no-key recovery.
type recovery struct {
	ID        string
	VIN       string
	StationID string
	StartedAt time.Time
	Contacts  []string
	Vetoed    map[string]bool
}

// New builds a service.
func New(st Store, cfg policy.Config, log *audit.Log, issuer IssuerKey) *Service {
	return &Service{
		Store:             st,
		Cfg:               cfg,
		Log:               log,
		Issuer:            issuer,
		Now:               time.Now,
		SessionTTL:        10 * time.Minute,
		ClockSkew:         2 * time.Minute,
		MaxProofLifetime:  15 * time.Minute,
		RecoveryProviders: map[string]ed25519.PublicKey{},
		veto:              map[string]map[string]bool{},
		notify:            map[string]map[string]string{},
		tokenIdx:          map[string]string{},
		recoveries:        map[string]*recovery{},
	}
}

// --- session lifecycle -----------------------------------------------------

// OpenRequest is what a station handheld submits to start a handshake.
type OpenRequest struct {
	DeviceID     string        `json:"device_id"`
	TechnicianID string        `json:"technician_id"`
	VIN          string        `json:"vin"`
	Purpose      model.Purpose `json:"purpose"`
	KeySlot      int           `json:"key_slot"`
	NewKeyPubB64 string        `json:"new_key_pub"`
	CheckInID    string        `json:"check_in_id"`
}

// OpenResult carries the service nonce that every subsequent proof must bind.
type OpenResult struct {
	SessionID       string   `json:"session_id"`
	ServiceNonceB64 string   `json:"service_nonce"`
	ExpiresAtMS     int64    `json:"expires_at_ms"`
	VIN             string   `json:"vin"`
	Purpose         string   `json:"purpose"`
	KeySlot         int      `json:"key_slot"`
	Instructions    []string `json:"instructions"`
}

// OpenSession validates static preconditions and creates the session.
func (s *Service) OpenSession(req OpenRequest) (*OpenResult, error) {
	now := s.Now()
	dev, err := s.Store.Device(req.DeviceID)
	if err != nil {
		return nil, err
	}
	st, err := s.Store.Station(dev.StationID)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.Tech(req.TechnicianID); err != nil {
		return nil, err
	}
	v, err := s.Store.Vehicle(req.VIN)
	if err != nil {
		return nil, err
	}
	ci, err := s.Store.CheckIn(req.CheckInID)
	if err != nil {
		return nil, err
	}
	if !req.Purpose.Valid() {
		return nil, fmt.Errorf("%w: unknown purpose", ErrState)
	}
	newKey, err := protocol.DecodeB64(req.NewKeyPubB64)
	if err != nil || len(newKey) == 0 {
		return nil, fmt.Errorf("%w: new key public key required", ErrState)
	}
	if ci.VIN != req.VIN || ci.StationID != st.ID || !ci.ValidAt(now) {
		s.audit("session.open.refused", req.TechnicianID, req.VIN, st.ID, "", map[string]any{
			"reason": "check_in_not_usable_for_this_vehicle_and_station",
		})
		return nil, fmt.Errorf("%w: check-in does not cover this vehicle and station, or is closed", ErrUnauthorized)
	}

	nonce, err := vcrypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	sess := &model.Session{
		ID:           vcrypto.RandomID(),
		ServerNonce:  nonce,
		VIN:          req.VIN,
		StationID:    st.ID,
		TechnicianID: req.TechnicianID,
		DeviceID:     req.DeviceID,
		Purpose:      req.Purpose,
		KeySlot:      req.KeySlot,
		NewKeyPublic: newKey,
		CheckInID:    req.CheckInID,
		OpenedAt:     now,
		ExpiresAt:    now.Add(s.SessionTTL),
		State:        model.StateOpen,
	}
	s.Store.PutSession(sess)
	s.audit("session.open", req.TechnicianID, req.VIN, st.ID, sess.ID, map[string]any{
		"purpose": string(req.Purpose), "key_slot": req.KeySlot,
		"device_id": req.DeviceID, "check_in": req.CheckInID,
		"working_keys": v.WorkingKeys(),
	})
	return &OpenResult{
		SessionID:       sess.ID,
		ServiceNonceB64: protocol.EncodeB64(nonce),
		ExpiresAtMS:     sess.ExpiresAt.UnixMilli(),
		VIN:             v.VIN,
		Purpose:         string(req.Purpose),
		KeySlot:         req.KeySlot,
		Instructions:    instructionsFor(req.Purpose),
	}, nil
}

func instructionsFor(p model.Purpose) []string {
	switch p {
	case model.PurposeAddKey:
		return []string{
			"Connect the diagnostic lead to the vehicle.",
			"Insert an existing working key when the vehicle asks for it.",
			"Ask the owner to hold their phone against the start button and approve on screen.",
		}
	case model.PurposeReplaceLost, model.PurposeFirstEnroll:
		return []string{
			"Connect the diagnostic lead to the vehicle.",
			"No working key exists: the owner must approve on their enrolled phone held against the start button.",
			"If the owner has no phone, a second technician and a verified identity document are required, and the key stays provisional through the cooling-off period.",
		}
	}
	return nil
}

// --- check-in ingestion ----------------------------------------------------

// IngestCheckIn verifies a back-office check-in assertion and stores it. The
// signature is checked against the station's provisioned back-office key, so
// a stolen handheld (which does not hold that key) cannot mint a check-in.
//
// This is the service's only trust boundary for "the car arrived at a bay".
// In production the station's shop-management system calls this over mTLS as
// part of opening a repair order, not from the handheld.
func (s *Service) IngestCheckIn(raw []byte) (*model.CheckIn, error) {
	stationID, err := peekString(raw, "station_id")
	if err != nil {
		return nil, fmt.Errorf("%w: malformed check-in", ErrProof)
	}
	st, err := s.Store.Station(stationID)
	if err != nil {
		return nil, err
	}
	payload, sig, err := protocol.UnmarshalEnvelope(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed check-in", ErrProof)
	}
	if err := protocol.Open(st.BackOfficePublicKey, protocol.DomainCheckIn, payload, sig); err != nil {
		s.audit("checkin.refused", "backoffice:"+stationID, "", stationID, "", map[string]any{
			"reason": "signature invalid",
		})
		return nil, fmt.Errorf("%w: check-in signature invalid", ErrProof)
	}
	var ci protocol.CheckInAssertion
	if err := protocol.DecodeStrict(payload, &ci); err != nil {
		return nil, fmt.Errorf("%w: malformed check-in", ErrProof)
	}
	now := s.Now()
	if ci.Ver != protocol.ProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported version", ErrProof)
	}
	if ci.IssuedAtMS > now.Add(s.ClockSkew).UnixMilli() {
		return nil, fmt.Errorf("%w: check-in from the future", ErrProof)
	}
	if ci.ExpiresAtMS <= now.UnixMilli() {
		return nil, fmt.Errorf("%w: check-in already expired", ErrProof)
	}
	if ci.ExpiresAtMS-ci.ArrivedAtMS > int64(24*time.Hour/time.Millisecond) {
		return nil, fmt.Errorf("%w: check-in window too long", ErrProof)
	}
	if ci.VIN == "" || ci.CheckInID == "" {
		return nil, fmt.Errorf("%w: incomplete check-in", ErrProof)
	}
	rec := &model.CheckIn{
		ID: ci.CheckInID, VIN: ci.VIN, StationID: ci.StationID, Bay: ci.Bay,
		RepairRef: ci.RepairRef, AdvisorID: ci.AdvisorID,
		ArrivedAt: time.UnixMilli(ci.ArrivedAtMS), ExpiresAt: time.UnixMilli(ci.ExpiresAtMS),
		IssuedAt:  time.UnixMilli(ci.IssuedAtMS),
		Signature: sig, Revoked: false,
	}
	s.Store.PutCheckIn(rec)
	s.audit("checkin.ingested", "backoffice:"+stationID, ci.VIN, stationID, "", map[string]any{
		"check_in": ci.CheckInID, "bay": ci.Bay, "repair_ref": ci.RepairRef,
	})
	return rec, nil
}

// CloseCheckIn closes a check-in when the vehicle leaves the bay, so a stale
// open repair order cannot be reused hours later.
func (s *Service) CloseCheckIn(checkInID string) error {
	ci, err := s.Store.CheckIn(checkInID)
	if err != nil {
		return err
	}
	ci.Revoked = true
	ci.ExpiresAt = s.Now()
	s.Store.PutCheckIn(ci)
	s.audit("checkin.closed", "backoffice:"+ci.StationID, ci.VIN, ci.StationID, "", map[string]any{
		"check_in": ci.ID,
	})
	return nil
}

// --- proofs ----------------------------------------------------------------

// ProofBundle is what the handheld submits once the physical steps are done.
// Each field is a sealed, signed envelope; the service verifies all of them
// itself and never trusts a boolean from the caller.
type ProofBundle struct {
	SessionID        string     `json:"session_id"`
	VehicleProof     []byte     `json:"vehicle_proof,omitempty"`
	OwnerConsent     []byte     `json:"owner_consent,omitempty"`
	Proximity        []byte     `json:"proximity,omitempty"`
	Witness          []byte     `json:"witness,omitempty"`
	RecoveryClaim    []byte     `json:"recovery_claim,omitempty"`
	OwnerReportedGeo *model.Geo `json:"owner_geo,omitempty"`
}

// VerifyOutcome is the full, explained result. Unmet lists what is still
// needed so the handheld can prompt the technician without guessing.
type VerifyOutcome struct {
	Allowed    bool            `json:"allowed"`
	Tier       model.RiskTier  `json:"tier"`
	Grant      *protocol.Grant `json:"grant,omitempty"`
	Unmet      []string        `json:"unmet,omitempty"`
	Reasons    []string        `json:"reasons"`
	DenyReason string          `json:"deny_reason,omitempty"`
	// Details records the per-proof verdict (e.g. "owner_consent": "signature
	// invalid"). The handheld shows it, and tests assert on it: a refusal for
	// the wrong reason is a bug even if it happens to be a refusal.
	Details map[string]any `json:"details,omitempty"`
}

// SubmitProofs verifies every supplied envelope and runs policy.
//
// Security properties:
//   - Each envelope is signature-checked against a key the service holds,
//     never against a key supplied in the same request.
//   - Each envelope must bind this session ID, VIN, purpose, key slot, new
//     key and both nonces; a proof harvested from another session fails.
//   - Timestamps must be fresh, so a recorded proof cannot be replayed later.
//   - Every rejected attempt is audited.
func (s *Service) SubmitProofs(pb ProofBundle) (*VerifyOutcome, error) {
	now := s.Now()
	sess, err := s.Store.Session(pb.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.State != model.StateOpen && sess.State != model.StateProven {
		return nil, fmt.Errorf("%w: session is %s", ErrState, sess.State)
	}
	if now.After(sess.ExpiresAt) {
		s.settle(sess, model.StateExpired, "session timed out")
		return nil, ErrExpired
	}
	v, err := s.Store.Vehicle(sess.VIN)
	if err != nil {
		return nil, err
	}
	st, err := s.Store.Station(sess.StationID)
	if err != nil {
		return nil, err
	}
	tech, err := s.Store.Tech(sess.TechnicianID)
	if err != nil {
		return nil, err
	}
	dev, err := s.Store.Device(sess.DeviceID)
	if err != nil {
		return nil, err
	}

	exp := expectation{
		typ: "vehicle_proof", sessionID: sess.ID, vin: sess.VIN, purpose: sess.Purpose,
		keySlot: sess.KeySlot, newKey: sess.NewKeyPublic, serviceNonce: sess.ServerNonce,
	}

	ev := policy.Evidence{}
	detail := map[string]any{}
	var vehicleNonce []byte
	var consentHash []byte

	// ---- 1. vehicle proof (signed by the vehicle's secure element) --------
	if len(pb.VehicleProof) == 0 {
		detail["vehicle_proof"] = "missing"
	} else if vp, why := s.verifyVehicleProof(v, sess, pb.VehicleProof, now); why != "" {
		detail["vehicle_proof"] = why
	} else {
		ev.VehicleProofValid = true
		ev.VehicleProofFresh = true
		ev.PresentKeySlots = vp.PresentKeySlots
		// "Challenged" means an inserted key answered the cryptographic
		// challenge in this session, not merely that a radio transponder was
		// sensed nearby.
		ev.PresentKeyChallenged = len(vp.ChallengedKeySlots) > 0
		vehicleNonce = mustB64(vp.VehicleNonceB64)
		detail["vehicle_proof"] = "ok"
		detail["present_slots"] = vp.PresentKeySlots
		detail["challenged_slots"] = vp.ChallengedKeySlots
		detail["odometer_km"] = vp.OdometerKM
	}

	// ---- 2. owner consent (signed by the enrolled owner device) ----------
	if len(pb.OwnerConsent) > 0 {
		devID, perr := peekString(pb.OwnerConsent, "owner_device_id")
		bound, ok := v.FindBoundDevice(devID)
		var oc protocol.OwnerConsent
		sigOK, why := false, ""
		if perr == nil && ok {
			sigOK, why = s.openEnvelope(bound.PublicKey, protocol.DomainOwnerConsent, pb.OwnerConsent, &oc)
		}
		switch {
		case perr != nil:
			detail["owner_consent"] = "malformed envelope"
		case !ok:
			detail["owner_consent"] = "owner device not enrolled for this vehicle"
		case !sigOK:
			detail["owner_consent"] = why
		case strings.TrimSpace(oc.ApprovedKeyLabel) == "":
			detail["owner_consent"] = "consent does not name the approved key"
		case oc.OwnerSubject != v.OwnerSubject:
			// The phone signed as a different owner than the vehicle's
			// registered owner. A device bound to the vehicle but belonging to
			// a previous owner must not approve work on it.
			detail["owner_consent"] = "consenting device belongs to a different owner"
		case oc.StationID != st.ID:
			detail["owner_consent"] = "consent names a different station"
		case oc.DisplayedVIN != sess.VIN || oc.DisplayedStation == "":
			// What the owner was shown must match what we are authorizing.
			// Note: these display fields are self-asserted by the phone, so
			// this catches a lazy/confused client, not a hostile one. The
			// binding that actually matters is the signed session/VIN above;
			// the owner's *actual* view is protected by app code review and
			// attestation, out of scope for this service.
			detail["owner_consent"] = "consent display did not match the vehicle"
		case vehicleNonce != nil && !equalB64(oc.VehicleNonceB64, vehicleNonce):
			detail["owner_consent"] = "consent is bound to a different vehicle session"
		case s.checkHeader(oc.Header, exp, now) != "":
			detail["owner_consent"] = s.checkHeader(oc.Header, exp, now)
		default:
			ev.OwnerConsentValid = true
			ev.OwnerConsentFresh = true
			ev.OwnerDeviceBound = true
			// The vehicle attests over the exact consent envelope the
			// phone handed it, so hash the raw bytes as submitted.
			consentHash = vcrypto.Hash(pb.OwnerConsent)
			sess.OwnerDeviceID = bound.DeviceID
			sess.OwnerDevicePub = bound.PublicKey
			detail["owner_consent"] = "ok"
			detail["owner_device"] = bound.DeviceID
		}
	}

	// ---- 3. proximity attestation (signed by the VEHICLE) ----------------
	if len(pb.Proximity) > 0 {
		var pa protocol.ProximityAttestation
		sigOK, why := s.openEnvelope(v.HSMPublicKey, protocol.DomainProximity, pb.Proximity, &pa)
		switch {
		case !sigOK:
			detail["proximity"] = why
		case s.checkHeader(pa.Header, exp, now) != "":
			detail["proximity"] = s.checkHeader(pa.Header, exp, now)
		case vehicleNonce != nil && !equalB64(pa.VehicleNonceB64, vehicleNonce):
			detail["proximity"] = "attestation bound to a different vehicle session"
		case pa.RTTMicros > maxRTTMicros(pa.Channel) || pa.SampleCount < 3:
			detail["proximity"] = "round-trip too slow for the claimed channel (likely relayed)"
		case consentHash != nil && !equalB64(pa.OwnerConsentHashB64, consentHash):
			detail["proximity"] = "attestation does not cover the submitted consent"
		default:
			ev.ProximityValid = true
			ev.ProximityFresh = true
			detail["proximity"] = "ok"
			detail["rtt_us"] = pa.RTTMicros
			detail["channel"] = pa.Channel
		}
	}

	// ---- 4. station check-in (back-office signature, stored at ingest) ---
	if ci, err := s.Store.CheckIn(sess.CheckInID); err == nil {
		ev.CheckInValid = ci.VIN == sess.VIN && ci.StationID == sess.StationID && !ci.Revoked
		ev.CheckInFresh = ci.ValidAt(now)
		ev.CheckInAtStation = true
		detail["check_in"] = map[string]any{"valid": ev.CheckInValid, "fresh": ev.CheckInFresh}
	}

	// ---- 5. second-technician witness (different person AND device) -----
	if len(pb.Witness) > 0 {
		wDevID, perr := peekString(pb.Witness, "witness_device_id")
		wdev, derr := s.Store.Device(wDevID)
		switch {
		case perr != nil || derr != nil:
			detail["witness"] = "witness device unknown"
		default:
			var w protocol.WitnessAttestation
			sigOK, why := s.openEnvelope(wdev.PublicKey, protocol.DomainWitness, pb.Witness, &w)
			switch {
			case !sigOK:
				detail["witness"] = why
			case s.checkHeader(w.Header, exp, now) != "":
				detail["witness"] = s.checkHeader(w.Header, exp, now)
			case w.StationID != st.ID:
				detail["witness"] = "witness not from this station"
			case w.WitnessTechID == sess.TechnicianID || w.WitnessDeviceID == sess.DeviceID:
				detail["witness"] = "witness must be a different technician on a different device"
			case !w.Confirmed || w.ObservedVIN != sess.VIN:
				detail["witness"] = "witness did not confirm this VIN"
			default:
				ev.WitnessValid = true
				ev.WitnessDifferentPerson = true
				detail["witness"] = "ok"
				detail["witness_tech"] = w.WitnessTechID
			}
		}
	}

	// ---- 6. recovery claim (identity provider) --------------------------
	//
	// The cooling-off is tracked per vehicle, not per session, because a
	// session is deliberately short-lived while the cooling-off is
	// deliberately long. Presenting a valid claim for the first time starts
	// the clock; a later session for the same vehicle inherits it.
	if len(pb.RecoveryClaim) > 0 {
		var rc protocol.RecoveryClaim
		if why := s.verifyRecovery(&rc, pb.RecoveryClaim, sess, now); why != "" {
			detail["recovery_claim"] = why
		} else {
			ev.RecoveryClaimValid = true
			ev.RecoveryClaimFresh = true
			rec := s.startOrGetRecovery(sess.VIN, sess.StationID, v, now)
			sess.RecoveryStartedAt = rec.StartedAt
			sess.ContactsNotified = len(rec.Contacts)
			detail["recovery_claim"] = "ok"
			detail["recovery_id"] = rec.ID
			detail["contacts_notified"] = len(rec.Contacts)
		}
	}
	if ev.RecoveryClaimValid && !sess.RecoveryStartedAt.IsZero() {
		ev.CoolingOffElapsed = now.Sub(sess.RecoveryStartedAt) >= s.Cfg.RecoveryCoolingOff
		ev.OwnerContactsVetoed = s.vetoed(sess.VIN)
	}

	vCount, stCount := s.Store.HighRiskCounts(sess.VIN, sess.StationID, now)
	in := policy.Input{
		Purpose: sess.Purpose,
		KeySlot: sess.KeySlot,
		NewKey:  sess.NewKeyPublic,
		Facts: policy.Facts{
			Vehicle: v, Station: st, Tech: tech, Device: dev, Now: now,
			HighRiskTodayVehicle:  vCount,
			HighRiskTodayStation:  stCount,
			OwnerReportedGeo:      pb.OwnerReportedGeo,
			OwnerContactsNotified: sess.ContactsNotified,
		},
		Evidence: ev,
	}
	dec := policy.Evaluate(in, s.Cfg)
	sess.Decision = &dec
	s.Store.PutSession(sess)

	detail["tier"] = string(dec.Tier)
	detail["allow"] = dec.Allow
	detail["unmet"] = policy.UnmetCodes(dec)
	detail["reasons"] = dec.Reasons

	if !dec.Allow {
		sess.State = model.StateProven
		s.Store.PutSession(sess)
		s.audit("proofs.refused", sess.TechnicianID, sess.VIN, sess.StationID, sess.ID, detail)
		return &VerifyOutcome{
			Allowed: false, Tier: dec.Tier,
			Unmet: dec.Unmet, Reasons: dec.Reasons,
			DenyReason: "requirements outstanding",
			Details:    detail,
		}, nil
	}

	g, err := s.mintGrant(sess, v, st, tech, dev, vehicleNonce, dec, now)
	if err != nil {
		return nil, err
	}
	sess.State = model.StateGranted
	sess.GrantID = g.GrantID
	s.Store.PutSession(sess)
	s.Store.RecordGrant(sess.VIN, sess.StationID, dec.Tier, now)
	detail["grant_id"] = g.GrantID
	s.audit("grant.issued", sess.TechnicianID, sess.VIN, sess.StationID, sess.ID, detail)

	// The technician's handset now writes this key into the vehicle. The
	// vehicle verifies the grant itself; the service does not need to
	// confirm the write, but it expects a completion record.
	return &VerifyOutcome{Allowed: true, Tier: dec.Tier, Grant: g, Reasons: dec.Reasons, Details: detail}, nil
}

// --- grant construction ----------------------------------------------------

func (s *Service) mintGrant(sess *model.Session, v *model.Vehicle, st *model.Station,
	tech *model.Technician, dev *model.DiagnosticDevice, vehicleNonce []byte,
	dec model.Decision, now time.Time) (*protocol.Grant, error) {

	g := &protocol.Grant{}
	g.Typ = "grant"
	g.Ver = protocol.ProtocolVersion
	g.GrantID = vcrypto.RandomID()
	g.VIN = sess.VIN
	g.SessionID = sess.ID
	g.VehicleNonceB64 = protocol.EncodeB64(vehicleNonce)
	g.ServiceNonceB64 = protocol.EncodeB64(sess.ServerNonce)
	g.OwnerSubject = v.OwnerSubject
	g.OwnerDeviceID = sess.OwnerDeviceID
	if len(sess.OwnerDevicePub) > 0 {
		g.OwnerDevicePubB64 = protocol.EncodeB64(sess.OwnerDevicePub)
	}
	g.StationID = st.ID
	g.CheckInID = sess.CheckInID
	g.TechnicianID = tech.ID
	g.DeviceID = dev.ID
	g.Purpose = string(sess.Purpose)
	g.KeySlot = sess.KeySlot
	g.NewKeyPubB64 = protocol.EncodeB64(sess.NewKeyPublic)
	g.Tier = string(dec.Tier)
	g.PolicyVersion = dec.PolicyVersion
	g.Provisional = dec.Constraints.Provisional
	g.OwnerProximityRequiredPerUse = dec.Constraints.OwnerProximityRequiredPerUse
	g.MaxActivations = dec.Constraints.MaxActivations
	g.RevocableUntilMS = dec.Constraints.RevocableUntilMS
	g.IssuedAtMS = now.UnixMilli()
	g.NotAfterMS = dec.Constraints.NotAfterMS
	g.IssuerKeyID = s.Issuer.KeyID
	if err := protocol.SignGrant(s.Issuer.Private, g); err != nil {
		return nil, err
	}
	return g, nil
}

// --- verification helpers --------------------------------------------------

type expectation struct {
	typ          string
	sessionID    string
	vin          string
	purpose      model.Purpose
	keySlot      int
	newKey       []byte
	serviceNonce []byte
}

// openEnvelope verifies the signature over the raw payload and strictly
// decodes it. It never decodes into a caller-supplied struct before the
// signature passes.
func (s *Service) openEnvelope(pub ed25519.PublicKey, domain string, raw []byte, out any) (bool, string) {
	payload, sig, err := protocol.UnmarshalEnvelope(raw)
	if err != nil {
		return false, "malformed envelope"
	}
	if err := protocol.Open(pub, domain, payload, sig); err != nil {
		return false, "signature invalid"
	}
	if err := protocol.DecodeStrict(payload, out); err != nil {
		return false, "malformed payload"
	}
	return true, ""
}

func (s *Service) verifyVehicleProof(v *model.Vehicle, sess *model.Session, raw []byte, now time.Time) (*protocol.VehicleProof, string) {
	var vp protocol.VehicleProof
	if ok, why := s.openEnvelope(v.HSMPublicKey, protocol.DomainVehicleProof, raw, &vp); !ok {
		return nil, why
	}
	exp := expectation{
		typ: "vehicle_proof", sessionID: sess.ID, vin: sess.VIN, purpose: sess.Purpose,
		keySlot: sess.KeySlot, newKey: sess.NewKeyPublic, serviceNonce: sess.ServerNonce,
	}
	if why := s.checkHeader(vp.Header, exp, now); why != "" {
		return nil, why
	}
	// The vehicle must echo the service challenge it was asked to sign, so a
	// recorded proof from an earlier session cannot be replayed even if the
	// session ID somehow matched.
	if !equalB64(vp.ChallengeHashB64, vcrypto.Hash(sess.ServerNonce, []byte(sess.ID))) {
		return nil, "vehicle did not answer this session's challenge"
	}
	return &vp, ""
}

func (s *Service) verifyRecovery(rc *protocol.RecoveryClaim, raw []byte, sess *model.Session, now time.Time) string {
	keyID, err := peekString(raw, "provider_key_id")
	if err != nil {
		return "malformed claim"
	}
	pub, ok := s.RecoveryProviders[keyID]
	if !ok {
		return "unknown identity provider"
	}
	var tmp protocol.RecoveryClaim
	if ok, why := s.openEnvelope(pub, protocol.DomainRecovery, raw, &tmp); !ok {
		return why
	}
	if tmp.Ver != protocol.ProtocolVersion {
		return "unsupported protocol version"
	}
	if tmp.VIN != sess.VIN || tmp.StationID != sess.StationID {
		return "claim is for a different vehicle or station"
	}
	// A recovery claim is an in-person identity check, not a live handshake,
	// so it may legitimately be valid for a shift rather than minutes. We
	// still bound it, and we never accept one that has already expired.
	const maxClaimLifetime = 24 * time.Hour
	if tmp.ExpiresAtMS < now.UnixMilli() || tmp.ExpiresAtMS-tmp.VerifiedAtMS > int64(maxClaimLifetime/time.Millisecond) {
		return "claim expired or has an implausible lifetime"
	}
	if tmp.VerifiedAtMS > now.Add(s.ClockSkew).UnixMilli() {
		return "claim is from the future"
	}
	if strings.TrimSpace(tmp.IdentityDocRef) == "" || strings.TrimSpace(tmp.Method) == "" {
		return "claim lacks identity document reference"
	}
	*rc = tmp
	return ""
}

// checkHeader enforces session binding and freshness on a signed proof
// header. The message type is already pinned by the signature domain used to
// verify the envelope, so it is not re-checked here; every other field that
// ties the proof to *this* operation is.
func (s *Service) checkHeader(h protocol.Header, exp expectation, now time.Time) string {
	if h.Ver != protocol.ProtocolVersion {
		return "unsupported protocol version"
	}
	if h.SessionID != exp.sessionID {
		return "bound to a different session"
	}
	if h.VIN != exp.vin {
		return "bound to a different vehicle"
	}
	if h.Purpose != string(exp.purpose) {
		return "bound to a different purpose"
	}
	if h.KeySlot != exp.keySlot {
		return "bound to a different key slot"
	}
	if !equalB64(h.NewKeyPubB64, exp.newKey) {
		return "bound to a different new key"
	}
	if !equalB64(h.ServiceNonceB64, exp.serviceNonce) {
		return "does not bind the service nonce"
	}
	skew := s.ClockSkew.Milliseconds()
	if h.IssuedAtMS < now.UnixMilli()-skew || h.IssuedAtMS > now.Add(s.ClockSkew).UnixMilli() {
		return "timestamp outside the accepted window"
	}
	if h.ExpiresAtMS <= now.UnixMilli() {
		return "proof expired"
	}
	if h.ExpiresAtMS-h.IssuedAtMS > s.MaxProofLifetime.Milliseconds() {
		return "proof lifetime implausibly long"
	}
	return ""
}

// --- cooling-off, notification and veto -----------------------------------

// startOrGetRecovery returns the open recovery for a VIN, creating it and
// fanning out alerts to every registered contact on first call.
func (s *Service) startOrGetRecovery(vin, stationID string, v *model.Vehicle, now time.Time) *recovery {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.recoveries[vin]; ok {
		return rec
	}
	rec := &recovery{
		ID:        vcrypto.RandomID(),
		VIN:       vin,
		StationID: stationID,
		StartedAt: now,
		Vetoed:    map[string]bool{},
	}
	s.notify[rec.ID] = map[string]string{}
	for _, c := range v.OwnerContacts {
		if c == "" {
			continue
		}
		tok := vcrypto.RandomID()
		rec.Contacts = append(rec.Contacts, c)
		s.notify[rec.ID][c] = tok
		s.tokenIdx[tok] = rec.ID + "\x00" + c
	}
	s.recoveries[vin] = rec
	s.audit("recovery.started", "service", vin, stationID, rec.ID, map[string]any{
		"contacts_notified": len(rec.Contacts),
	})
	return rec
}

// VetoTokens returns the per-contact tokens for a vehicle's open recovery. In
// production these are delivered by SMS/email/push; here they are returned for
// the demo harness and tests.
func (s *Service) VetoTokens(vin string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	rec, ok := s.recoveries[vin]
	if !ok {
		return out
	}
	for k, v := range s.notify[rec.ID] {
		out[k] = v
	}
	return out
}

// Veto records a contact's refusal using the token they were sent. Any single
// registered contact can stop a high-risk recovery.
func (s *Service) Veto(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.tokenIdx[token]
	if !ok {
		return fmt.Errorf("%w: unknown veto token", ErrUnauthorized)
	}
	recID, contact, _ := strings.Cut(ref, "\x00")
	var vin string
	for v, rec := range s.recoveries {
		if rec.ID == recID {
			vin = v
			rec.Vetoed[contact] = true
		}
	}
	if vin == "" {
		return fmt.Errorf("%w: unknown veto token", ErrUnauthorized)
	}
	s.audit("recovery.vetoed", contact, vin, "", recID, map[string]any{"contact": contact})
	return nil
}

func (s *Service) vetoed(vin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recoveries[vin]
	return ok && len(rec.Vetoed) > 0
}

// --- other operations ------------------------------------------------------

// Cancel lets the technician abandon a session so it cannot be used later.
func (s *Service) Cancel(sessionID, technicianID string) error {
	sess, err := s.Store.Session(sessionID)
	if err != nil {
		return err
	}
	if sess.TechnicianID != technicianID {
		return ErrUnauthorized
	}
	s.settle(sess, model.StateCancelled, "cancelled by technician")
	return nil
}

// RevokeKey lets the owner disable a key slot without any station help. It is
// the standing remedy for a provisional key: the owner does not need to prove
// anything to the station, only to their own enrolled device.
func (s *Service) RevokeKey(revRaw []byte) error {
	var r protocol.KeyRevocation
	devID, err := peekString(revRaw, "owner_device_id")
	if err != nil {
		return fmt.Errorf("%w: malformed revocation", ErrProof)
	}
	payload, sig, err := protocol.UnmarshalEnvelope(revRaw)
	if err != nil {
		return fmt.Errorf("%w: malformed revocation", ErrProof)
	}
	// Decode untrusted JSON only to find the VIN/device, then verify.
	vin, err := peekString(revRaw, "vin")
	if err != nil {
		return fmt.Errorf("%w: malformed revocation", ErrProof)
	}
	v, err := s.Store.Vehicle(vin)
	if err != nil {
		return err
	}
	bound, ok := v.FindBoundDevice(devID)
	if !ok {
		return fmt.Errorf("%w: owner device not enrolled", ErrUnauthorized)
	}
	if err := protocol.Open(bound.PublicKey, protocol.DomainRevocation, payload, sig); err != nil {
		return fmt.Errorf("%w: signature invalid", ErrProof)
	}
	if err := protocol.DecodeStrict(payload, &r); err != nil {
		return fmt.Errorf("%w: malformed revocation", ErrProof)
	}
	if s.Store.SeenNonce("revoke:"+vin, r.NonceB64) {
		return ErrReplay
	}
	s.audit("key.revoked", devID, vin, "", "", map[string]any{
		"key_slot": r.KeySlot, "reason": r.Reason,
	})
	return nil
}

func (s *Service) settle(sess *model.Session, state model.SessionState, why string) {
	sess.State = state
	sess.DenyReason = why
	s.Store.PutSession(sess)
	s.audit("session."+string(state), sess.TechnicianID, sess.VIN, sess.StationID, sess.ID, map[string]any{
		"reason": why,
	})
}

func (s *Service) audit(kind, actor, vin, station, session string, detail map[string]any) {
	_, _ = s.Log.Append(kind, actor, vin, station, session, detail)
}

// --- small helpers ---------------------------------------------------------

func maxRTTMicros(channel string) int64 {
	switch channel {
	case "uwb":
		return 20_000 // 20 ms, generous for UWB
	case "ble":
		return 60_000 // 60 ms over BLE
	case "nfc":
		return 10_000
	default:
		return 0 // unknown channel never qualifies
	}
}

func peekString(raw []byte, field string) (string, error) {
	payload, _, err := protocol.UnmarshalEnvelope(raw)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := protocol.DecodeStrict(payload, &m); err != nil {
		return "", err
	}
	s, ok := m[field].(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%w: missing %s", ErrProof, field)
	}
	return s, nil
}

func mustB64(s string) []byte {
	b, _ := protocol.DecodeB64(s)
	return b
}

func equalB64(a string, b []byte) bool {
	ab, err := protocol.DecodeB64(a)
	if err != nil {
		return false
	}
	return vcrypto.Equal(ab, b)
}

func mustCanon(v any) []byte {
	b, err := canon.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
