// Package sim builds a realistic, fully wired world for the scenario tests:
// a manufacturer, two stations, technicians, handsets, owner phones, and
// vehicles whose secure elements sign in-process.
//
// It exists so that the tests exercise the real protocol end to end
// (canonical encoding, signatures, freshness, policy) rather than mocking
// the parts that matter.
package sim

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"example.com/vehicle-key-authz/internal/audit"
	"example.com/vehicle-key-authz/internal/model"
	"example.com/vehicle-key-authz/internal/policy"
	"example.com/vehicle-key-authz/internal/protocol"
	"example.com/vehicle-key-authz/internal/service"
	"example.com/vehicle-key-authz/internal/store"
	"example.com/vehicle-key-authz/internal/vcrypto"
)

// Clock is a controllable clock so freshness and cooling-off are testable.
type Clock struct{ T time.Time }

func (c *Clock) Now() time.Time          { return c.T }
func (c *Clock) Advance(d time.Duration) { c.T = c.T.Add(d) }

// Station is a station fixture with a real back-office key.
type Station struct {
	*model.Station
	BackOfficePriv ed25519.PrivateKey
}

// VehicleSim is a vehicle plus its secure element.
type VehicleSim struct {
	*model.Vehicle
	HSMPriv ed25519.PrivateKey
	// Online indicates the vehicle can reach the service. Offline vehicles
	// must self-authorize for low-risk operations.
	Online bool
}

// OwnerDevice is the owner's enrolled phone.
type OwnerDevice struct {
	ID      string
	Subject string
	Pub     ed25519.PublicKey
	Priv    ed25519.PrivateKey
	// Unlocked models whether the phone's biometric/passcode gate was
	// satisfied. A locked phone cannot produce consent.
	Unlocked bool
}

// Device is a diagnostic handset plus its mTLS key.
type Device struct {
	ID      string
	Pub     ed25519.PublicKey
	Priv    ed25519.PrivateKey
	Station string
}

// World is the wired simulation.
type World struct {
	T     *testing.T
	Clock *Clock
	Store *store.Memory
	Svc   *service.Service
	Log   *audit.Log

	Station  *Station
	Station2 *Station
	Vehicle  *VehicleSim
	Owner    *OwnerDevice
	Tech     *model.Technician
	Witness  *model.Technician
	Device   *Device
	WDevice  *Device

	allVehicles []*VehicleSim
}

// New builds a world with one vehicle, one station, one owner, a primary and
// a witness technician, and two handsets.
func New(t *testing.T) *World {
	t.Helper()
	clock := &Clock{T: time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}

	issPub, issPriv, err := vcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	st := store.New()
	log := audit.NewLog(nil, clock.Now)
	svc := service.New(st, policy.DefaultConfig(), log, service.IssuerKey{
		KeyID: "issuer-2026", Private: issPriv, Public: issPub,
	})
	svc.Now = clock.Now
	svc.SessionTTL = 10 * time.Minute

	w := &World{T: t, Clock: clock, Store: st, Svc: svc, Log: log}

	w.Station = w.newStation("ST-001", "Downtown Authorized Service", true, false)
	w.Station2 = w.newStation("ST-002", "Harbor Auto Care", true, false)

	w.Tech = &model.Technician{ID: "TECH-A", StationID: "ST-001", Name: "A. Rivera", Active: true,
		DeviceIDs: []string{"DEV-1"}}
	w.Witness = &model.Technician{ID: "TECH-B", StationID: "ST-001", Name: "B. Chen", Active: true,
		DeviceIDs: []string{"DEV-2"}}
	w.Device = w.newDevice("DEV-1", "ST-001")
	w.WDevice = w.newDevice("DEV-2", "ST-001")
	st.PutTech(w.Tech)
	st.PutTech(w.Witness)

	w.Owner = newOwnerDevice("OWN-1", "owner-subject-1")
	w.Vehicle = w.newVehicle("VIN00000000000001", "owner-subject-1", 2, 5)
	w.BindOwner()
	return w
}

func (w *World) newStation(id, name string, audited, watch bool) *Station {
	pub, priv, err := vcrypto.GenerateKey()
	if err != nil {
		w.T.Fatal(err)
	}
	m := &model.Station{
		ID: id, Name: name, Status: model.StationActive,
		Geo:                 model.Geo{Lat: 37.7749, Lon: -122.4194, AccuracyM: 10},
		BackOfficePublicKey: pub,
		TwoStaffAttested:    audited,
		Watchlisted:         watch,
	}
	w.Store.PutStation(m)
	return &Station{Station: m, BackOfficePriv: priv}
}

func (w *World) newDevice(id, stationID string) *Device {
	pub, priv, err := vcrypto.GenerateKey()
	if err != nil {
		w.T.Fatal(err)
	}
	w.Store.PutDevice(&model.DiagnosticDevice{ID: id, StationID: stationID, PublicKey: pub})
	return &Device{ID: id, Pub: pub, Priv: priv, Station: stationID}
}

func newOwnerDevice(id, subject string) *OwnerDevice {
	pub, priv, err := vcrypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return &OwnerDevice{ID: id, Subject: subject, Pub: pub, Priv: priv, Unlocked: true}
}

func (w *World) newVehicle(vin, owner string, keys, maxKeys int) *VehicleSim {
	pub, priv, err := vcrypto.GenerateKey()
	if err != nil {
		w.T.Fatal(err)
	}
	v := &model.Vehicle{
		VIN: vin, HSMPublicKey: pub, OwnerSubject: owner,
		OwnerContacts:  []string{"+15550001111", "backup@example.com"},
		MaxKeys:        maxKeys,
		Status:         model.VehicleActive,
		OwnershipSince: w.Clock.T.Add(-3 * 365 * 24 * time.Hour),
	}
	for i := 0; i < keys; i++ {
		kpub, _, _ := vcrypto.GenerateKey()
		v.Keys = append(v.Keys, model.KeyRecord{
			Slot: i + 1, PublicKey: kpub, Label: fmt.Sprintf("key-%d", i+1),
			AddedAt: w.Clock.T.Add(-24 * time.Hour), LastSeenAt: w.Clock.T,
		})
	}
	w.Store.PutVehicle(v)
	return &VehicleSim{Vehicle: v, HSMPriv: priv, Online: true}
}

// CheckIn has the station back office sign a check-in and submits it to the
// service, exercising the real ingest path (signature verified against the
// station's back-office key).
func (w *World) CheckIn(st *Station, v *VehicleSim, ttl time.Duration) *model.CheckIn {
	w.T.Helper()
	ci := protocol.CheckInAssertion{
		Typ: "check_in", Ver: protocol.ProtocolVersion,
		CheckInID:   vcrypto.RandomID(),
		VIN:         v.VIN,
		StationID:   st.ID,
		Bay:         "bay-3",
		RepairRef:   "RO-" + vcrypto.RandomID()[:8],
		AdvisorID:   "ADV-1",
		ArrivedAtMS: w.Clock.T.UnixMilli(),
		ExpiresAtMS: w.Clock.T.Add(ttl).UnixMilli(),
		IssuedAtMS:  w.Clock.T.UnixMilli(),
		GeofenceLat: st.Geo.Lat, GeofenceLon: st.Geo.Lon, GeofenceRadiusM: 200,
	}
	raw, err := protocol.Seal(st.BackOfficePriv, protocol.DomainCheckIn, ci)
	if err != nil {
		w.T.Fatal(err)
	}
	rec, err := w.Svc.IngestCheckIn(raw)
	if err != nil {
		w.T.Fatalf("sim: ingest check-in: %v", err)
	}
	return rec
}

// BindOwner enrolls the owner device on the vehicle.
func (w *World) BindOwner() {
	w.Vehicle.BoundDevices = append(w.Vehicle.BoundDevices, model.BoundDevice{
		DeviceID: w.Owner.ID, PublicKey: w.Owner.Pub, Subject: w.Owner.Subject,
		EnrolledAt: w.Clock.T.Add(-100 * 24 * time.Hour),
	})
}

// VehicleNonce derives the vehicle's own nonce from the service challenge.
func (w *World) VehicleNonce(sess *service.OpenResult) []byte {
	b, _ := protocol.DecodeB64(sess.ServiceNonceB64)
	return vcrypto.Hash(b, []byte("vehicle-nonce"))
}

// Header builds a proof header bound to a session.
func (w *World) Header(typ string, sess *service.OpenResult, purpose model.Purpose, slot int, newKey []byte) protocol.Header {
	now := w.Clock.T
	return protocol.Header{
		Typ: typ, Ver: protocol.ProtocolVersion,
		SessionID: sess.SessionID, VIN: sess.VIN, Purpose: string(purpose),
		KeySlot: slot, NewKeyPubB64: protocol.EncodeB64(newKey),
		ServiceNonceB64: sess.ServiceNonceB64,
		VehicleNonceB64: protocol.EncodeB64(w.VehicleNonce(sess)),
		IssuedAtMS:      now.UnixMilli(),
		ExpiresAtMS:     now.Add(5 * time.Minute).UnixMilli(),
	}
}

// VehicleProof has the vehicle secure element sign the challenge.
func (w *World) VehicleProof(sess *service.OpenResult, purpose model.Purpose, slot int, newKey []byte,
	present, challenged []int) []byte {
	w.T.Helper()
	hdr := w.Header("vehicle_proof", sess, purpose, slot, newKey)
	sn, _ := protocol.DecodeB64(sess.ServiceNonceB64)
	vp := protocol.VehicleProof{
		Header: hdr, HSMSerial: "HSM-" + w.Vehicle.VIN[3:9],
		PresentKeySlots: present, ChallengedKeySlots: challenged,
		ChallengeHashB64: protocol.EncodeB64(vcrypto.Hash(sn, []byte(sess.SessionID))),
		OdometerKM:       42113, FirmwareVersion: "4.2.0",
	}
	raw, err := protocol.Seal(w.Vehicle.HSMPriv, protocol.DomainVehicleProof, vp)
	if err != nil {
		w.T.Fatal(err)
	}
	return raw
}

// OwnerConsent has the owner phone sign approval. A locked phone cannot.
func (w *World) OwnerConsent(sess *service.OpenResult, purpose model.Purpose, slot int, newKey []byte,
	label, stationID string) []byte {
	w.T.Helper()
	if !w.Owner.Unlocked {
		w.T.Fatal("sim: owner phone is locked; UI would not produce consent")
	}
	hdr := w.Header("owner_consent", sess, purpose, slot, newKey)
	oc := protocol.OwnerConsent{
		Header: hdr, StationID: stationID, OwnerDeviceID: w.Owner.ID,
		OwnerSubject: w.Owner.Subject, ApprovedKeyLabel: label,
		ApprovedSlots: []int{slot}, ConsentMethod: "face_id",
		DisplayedStation: "Authorized Service", DisplayedVIN: sess.VIN,
	}
	raw, err := protocol.Seal(w.Owner.Priv, protocol.DomainOwnerConsent, oc)
	if err != nil {
		w.T.Fatal(err)
	}
	return raw
}

// Proximity has the VEHICLE sign that the owner phone was physically near.
func (w *World) Proximity(sess *service.OpenResult, purpose model.Purpose, slot int, newKey []byte,
	consent []byte, rttMicros int64, channel string) []byte {
	w.T.Helper()
	hdr := w.Header("proximity", sess, purpose, slot, newKey)
	pa := protocol.ProximityAttestation{
		Header: hdr, OwnerDeviceID: w.Owner.ID,
		OwnerDevicePubB64:   protocol.EncodeB64(w.Owner.Pub),
		OwnerConsentHashB64: protocol.EncodeB64(vcrypto.Hash(consent)),
		Channel:             channel, RTTMicros: rttMicros, DistanceUpperCMM: 30, SampleCount: 8,
	}
	raw, err := protocol.Seal(w.Vehicle.HSMPriv, protocol.DomainProximity, pa)
	if err != nil {
		w.T.Fatal(err)
	}
	return raw
}

// WitnessProof has the second technician's handset sign.
func (w *World) WitnessProof(sess *service.OpenResult, purpose model.Purpose, slot int, newKey []byte) []byte {
	w.T.Helper()
	hdr := w.Header("witness", sess, purpose, slot, newKey)
	wa := protocol.WitnessAttestation{
		Header: hdr, StationID: w.WDevice.Station, WitnessTechID: w.Witness.ID,
		WitnessDeviceID: w.WDevice.ID, WitnessDevicePubB64: protocol.EncodeB64(w.WDevice.Pub),
		ObservedVIN: sess.VIN, Confirmed: true,
	}
	raw, err := protocol.Seal(w.WDevice.Priv, protocol.DomainWitness, wa)
	if err != nil {
		w.T.Fatal(err)
	}
	return raw
}

// Open opens a session for the vehicle's current check-in.
func (w *World) Open(purpose model.Purpose, slot int, newKey []byte, ci *model.CheckIn) *service.OpenResult {
	w.T.Helper()
	res, err := w.Svc.OpenSession(service.OpenRequest{
		DeviceID: w.Device.ID, TechnicianID: w.Tech.ID, VIN: w.Vehicle.VIN,
		Purpose: purpose, KeySlot: slot, NewKeyPubB64: protocol.EncodeB64(newKey), CheckInID: ci.ID,
	})
	if err != nil {
		w.T.Fatalf("sim: open session: %v", err)
	}
	return res
}

// NewKey makes a throwaway keypair for the key being programmed.
func NewKey() (pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	pub, priv, err := vcrypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// --- multi-vehicle helpers (used by rate-limit and fleet scenarios) --------

// NewVehicleSim creates and registers an additional vehicle with no keys and
// binds the world's owner device to it.
func (w *World) NewVehicleSim() *VehicleSim {
	w.T.Helper()
	vin := fmt.Sprintf("VIN%014d", len(w.allVehicles)+2)
	v := w.newVehicle(vin, w.Owner.Subject, 0, 5)
	w.allVehicles = append(w.allVehicles, v)
	w.BindOwnerTo(v)
	return v
}

// BindOwnerTo enrolls the owner device on a specific vehicle.
func (w *World) BindOwnerTo(v *VehicleSim) {
	v.BoundDevices = append(v.BoundDevices, model.BoundDevice{
		DeviceID: w.Owner.ID, PublicKey: w.Owner.Pub, Subject: w.Owner.Subject,
		EnrolledAt: w.Clock.T.Add(-100 * 24 * time.Hour),
	})
}

// OpenFor opens a session for a specific vehicle.
func (w *World) OpenFor(v *VehicleSim, purpose model.Purpose, slot int, newKey []byte, ci *model.CheckIn) *service.OpenResult {
	w.T.Helper()
	res, err := w.Svc.OpenSession(service.OpenRequest{
		DeviceID: w.Device.ID, TechnicianID: w.Tech.ID, VIN: v.VIN,
		Purpose: purpose, KeySlot: slot, NewKeyPubB64: protocol.EncodeB64(newKey), CheckInID: ci.ID,
	})
	if err != nil {
		w.T.Fatalf("sim: open session: %v", err)
	}
	return res
}

// VehicleProofFor has a specific vehicle's secure element sign the challenge.
func (w *World) VehicleProofFor(v *VehicleSim, sess *service.OpenResult, purpose model.Purpose,
	slot int, newKey []byte, present, challenged []int) []byte {
	w.T.Helper()
	hdr := w.Header("vehicle_proof", sess, purpose, slot, newKey)
	sn, _ := protocol.DecodeB64(sess.ServiceNonceB64)
	vp := protocol.VehicleProof{
		Header: hdr, HSMSerial: "HSM-" + v.VIN[3:9],
		PresentKeySlots: present, ChallengedKeySlots: challenged,
		ChallengeHashB64: protocol.EncodeB64(vcrypto.Hash(sn, []byte(sess.SessionID))),
		OdometerKM:       42113, FirmwareVersion: "4.2.0",
	}
	raw, err := protocol.Seal(v.HSMPriv, protocol.DomainVehicleProof, vp)
	if err != nil {
		w.T.Fatal(err)
	}
	return raw
}

// ProximityFor is Proximity for a specific vehicle's secure element.
func (w *World) ProximityFor(v *VehicleSim, sess *service.OpenResult, purpose model.Purpose, slot int,
	newKey, consent []byte, rttMicros int64, channel string) []byte {
	w.T.Helper()
	hdr := w.Header("proximity", sess, purpose, slot, newKey)
	pa := protocol.ProximityAttestation{
		Header: hdr, OwnerDeviceID: w.Owner.ID,
		OwnerDevicePubB64:   protocol.EncodeB64(w.Owner.Pub),
		OwnerConsentHashB64: protocol.EncodeB64(vcrypto.Hash(consent)),
		Channel:             channel, RTTMicros: rttMicros, DistanceUpperCMM: 30, SampleCount: 8,
	}
	raw, err := protocol.Seal(v.HSMPriv, protocol.DomainProximity, pa)
	if err != nil {
		w.T.Fatal(err)
	}
	return raw
}

// WitnessDevicePub / Priv expose the second handset key for ad-hoc tests.
func (w *World) WitnessDevicePub() ed25519.PublicKey   { return w.WDevice.Pub }
func (w *World) WitnessDevicePriv() ed25519.PrivateKey { return w.WDevice.Priv }
