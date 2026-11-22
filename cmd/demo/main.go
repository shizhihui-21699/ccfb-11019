// Command demo runs the authorization flows end to end and prints what an
// investigator would want to see: for each situation, whether a key may be
// made, and if not, exactly which physical fact was missing.
//
// It uses a fixed clock and in-process keys, so the output is deterministic.
package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"example.com/vehicle-key-authz/internal/audit"
	"example.com/vehicle-key-authz/internal/model"
	"example.com/vehicle-key-authz/internal/policy"
	"example.com/vehicle-key-authz/internal/protocol"
	"example.com/vehicle-key-authz/internal/service"
	"example.com/vehicle-key-authz/internal/store"
	"example.com/vehicle-key-authz/internal/vcrypto"
)

type world struct {
	clock   time.Time
	store   *store.Memory
	svc     *service.Service
	log     *audit.Log
	station *model.Station
	stPriv  ed25519.PrivateKey
	vehicle *model.Vehicle
	vPriv   ed25519.PrivateKey
	owner   *model.BoundDevice
	oPriv   ed25519.PrivateKey
	tech    *model.Technician
	wit     *model.Technician
	dev     *model.DiagnosticDevice
	dPriv   ed25519.PrivateKey
	wdev    *model.DiagnosticDevice
	wPriv   ed25519.PrivateKey
}

func main() {
	w := build()
	fmt.Println("=== Vehicle key authorization: end-to-end scenarios ===")

	w.happyPath()
	w.offlineAddKey()
	w.parkingLotTheft()
	w.insiderNoOwner()
	w.relayedConsent()
	w.lostEverything()
	w.ownerRevokes()
	w.auditIntegrity()
}

func build() *world {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	w := &world{clock: now, store: store.New()}
	w.log = audit.NewLog(nil, func() time.Time { return w.clock })

	issPub, issPriv, _ := vcrypto.GenerateKey()
	w.svc = service.New(w.store, policy.DefaultConfig(), w.log, service.IssuerKey{
		KeyID: "issuer-2026", Private: issPriv, Public: issPub,
	})
	w.svc.Now = func() time.Time { return w.clock }

	stPub, stPriv, _ := vcrypto.GenerateKey()
	w.station = &model.Station{
		ID: "ST-001", Name: "Downtown Authorized Service", Status: model.StationActive,
		Geo:                 model.Geo{Lat: 37.7749, Lon: -122.4194, AccuracyM: 10},
		BackOfficePublicKey: stPub, TwoStaffAttested: true,
	}
	w.stPriv = stPriv
	w.store.PutStation(w.station)

	vPub, vPriv, _ := vcrypto.GenerateKey()
	oPub, oPriv, _ := vcrypto.GenerateKey()
	w.vPriv, w.oPriv = vPriv, oPriv
	w.owner = &model.BoundDevice{DeviceID: "OWN-1", PublicKey: oPub, Subject: "owner-1",
		EnrolledAt: now.Add(-100 * 24 * time.Hour)}
	w.vehicle = &model.Vehicle{
		VIN: "VIN00000000000001", HSMPublicKey: vPub, OwnerSubject: "owner-1",
		BoundDevices:   []model.BoundDevice{*w.owner},
		OwnerContacts:  []string{"+15550001111", "spouse@example.com"},
		MaxKeys:        5,
		Status:         model.VehicleActive,
		OwnershipSince: now.Add(-3 * 365 * 24 * time.Hour),
	}
	for i := 0; i < 2; i++ {
		pub, _, _ := vcrypto.GenerateKey()
		w.vehicle.Keys = append(w.vehicle.Keys, model.KeyRecord{Slot: i + 1, PublicKey: pub, Label: fmt.Sprintf("key-%d", i+1)})
	}
	w.store.PutVehicle(w.vehicle)

	dPub, dPriv, _ := vcrypto.GenerateKey()
	w.dev = &model.DiagnosticDevice{ID: "DEV-1", StationID: "ST-001", PublicKey: dPub}
	w.dPriv = dPriv
	w.store.PutDevice(w.dev)

	wdPub, wdPriv, _ := vcrypto.GenerateKey()
	w.wdev = &model.DiagnosticDevice{ID: "DEV-2", StationID: "ST-001", PublicKey: wdPub}
	w.wPriv = wdPriv
	w.store.PutDevice(w.wdev)

	w.tech = &model.Technician{ID: "TECH-A", StationID: "ST-001", Name: "A. Rivera", Active: true, DeviceIDs: []string{"DEV-1"}}
	w.wit = &model.Technician{ID: "TECH-B", StationID: "ST-001", Name: "B. Chen", Active: true, DeviceIDs: []string{"DEV-2"}}
	w.store.PutTech(w.tech)
	w.store.PutTech(w.wit)
	return w
}

func (w *world) checkIn(ttl time.Duration) *model.CheckIn {
	assertion := protocol.CheckInAssertion{
		Typ: "check_in", Ver: protocol.ProtocolVersion, CheckInID: vcrypto.RandomID(),
		VIN: w.vehicle.VIN, StationID: "ST-001", Bay: "bay-3", RepairRef: "RO-1", AdvisorID: "ADV-1",
		ArrivedAtMS: w.clock.UnixMilli(), ExpiresAtMS: w.clock.Add(ttl).UnixMilli(),
		IssuedAtMS: w.clock.UnixMilli(), GeofenceLat: w.station.Geo.Lat, GeofenceLon: w.station.Geo.Lon,
		GeofenceRadiusM: 200,
	}
	raw, _ := protocol.Seal(w.stPriv, protocol.DomainCheckIn, assertion)
	ci, err := w.svc.IngestCheckIn(raw)
	if err != nil {
		panic(err)
	}
	return ci
}

func (w *world) open(purpose model.Purpose, slot int, pub []byte, ci *model.CheckIn) *service.OpenResult {
	res, err := w.svc.OpenSession(service.OpenRequest{
		DeviceID: "DEV-1", TechnicianID: "TECH-A", VIN: w.vehicle.VIN,
		Purpose: purpose, KeySlot: slot, NewKeyPubB64: protocol.EncodeB64(pub), CheckInID: ci.ID,
	})
	if err != nil {
		panic(err)
	}
	return res
}

func (w *world) header(typ string, s *service.OpenResult, purpose model.Purpose, slot int, newKey []byte) protocol.Header {
	sn, _ := protocol.DecodeB64(s.ServiceNonceB64)
	return protocol.Header{
		Typ: typ, Ver: protocol.ProtocolVersion, SessionID: s.SessionID, VIN: s.VIN,
		Purpose: string(purpose), KeySlot: slot, NewKeyPubB64: protocol.EncodeB64(newKey),
		ServiceNonceB64: s.ServiceNonceB64,
		VehicleNonceB64: protocol.EncodeB64(vcrypto.Hash(sn, []byte("vehicle-nonce"))),
		IssuedAtMS:      w.clock.UnixMilli(), ExpiresAtMS: w.clock.Add(5 * time.Minute).UnixMilli(),
	}
}

func (w *world) vehicleProof(s *service.OpenResult, purpose model.Purpose, slot int, newKey []byte) []byte {
	h := w.header("vehicle_proof", s, purpose, slot, newKey)
	sn, _ := protocol.DecodeB64(s.ServiceNonceB64)
	raw, _ := protocol.Seal(w.vPriv, protocol.DomainVehicleProof, protocol.VehicleProof{
		Header: h, HSMSerial: "HSM-0001", PresentKeySlots: []int{1, 2}, ChallengedKeySlots: []int{1},
		ChallengeHashB64: protocol.EncodeB64(vcrypto.Hash(sn, []byte(s.SessionID))),
		OdometerKM:       42113, FirmwareVersion: "4.2.0",
	})
	return raw
}

func (w *world) noKeyVehicleProof(s *service.OpenResult, purpose model.Purpose, slot int, newKey []byte) []byte {
	h := w.header("vehicle_proof", s, purpose, slot, newKey)
	sn, _ := protocol.DecodeB64(s.ServiceNonceB64)
	raw, _ := protocol.Seal(w.vPriv, protocol.DomainVehicleProof, protocol.VehicleProof{
		Header: h, HSMSerial: "HSM-0001", ChallengeHashB64: protocol.EncodeB64(vcrypto.Hash(sn, []byte(s.SessionID))),
		OdometerKM: 42113, FirmwareVersion: "4.2.0",
	})
	return raw
}

func (w *world) consent(s *service.OpenResult, purpose model.Purpose, slot int, newKey []byte) []byte {
	h := w.header("owner_consent", s, purpose, slot, newKey)
	raw, _ := protocol.Seal(w.oPriv, protocol.DomainOwnerConsent, protocol.OwnerConsent{
		Header: h, StationID: "ST-001", OwnerDeviceID: "OWN-1", OwnerSubject: "owner-1",
		ApprovedKeyLabel: "spare key", ApprovedSlots: []int{slot}, ConsentMethod: "face_id",
		DisplayedStation: "Downtown Authorized Service", DisplayedVIN: s.VIN,
	})
	return raw
}

func (w *world) proximity(s *service.OpenResult, purpose model.Purpose, slot int, newKey, consent []byte, rtt int64) []byte {
	h := w.header("proximity", s, purpose, slot, newKey)
	raw, _ := protocol.Seal(w.vPriv, protocol.DomainProximity, protocol.ProximityAttestation{
		Header: h, OwnerDeviceID: "OWN-1", OwnerDevicePubB64: protocol.EncodeB64(w.owner.PublicKey),
		OwnerConsentHashB64: protocol.EncodeB64(vcrypto.Hash(consent)),
		Channel:             "ble", RTTMicros: rtt, SampleCount: 8, DistanceUpperCMM: 30,
	})
	return raw
}

func (w *world) witness(s *service.OpenResult, purpose model.Purpose, slot int, newKey []byte) []byte {
	h := w.header("witness", s, purpose, slot, newKey)
	raw, _ := protocol.Seal(w.wPriv, protocol.DomainWitness, protocol.WitnessAttestation{
		Header: h, StationID: "ST-001", WitnessTechID: "TECH-B", WitnessDeviceID: "DEV-2",
		ObservedVIN: s.VIN, Confirmed: true,
	})
	return raw
}

func (w *world) report(title string, out *service.VerifyOutcome, err error) {
	fmt.Printf("\n--- %s\n", title)
	if err != nil {
		fmt.Printf("    error: %v\n", err)
		return
	}
	if out.Allowed {
		fmt.Printf("    ALLOWED  tier=%s provisional=%v per-use-proximity=%v max-uses=%d\n",
			out.Tier, out.Grant.Provisional, out.Grant.OwnerProximityRequiredPerUse, out.Grant.MaxActivations)
		fmt.Printf("    grant %s signed by %s\n", shortID(out.Grant.GrantID), out.Grant.IssuerKeyID)
	} else {
		fmt.Printf("    DENIED   tier=%s\n", out.Tier)
		for _, u := range out.Unmet {
			fmt.Printf("      missing: %s\n", u)
		}
	}
	for k, v := range out.Details {
		if v != "ok" && k != "reasons" && k != "unmet" && k != "allow" && k != "tier" {
			fmt.Printf("      %s: %v\n", k, v)
		}
	}
}

func (w *world) happyPath() {
	pub, _, _ := vcrypto.GenerateKey()
	ci := w.checkIn(30 * time.Minute)
	s := w.open(model.PurposeAddKey, 3, pub, ci)
	c := w.consent(s, model.PurposeAddKey, 3, pub)
	out, err := w.svc.SubmitProofs(service.ProofBundle{
		SessionID: s.SessionID, VehicleProof: w.vehicleProof(s, model.PurposeAddKey, 3, pub),
		OwnerConsent: c, Proximity: w.proximity(s, model.PurposeAddKey, 3, pub, c, 8_000),
	})
	w.report("Normal add-key: car in the bay, owner standing there with their phone", out, err)
}

func (w *world) offlineAddKey() {
	pub, _, _ := vcrypto.GenerateKey()
	ci := w.checkIn(30 * time.Minute)
	s := w.open(model.PurposeAddKey, 4, pub, ci)
	// Owner approves from the app at home: signed consent, but no proximity
	// attestation (their phone is not at the car). A second technician on a
	// different handset witnesses the physical work.
	c := w.consent(s, model.PurposeAddKey, 4, pub)
	out, err := w.svc.SubmitProofs(service.ProofBundle{
		SessionID: s.SessionID, VehicleProof: w.vehicleProof(s, model.PurposeAddKey, 4, pub),
		OwnerConsent: c, Witness: w.witness(s, model.PurposeAddKey, 4, pub),
	})
	w.report("Fleet drop-off: owner approves remotely, second technician witnesses", out, err)
}

func (w *world) parkingLotTheft() {
	// The exact case: stolen handset + stolen station account, car in a lot.
	pub, _, _ := vcrypto.GenerateKey()
	ci := w.checkIn(30 * time.Minute)
	s := w.open(model.PurposeReplaceLost, 1, pub, ci)
	out, err := w.svc.SubmitProofs(service.ProofBundle{SessionID: s.SessionID})
	w.report("ATTACK: stolen handset and station login, car in a public car park", out, err)
}

func (w *world) insiderNoOwner() {
	pub, _, _ := vcrypto.GenerateKey()
	ci := w.checkIn(8 * time.Hour)
	s := w.open(model.PurposeAddKey, 3, pub, ci)
	out, err := w.svc.SubmitProofs(service.ProofBundle{
		SessionID: s.SessionID, VehicleProof: w.vehicleProof(s, model.PurposeAddKey, 3, pub),
	})
	w.report("ATTACK: insider technician, car genuinely in the shop, owner never approved", out, err)
}

func (w *world) relayedConsent() {
	pub, _, _ := vcrypto.GenerateKey()
	ci := w.checkIn(8 * time.Hour)
	s := w.open(model.PurposeAddKey, 3, pub, ci)
	c := w.consent(s, model.PurposeAddKey, 3, pub)
	out, err := w.svc.SubmitProofs(service.ProofBundle{
		SessionID: s.SessionID, VehicleProof: w.vehicleProof(s, model.PurposeAddKey, 3, pub),
		OwnerConsent: c, Proximity: w.proximity(s, model.PurposeAddKey, 3, pub, c, 450_000),
	})
	w.report("ATTACK: genuine owner approval, but relayed from 40 km away over the internet", out, err)
}

func (w *world) lostEverything() {
	pub, _, _ := vcrypto.GenerateKey()
	w.vehicle.Keys = nil
	w.vehicle.BoundDevices = nil
	provPub, provPriv, _ := vcrypto.GenerateKey()
	w.svc.RecoveryProviders["kyc"] = provPub

	ci := w.checkIn(4 * time.Hour)
	s := w.open(model.PurposeReplaceLost, 1, pub, ci)
	claimRaw, _ := protocol.Seal(provPriv, protocol.DomainRecovery, protocol.RecoveryClaim{
		Typ: "recovery", Ver: protocol.ProtocolVersion, ClaimID: "C1", VIN: w.vehicle.VIN,
		StationID: "ST-001", OwnerSubject: "owner-1", IdentityDocRef: "PASSPORT-****1234",
		Method: "in_person_document_check", VerifiedAtMS: w.clock.UnixMilli(),
		ExpiresAtMS: w.clock.Add(30 * time.Minute).UnixMilli(), ProviderKeyID: "kyc",
	})
	out, err := w.svc.SubmitProofs(service.ProofBundle{
		SessionID: s.SessionID, VehicleProof: w.noKeyVehicleProof(s, model.PurposeReplaceLost, 1, pub),
		Witness: w.witness(s, model.PurposeReplaceLost, 1, pub), RecoveryClaim: claimRaw,
	})
	w.report("Owner lost every key AND their phone: identity check, cooling-off starts", out, err)
	fmt.Printf("      (all registered contacts were alerted: %d)\n", len(w.svc.VetoTokens(w.vehicle.VIN)))

	// After the cooling-off, in a fresh session.
	w.clock = w.clock.Add(w.svc.Cfg.RecoveryCoolingOff + time.Minute)
	ci2 := w.checkIn(4 * time.Hour)
	s2 := w.open(model.PurposeReplaceLost, 1, pub, ci2)
	claim2, _ := protocol.Seal(provPriv, protocol.DomainRecovery, protocol.RecoveryClaim{
		Typ: "recovery", Ver: protocol.ProtocolVersion, ClaimID: "C1", VIN: w.vehicle.VIN,
		StationID: "ST-001", OwnerSubject: "owner-1", IdentityDocRef: "PASSPORT-****1234",
		Method: "in_person_document_check", VerifiedAtMS: w.clock.UnixMilli(),
		ExpiresAtMS: w.clock.Add(30 * time.Minute).UnixMilli(), ProviderKeyID: "kyc",
	})
	out, err = w.svc.SubmitProofs(service.ProofBundle{
		SessionID: s2.SessionID, VehicleProof: w.noKeyVehicleProof(s2, model.PurposeReplaceLost, 1, pub),
		Witness: w.witness(s2, model.PurposeReplaceLost, 1, pub), RecoveryClaim: claim2,
	})
	w.report("...same request after the cooling-off, no veto received", out, err)
}

func (w *world) ownerRevokes() {
	// This scenario is about a normally-enrolled owner phone, so restore the
	// binding the recovery scenario deliberately removed.
	w.vehicle.BoundDevices = []model.BoundDevice{*w.owner}
	raw, _ := protocol.Seal(w.oPriv, protocol.DomainRevocation, protocol.KeyRevocation{
		Typ: "revocation", Ver: protocol.ProtocolVersion, VIN: w.vehicle.VIN, KeySlot: 1,
		Reason: "this key was not mine", OwnerDeviceID: "OWN-1",
		RevokedAtMS: w.clock.UnixMilli(), NonceB64: vcrypto.RandomID(),
	})
	err := w.svc.RevokeKey(raw)
	fmt.Printf("\n--- Owner revokes a suspicious key from their own phone\n")
	if err != nil {
		fmt.Printf("    error: %v\n", err)
	} else {
		fmt.Printf("    revoked slot 1 with no station involvement\n")
	}
}

func (w *world) auditIntegrity() {
	entries := w.log.Entries()
	fmt.Printf("\n--- Audit log\n")
	fmt.Printf("    %d entries, chain verifies: %v\n", len(entries), w.log.Verify() == nil)
	for _, e := range entries {
		switch e.Kind {
		case "grant.issued", "proofs.refused", "key.revoked", "recovery.started", "recovery.vetoed":
			fmt.Printf("    %-18s vin=%s station=%-6s actor=%s\n", e.Kind, e.VIN, e.StationID, e.Actor)
		}
	}
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func init() {
	if os.Getenv("VKZ_QUIET") == "1" {
		// Reserved for scripted use; nothing to suppress yet.
	}
}
