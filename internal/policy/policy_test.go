package policy

import (
	"strings"
	"testing"
	"time"

	"example.com/vehicle-key-authz/internal/model"
)

func baseIn() Input {
	now := time.Unix(1000, 0)
	return Input{
		Purpose: model.PurposeReplaceLost, KeySlot: 1, NewKey: []byte("k"),
		Facts: Facts{
			Vehicle: &model.Vehicle{VIN: "V", MaxKeys: 5, Status: model.VehicleActive,
				OwnerContacts: []string{"a"}},
			Station: &model.Station{ID: "S", Status: model.StationActive, TwoStaffAttested: true},
			Tech:    &model.Technician{ID: "T", StationID: "S", Active: true, DeviceIDs: []string{"D"}},
			Device:  &model.DiagnosticDevice{ID: "D", StationID: "S"},
			Now:     now, OwnerContactsNotified: 1,
		},
	}
}

func TestRecoveryNeedsCoolingOff(t *testing.T) {
	in := baseIn()
	in.Evidence.RecoveryClaimValid = true
	in.Evidence.RecoveryClaimFresh = true
	in.Evidence.VehicleProofValid = true
	in.Evidence.VehicleProofFresh = true
	in.Evidence.CheckInValid = true
	in.Evidence.CheckInFresh = true
	in.Evidence.CheckInAtStation = true
	in.Evidence.WitnessValid = true
	in.Evidence.WitnessDifferentPerson = true
	in.Evidence.CoolingOffElapsed = false

	d := Evaluate(in, DefaultConfig())
	if d.Allow {
		t.Fatalf("recovery must not be allowed before cooling-off; unmet=%v", d.Unmet)
	}
	in.Evidence.CoolingOffElapsed = true
	d = Evaluate(in, DefaultConfig())
	if !d.Allow {
		t.Fatalf("recovery should be allowed after cooling-off; unmet=%v reasons=%v", d.Unmet, d.Reasons)
	}
	if !d.Constraints.Provisional || !d.Constraints.OwnerProximityRequiredPerUse {
		t.Fatalf("recovery key must be provisional with per-use proximity: %+v", d.Constraints)
	}
}

func TestDbgRecoveryDecision(t *testing.T) {
	in := baseIn()
	in.Evidence.RecoveryClaimValid = true
	in.Evidence.RecoveryClaimFresh = true
	in.Evidence.VehicleProofValid = true
	in.Evidence.VehicleProofFresh = true
	in.Evidence.CheckInValid = true
	in.Evidence.CheckInFresh = true
	in.Evidence.CheckInAtStation = true
	in.Evidence.WitnessValid = true
	in.Evidence.WitnessDifferentPerson = true
	in.Evidence.CoolingOffElapsed = false
	d := Evaluate(in, DefaultConfig())
	t.Logf("allow=%v tier=%v unmet=%v reasons=%v", d.Allow, d.Tier, d.Unmet, d.Reasons)
}

func allPresent(in *Input) {
	in.Evidence.VehicleProofValid = true
	in.Evidence.VehicleProofFresh = true
	in.Evidence.CheckInValid = true
	in.Evidence.CheckInFresh = true
	in.Evidence.CheckInAtStation = true
}

func TestHardBlocks(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Input)
		want string
	}{
		{"stolen", func(in *Input) { in.Facts.Vehicle.Status = model.VehicleStolen }, "stolen"},
		{"suspended", func(in *Input) { in.Facts.Station.Status = model.StationSuspended }, "suspended"},
		{"revoked device", func(in *Input) { in.Facts.Device.Revoked = true }, "revoked"},
		{"device wrong station", func(in *Input) { in.Facts.Device.StationID = "X" }, "does not belong"},
		{"inactive tech", func(in *Input) { in.Facts.Tech.Active = false }, "not active"},
		{"device not assigned", func(in *Input) { in.Facts.Tech.DeviceIDs = []string{"OTHER"} }, "not assigned"},
	}
	for _, c := range cases {
		in := baseIn()
		in.Purpose = model.PurposeAddKey
		c.mut(&in)
		d := Evaluate(in, DefaultConfig())
		if d.Allow {
			t.Fatalf("%s: expected deny", c.name)
		}
		if !containsSubstr(d.Reasons, c.want) {
			t.Fatalf("%s: reason %v does not mention %q", c.name, d.Reasons, c.want)
		}
	}
}

func TestAddKeyWithExistingKey_OwnerPresent_LowTier(t *testing.T) {
	in := baseIn()
	in.Purpose = model.PurposeAddKey
	in.KeySlot = 5
	in.Facts.Vehicle.Keys = []model.KeyRecord{{Slot: 1}, {Slot: 2}}
	allPresent(&in)
	in.Evidence.PresentKeySlots = []int{1}
	in.Evidence.PresentKeyChallenged = true
	in.Evidence.OwnerConsentValid = true
	in.Evidence.OwnerConsentFresh = true
	in.Evidence.OwnerDeviceBound = true
	in.Evidence.ProximityValid = true
	in.Evidence.ProximityFresh = true

	d := Evaluate(in, DefaultConfig())
	if !d.Allow || d.Tier != model.TierLow {
		t.Fatalf("expected low-tier allow, got allow=%v tier=%v unmet=%v", d.Allow, d.Tier, d.Unmet)
	}
	if d.Constraints.Provisional {
		t.Fatal("owner-present add-key should be permanent")
	}
}

func TestAddKeyNeedsChallengedKey(t *testing.T) {
	in := baseIn()
	in.Purpose = model.PurposeAddKey
	in.KeySlot = 5 // free slot; slot 1 is occupied
	in.Facts.Vehicle.Keys = []model.KeyRecord{{Slot: 1}}
	allPresent(&in)
	in.Evidence.PresentKeySlots = []int{1}
	in.Evidence.PresentKeyChallenged = false // sensed but did not answer
	in.Evidence.OwnerConsentValid = true
	in.Evidence.OwnerConsentFresh = true
	in.Evidence.OwnerDeviceBound = true
	in.Evidence.ProximityValid = true
	in.Evidence.ProximityFresh = true

	d := Evaluate(in, DefaultConfig())
	if d.Allow {
		t.Fatal("an un-challenged key must not satisfy existing_key_proof")
	}
	found := false
	for _, u := range d.Unmet {
		if len(u) > 18 && u[:18] == "existing_key_proof" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected existing_key_proof unmet, got %v", d.Unmet)
	}
}

func TestRecentTransfer_ForcesCoolingOff(t *testing.T) {
	in := baseIn()
	in.Purpose = model.PurposeAddKey
	in.KeySlot = 5
	in.Facts.Vehicle.Keys = []model.KeyRecord{{Slot: 1}}
	in.Facts.Vehicle.OwnershipSince = in.Facts.Now.Add(-48 * time.Hour) // 2 days
	allPresent(&in)
	in.Evidence.PresentKeySlots = []int{1}
	in.Evidence.PresentKeyChallenged = true
	in.Evidence.OwnerConsentValid = true
	in.Evidence.OwnerConsentFresh = true
	in.Evidence.OwnerDeviceBound = true
	in.Evidence.ProximityValid = true
	in.Evidence.ProximityFresh = true

	d := Evaluate(in, DefaultConfig())
	if d.Allow {
		t.Fatal("recent transfer must require a witness even with owner present")
	}
	if d.Tier != model.TierHigh {
		t.Fatalf("recent transfer should raise tier to high, got %v", d.Tier)
	}
}

func TestGeoMismatch_DeniesHighRisk(t *testing.T) {
	in := baseIn()
	allPresent(&in)
	in.Evidence.RecoveryClaimValid = true
	in.Evidence.RecoveryClaimFresh = true
	in.Evidence.WitnessValid = true
	in.Evidence.WitnessDifferentPerson = true
	in.Evidence.CoolingOffElapsed = true
	in.Facts.Station.Geo = model.Geo{Lat: 37.7, Lon: -122.4}
	in.Facts.OwnerReportedGeo = &model.Geo{Lat: 48.8, Lon: 2.3, AccuracyM: 10} // Paris

	d := Evaluate(in, DefaultConfig())
	if d.Allow {
		t.Fatal("implausible geo must deny high-risk")
	}
	if !containsSubstr(d.Reasons, "implausibly far") {
		t.Fatalf("expected geo reason, got %v", d.Reasons)
	}
}

func TestHighRiskRateLimits(t *testing.T) {
	in := baseIn()
	allPresent(&in)
	in.Evidence.RecoveryClaimValid = true
	in.Evidence.RecoveryClaimFresh = true
	in.Evidence.WitnessValid = true
	in.Evidence.WitnessDifferentPerson = true
	in.Evidence.CoolingOffElapsed = true
	cfg := DefaultConfig()

	in.Facts.HighRiskTodayVehicle = cfg.MaxHighRiskPerVehiclePerDay
	if d := Evaluate(in, cfg); d.Allow {
		t.Fatal("per-vehicle cap must deny")
	}
	in.Facts.HighRiskTodayVehicle = 0
	in.Facts.HighRiskTodayStation = cfg.MaxHighRiskPerStationPerDay
	if d := Evaluate(in, cfg); d.Allow {
		t.Fatal("per-station cap must deny")
	}
}

func TestVetoBlocksRecoveryEvenAfterCooling(t *testing.T) {
	in := baseIn()
	allPresent(&in)
	in.Evidence.RecoveryClaimValid = true
	in.Evidence.RecoveryClaimFresh = true
	in.Evidence.WitnessValid = true
	in.Evidence.WitnessDifferentPerson = true
	in.Evidence.CoolingOffElapsed = true
	in.Evidence.OwnerContactsVetoed = true
	if d := Evaluate(in, DefaultConfig()); d.Allow {
		t.Fatal("a contact veto must deny even after cooling-off")
	}
}

func containsSubstr(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}
