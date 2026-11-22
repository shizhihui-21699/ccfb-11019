// Package policy decides whether a key operation may be authorized.
//
// It is deliberately a pure function of (facts, evidence, config) with no IO,
// no clock reads and no randomness. That makes every decision reproducible
// from the audit log years later, which matters both for prosecution and for
// bug-hunting: given the same inputs the service must reach the same verdict.
//
// The engine has no notion of "trusted device". A valid signature on a
// request only proves the caller holds some key; whether that key's holder is
// allowed to do this thing is decided entirely here, from physical evidence.
package policy

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"example.com/vehicle-key-authz/internal/model"
)

// Config holds tunable thresholds. Values are deliberately explicit rather
// than buried in code so a security team can review and change them without
// touching logic.
type Config struct {
	// MinOwnershipAgeForHighRisk is how long a vehicle must have belonged to
	// the current owner before high-risk operations avoid extra scrutiny.
	// Stops the "buy a car, immediately re-key it and disappear" pattern.
	MinOwnershipAgeForHighRisk time.Duration
	// RecoveryCoolingOff is how long a no-phone/no-key recovery must wait
	// while the owner's registered contacts can veto.
	RecoveryCoolingOff time.Duration
	// ProvisionalWindow is how long a provisional key stays unilaterally
	// revocable by the owner.
	ProvisionalWindow time.Duration
	// ProvisionalMaxActivations limits vehicle starts on a provisional key.
	ProvisionalMaxActivations int
	// MaxKeysPerVehicle caps total provisioned keys.
	MaxKeysPerVehicle int
	// MaxHighRiskPerVehiclePerDay bounds how often the worst operation can
	// happen on one car, catching a compromised station grinding through
	// vehicles.
	MaxHighRiskPerVehiclePerDay int
	// MaxHighRiskPerStationPerDay bounds station-level abuse.
	MaxHighRiskPerStationPerDay int
	// GeoMaxDistanceM is how far an owner's reported position may be from
	// the station geofence before it becomes a corroborating negative.
	GeoMaxDistanceM float64
	PolicyVersion   string
}

// DefaultConfig returns production-sensible defaults.
func DefaultConfig() Config {
	return Config{
		MinOwnershipAgeForHighRisk:  30 * 24 * time.Hour,
		RecoveryCoolingOff:          60 * time.Minute,
		ProvisionalWindow:           7 * 24 * time.Hour,
		ProvisionalMaxActivations:   30,
		MaxKeysPerVehicle:           5,
		MaxHighRiskPerVehiclePerDay: 2,
		MaxHighRiskPerStationPerDay: 5,
		GeoMaxDistanceM:             2000,
		PolicyVersion:               "2026-11-01",
	}
}

// Facts are server-held records. None of them come from the caller.
type Facts struct {
	Vehicle *model.Vehicle
	Station *model.Station
	Tech    *model.Technician
	Device  *model.DiagnosticDevice
	Now     time.Time

	// HighRiskTodayVehicle / HighRiskTodayStation are counts from the audit
	// store (rolling 24h).
	HighRiskTodayVehicle int
	HighRiskTodayStation int

	// ExternalSignals are corroborating, non-authoritative inputs.
	OwnerReportedGeo *model.Geo
	// OwnerContactsNotified counts contacts already reached for a pending
	// recovery cooling-off.
	OwnerContactsNotified int
}

// Evidence is what the caller proved. Each field is the result of a full
// signature verification done by the service, never a boolean supplied by the
// caller.
type Evidence struct {
	VehicleProofValid bool
	VehicleProofFresh bool
	// PresentKeySlots comes from the vehicle HSM and lists slots with a
	// transponder the car can actually talk to.
	PresentKeySlots      []int
	PresentKeyChallenged bool

	OwnerConsentValid bool
	OwnerConsentFresh bool
	OwnerDeviceBound  bool

	ProximityValid bool
	ProximityFresh bool

	CheckInValid     bool
	CheckInFresh     bool
	CheckInAtStation bool

	WitnessValid           bool
	WitnessDifferentPerson bool

	RecoveryClaimValid  bool
	RecoveryClaimFresh  bool
	CoolingOffElapsed   bool
	OwnerContactsVetoed bool
}

// Input bundles everything the engine may consider.
type Input struct {
	Purpose  model.Purpose
	KeySlot  int
	NewKey   []byte
	Facts    Facts
	Evidence Evidence
	// Offline indicates the station has no service connectivity and the
	// vehicle would self-authorize under a LocalGrant.
	Offline bool
}

// Evaluate returns the decision. It never returns an error: a denied
// operation is a normal outcome with an explanation.
func Evaluate(in Input, cfg Config) model.Decision {
	d := model.Decision{
		Allow:         false,
		Tier:          model.TierHigh,
		PolicyVersion: cfg.PolicyVersion,
	}
	deny := func(format string, args ...any) model.Decision {
		d.Reasons = append(d.Reasons, fmt.Sprintf(format, args...))
		return d
	}
	unmet := func(cond bool, code, human string) {
		if !cond {
			d.Unmet = append(d.Unmet, code+": "+human)
		}
	}

	v, st, tech, dev := in.Facts.Vehicle, in.Facts.Station, in.Facts.Tech, in.Facts.Device
	if v == nil || st == nil || tech == nil || dev == nil {
		return deny("internal: missing server-side facts")
	}
	if !in.Purpose.Valid() {
		return deny("unknown purpose %q", in.Purpose)
	}

	// ---- hard blocking conditions, checked before anything else ----------

	if v.Status == model.VehicleStolen {
		return deny("vehicle is reported stolen; only the police impound flow may re-key it")
	}
	if st.Status == model.StationSuspended {
		return deny("station %s is suspended", st.ID)
	}
	if dev.Revoked {
		return deny("diagnostic device %s is revoked", dev.ID)
	}
	if dev.StationID != st.ID {
		return deny("device %s does not belong to station %s", dev.ID, st.ID)
	}
	if tech.StationID != st.ID || !tech.Active {
		return deny("technician %s is not active at station %s", tech.ID, st.ID)
	}
	assertedByTech := false
	for _, id := range tech.DeviceIDs {
		if id == dev.ID {
			assertedByTech = true
			break
		}
	}
	if !assertedByTech {
		return deny("device %s is not assigned to technician %s", dev.ID, tech.ID)
	}
	if hasSlot(v, in.KeySlot) && in.Purpose != model.PurposeReplaceLost {
		// Re-programming a populated slot destroys an existing key without
		// saying so. Replace-lost is the only purpose allowed to touch a
		// populated slot, and it is separately gated below.
		return deny("key slot %d is occupied; refusing to overwrite silently", in.KeySlot)
	}
	if in.Purpose != model.PurposeReplaceLost && v.WorkingKeys() >= cfg.MaxKeysPerVehicle {
		return deny("vehicle already has %d keys (max %d)", v.WorkingKeys(), cfg.MaxKeysPerVehicle)
	}

	// ---- risk tier --------------------------------------------------------

	highRisk := in.Purpose == model.PurposeReplaceLost || in.Purpose == model.PurposeFirstEnroll

	// Ownership-age gate: a freshly transferred car is the classic "swoop".
	recentTransfer := !v.OwnershipSince.IsZero() &&
		in.Facts.Now.Sub(v.OwnershipSince) < cfg.MinOwnershipAgeForHighRisk

	vehiclePresent := in.Evidence.VehicleProofValid && in.Evidence.VehicleProofFresh
	stationPresent := in.Evidence.CheckInValid && in.Evidence.CheckInFresh && in.Evidence.CheckInAtStation

	ownerInteractive := in.Evidence.OwnerConsentValid && in.Evidence.OwnerConsentFresh &&
		in.Evidence.OwnerDeviceBound
	ownerNearby := in.Evidence.ProximityValid && in.Evidence.ProximityFresh

	// ---- common requirements ---------------------------------------------

	// Physical presence of the CAR is non-negotiable for every purpose. This
	// single check is what defeats the parking-lot attack: there is no
	// vehicle HSM on the network to sign.
	unmet(vehiclePresent, "vehicle_proof",
		"the vehicle's immobilizer must sign a fresh challenge (connect the diagnostic lead to this VIN)")

	// The station check-in says the car is in a service bay, written by the
	// back office, not the handheld.
	unmet(stationPresent && in.Evidence.CheckInAtStation, "station_checkin",
		"the station back office must have an open repair order for this VIN")

	if !vehiclePresent || !(stationPresent && in.Evidence.CheckInAtStation) {
		d.Reasons = append(d.Reasons, "physical co-presence of vehicle and station not established")
		return d
	}

	if highRisk {
		d.Tier = model.TierHigh
		return evaluateHighRisk(in, cfg, &d, deny, unmet, recentTransfer)
	}

	// ---- low / medium risk: add a key while a working key exists ----------

	if v.WorkingKeys() < 1 {
		// The car claims "add key" but reports no working key. Either the
		// caller is lying about the purpose to dodge the high-risk gates, or
		// the state is stale. Both are refusals.
		return deny("no working key is present on the vehicle; this is a replace-all-keys-lost operation and must take the high-risk path")
	}

	// At least one existing key must be physically challenged. A blank
	// transponder alone cannot unlock an add-key.
	unmet(len(in.Evidence.PresentKeySlots) > 0 && in.Evidence.PresentKeyChallenged,
		"existing_key_proof",
		"an existing working key must be inserted and answered at the vehicle")

	d.Tier = model.TierLow

	// Owner presence. For add-key the owner being physically at the car is
	// the normal case (they drove it in), so we require consent that they
	// signed. If the owner is NOT present (e.g. a fleet driver dropped the
	// car off), we do not hard-fail: we downgrade to elevated and demand the
	// second-technician witness plus a cooling-off before the key becomes
	// permanent.
	switch {
	case ownerInteractive && ownerNearby:
		d.Reasons = append(d.Reasons, "owner device present next to the vehicle and approved this key")
	case ownerInteractive && !ownerNearby:
		// The owner signed from somewhere else. That is allowed, but the key
		// must not become permanent on a remote click alone: a second
		// technician has to witness the physical work, and the key stays
		// provisional so the owner can still revoke it unilaterally.
		d.Tier = model.TierElevated
		d.Reasons = append(d.Reasons, "owner approved remotely; a second technician must witness the work")
		unmet(in.Evidence.WitnessValid && in.Evidence.WitnessDifferentPerson, "second_witness",
			"a second technician, on a different device, must witness the operation")
	default:
		// No owner consent on record. This is the fleet case (a driver left
		// the car) or the lost-everything case. It must never silently
		// produce a permanent key, so it takes the high-risk path, which can
		// still succeed via a verified recovery claim with a witness.
		return evaluateHighRisk(in, cfg, &d, deny, unmet, recentTransfer)
	}

	if st.Watchlisted {
		d.Tier = model.TierHigh
		d.Reasons = append(d.Reasons, "station is on the watchlist; elevated scrutiny applied")
		unmet(in.Evidence.WitnessValid && in.Evidence.WitnessDifferentPerson, "second_witness",
			"a second technician from a different device must witness this operation")
	}
	if recentTransfer {
		d.Tier = model.TierHigh
		d.Reasons = append(d.Reasons, "vehicle changed ownership recently")
		unmet(in.Evidence.WitnessValid && in.Evidence.WitnessDifferentPerson, "second_witness",
			"a second technician must witness operations on recently transferred vehicles")
	}

	// Low risk online: normal grant, no cooling-off. A key added with the
	// owner physically present and approving is permanent (they just watched
	// it happen). A key added on a remote approval, or on a vehicle whose
	// ownership is recent, stays provisional for the revocation window, so
	// the owner can undo it without going back to the station. Either way the
	// authorization itself has a short hard expiry.
	now := in.Facts.Now
	provisional := !(ownerInteractive && ownerNearby) || recentTransfer
	d.Constraints = model.Constraints{
		Provisional:                  provisional,
		OwnerProximityRequiredPerUse: false,
		MaxActivations:               0,
		RevocableUntilMS:             now.Add(cfg.ProvisionalWindow).UnixMilli(),
		NotAfterMS:                   now.Add(15 * time.Minute).UnixMilli(),
	}
	if in.Offline && d.Tier == model.TierLow && len(d.Unmet) == 0 {
		d.Reasons = append(d.Reasons, "offline mode: vehicle will self-authorize under pre-provisioned policy")
	}
	d.Allow = len(d.Unmet) == 0
	if !d.Allow {
		d.Reasons = append(d.Reasons, "requirements outstanding")
	}
	return d
}

func evaluateHighRisk(in Input, cfg Config, d *model.Decision, deny func(string, ...any) model.Decision, unmet func(bool, string, string), recentTransfer bool) model.Decision {
	d.Tier = model.TierHigh
	ev := in.Evidence

	// You cannot "replace all lost keys" on a car that visibly still has
	// working keys. The vehicle reports the slots it can challenge; if any
	// are alive, the honest operation is add_key.
	if len(ev.PresentKeySlots) > 0 && in.Purpose == model.PurposeReplaceLost {
		return deny("vehicle reports %d working key(s) present; use add-key instead of replace-all-keys-lost", len(ev.PresentKeySlots))
	}

	if in.Facts.HighRiskTodayVehicle >= cfg.MaxHighRiskPerVehiclePerDay {
		return deny("vehicle already had %d high-risk operations in 24h", in.Facts.HighRiskTodayVehicle)
	}
	if in.Facts.HighRiskTodayStation >= cfg.MaxHighRiskPerStationPerDay {
		return deny("station exceeded %d high-risk operations in 24h", in.Facts.HighRiskTodayStation)
	}

	// Path A: owner is physically present with an enrolled, unlocked phone.
	// This is the normal "lost my keys, I'm at the dealer with my phone"
	// case. No cooling-off, but the resulting key is provisional for the
	// revocation window, and the station must have been audited for the
	// two-person rule.
	ownerPresent := ev.OwnerConsentValid && ev.OwnerConsentFresh && ev.OwnerDeviceBound &&
		ev.ProximityValid && ev.ProximityFresh

	// Path B: owner has neither phone nor key. Needs independent identity
	// verification, a second technician, a cooling-off during which every
	// registered contact can veto, and yields a per-use-proximity key.
	recovery := ev.RecoveryClaimValid && ev.RecoveryClaimFresh &&
		ev.WitnessValid && ev.WitnessDifferentPerson

	if !ownerPresent && !recovery {
		d.Unmet = append(d.Unmet,
			"owner_presence: the owner's enrolled phone must be present at the vehicle and approve, OR a verified identity recovery claim plus a second-technician witness must be on file")
		d.Reasons = append(d.Reasons, "no acceptable proof of owner knowledge and presence")
		d.Allow = false
		return *d
	}

	now := in.Facts.Now
	provisionalUntil := now.Add(cfg.ProvisionalWindow)

	// A recently transferred vehicle gets the stricter treatment regardless
	// of which path was taken.
	requireCooling := recentTransfer || !ownerPresent
	requireWitness := recentTransfer || !ownerPresent || !in.Facts.Station.TwoStaffAttested

	if requireWitness {
		unmet(ev.WitnessValid && ev.WitnessDifferentPerson, "second_witness",
			"a second technician, on a different diagnostic device, must witness this high-risk operation")
	}
	if requireCooling {
		unmet(ev.CoolingOffElapsed, "cooling_off",
			fmt.Sprintf("a %s cooling-off must elapse with no veto from the owner's registered contacts", cfg.RecoveryCoolingOff))
		if ev.OwnerContactsVetoed {
			return deny("a registered owner contact vetoed this operation")
		}
		if in.Facts.OwnerContactsNotified == 0 {
			d.Unmet = append(d.Unmet, "owner_notified: no registered owner contact could be reached")
		}
	}
	if !ownerPresent {
		// Path B keys need the owner's phone nearby on every start until the
		// cooling-off and a follow-up owner visit make it permanent.
		d.Reasons = append(d.Reasons, "recovery path: key will require owner proximity for each use until made permanent")
	}

	if recentTransfer {
		d.Reasons = append(d.Reasons, "recent ownership change: cooling-off and witness mandatory")
	}

	// Geo is corroboration only. A mismatch is a strong negative, a match is
	// worth almost nothing (GPS is spoofable), so we never use it to allow.
	if in.Facts.OwnerReportedGeo != nil && !withinGeo(in.Facts.OwnerReportedGeo, in.Facts.Station, cfg.GeoMaxDistanceM) {
		return deny("owner's reported location is implausibly far from the station")
	}

	d.Allow = len(d.Unmet) == 0
	if !d.Allow {
		d.Reasons = append(d.Reasons, "requirements outstanding")
		return *d
	}

	if !in.Facts.Station.TwoStaffAttested && ownerPresent {
		d.Tier = model.TierElevated
		d.Reasons = append(d.Reasons, "station has not been audited for the two-person rule")
	}

	d.Constraints = model.Constraints{
		Provisional:                  true,
		OwnerProximityRequiredPerUse: !ownerPresent,
		MaxActivations:               ifElse(!ownerPresent, cfg.ProvisionalMaxActivations, 0),
		RevocableUntilMS:             provisionalUntil.UnixMilli(),
		NotAfterMS:                   now.Add(30 * time.Minute).UnixMilli(),
	}
	if ownerPresent {
		d.Reasons = append(d.Reasons, "owner verified in person; key is provisional and owner-revocable without station help")
	}
	return *d
}

func ifElse[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

func hasSlot(v *model.Vehicle, slot int) bool {
	for _, k := range v.Keys {
		if k.Slot == slot && !k.Revoked {
			return true
		}
	}
	return false
}

func withinGeo(g *model.Geo, s *model.Station, maxM float64) bool {
	if g == nil {
		return true
	}
	return haversineM(g.Lat, g.Lon, s.Geo.Lat, s.Geo.Lon) <= maxM+float64(g.AccuracyM)
}

func haversineM(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371000.0
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dlat := rad(lat2 - lat1)
	dlon := rad(lon2 - lon1)
	a := math.Pow(math.Sin(dlat/2), 2) +
		math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Pow(math.Sin(dlon/2), 2)
	return 2 * r * math.Asin(math.Sqrt(a))
}

// UnmetCodes returns just the machine codes of outstanding requirements,
// for structured API responses and metrics.
func UnmetCodes(d model.Decision) []string {
	out := make([]string, 0, len(d.Unmet))
	for _, u := range d.Unmet {
		code, _, _ := strings.Cut(u, ":")
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}
