package vehicle_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"example.com/vehicle-key-authz/internal/protocol"
	"example.com/vehicle-key-authz/internal/vcrypto"
	"example.com/vehicle-key-authz/internal/vehicle"
)

type fixture struct {
	hsm      *vehicle.HSM
	authPub  ed25519.PublicKey
	authPriv ed25519.PrivateKey
	nonce    []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	authPub, authPriv, err := vcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	hsm := vehicle.New("VIN1", vehicle.Policy{
		AuthorityKeys:                  map[string]ed25519.PublicKey{"auth-1": authPub},
		RequireProximityForProvisional: true,
	}, func() time.Time { return now })
	nonce := hsm.IssueChallenge([]byte("service-nonce"))
	return &fixture{hsm: hsm, authPub: authPub, authPriv: authPriv, nonce: nonce}
}

func (f *fixture) grant(t *testing.T, purpose string, provisional bool) *protocol.Grant {
	t.Helper()
	g := &protocol.Grant{}
	g.Typ = "grant"
	g.Ver = protocol.ProtocolVersion
	g.GrantID = "G-" + purpose
	g.VIN = "VIN1"
	g.SessionID = "S"
	g.VehicleNonceB64 = protocol.EncodeB64(f.nonce)
	g.Purpose = purpose
	g.KeySlot = 1
	g.NewKeyPubB64 = protocol.EncodeB64([]byte("key"))
	g.Provisional = provisional
	g.RevocableUntilMS = time.Unix(1_000_000, 0).Add(24 * time.Hour).UnixMilli()
	g.IssuedAtMS = time.Unix(1_000_000, 0).UnixMilli()
	g.NotAfterMS = time.Unix(1_000_000, 0).Add(10 * time.Minute).UnixMilli()
	g.IssuerKeyID = "auth-1"
	if err := protocol.SignGrant(f.authPriv, g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestHSM_AcceptsValidAddKeyGrant(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t, "add_key", false)
	if err := f.hsm.CheckGrant(g); err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}
	if _, err := f.hsm.Apply(g); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
}

func TestHSM_RejectsTamperedConstraints(t *testing.T) {
	// The station tries to strip "provisional" from a lost-keys grant after
	// the service signed it. The vehicle must catch the tampering.
	f := newFixture(t)
	g := f.grant(t, "replace_all_keys_lost", true)
	g.Provisional = false
	if err := f.hsm.CheckGrant(g); !errors.Is(err, vehicle.ErrGrantInvalid) {
		t.Fatalf("expected invalid grant, got %v", err)
	}
}

func TestHSM_RejectsPermanentHighRiskGrant(t *testing.T) {
	// Even a *correctly signed* permanent re-key is refused: the vehicle's own
	// policy says a lost-keys grant is always provisional. This holds even if
	// the service host is compromised and signs whatever it is told.
	f := newFixture(t)
	g := f.grant(t, "replace_all_keys_lost", false)
	if err := f.hsm.CheckGrant(g); !errors.Is(err, vehicle.ErrGrantInvalid) {
		t.Fatalf("expected invalid grant for permanent high-risk, got %v", err)
	}
}

func TestHSM_RejectsWrongIssuer(t *testing.T) {
	f := newFixture(t)
	_, otherPriv, _ := vcrypto.GenerateKey()
	g := f.grant(t, "add_key", false)
	g.IssuerKeyID = "auth-1"                                 // claims the trusted id...
	if err := protocol.SignGrant(otherPriv, g); err != nil { // ...but signed by the attacker
		t.Fatal(err)
	}
	// SignGrant keeps the claimed issuer id, only the signature differs.
	if err := f.hsm.CheckGrant(g); !errors.Is(err, vehicle.ErrGrantInvalid) {
		t.Fatalf("expected invalid grant for wrong signer, got %v", err)
	}
}

func TestHSM_RejectsWrongVehicle(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t, "add_key", false)
	g.VIN = "OTHER-VIN"
	if err := protocol.SignGrant(f.authPriv, g); err != nil {
		t.Fatal(err)
	}
	if err := f.hsm.CheckGrant(g); !errors.Is(err, vehicle.ErrWrongVehicle) {
		t.Fatalf("expected wrong vehicle, got %v", err)
	}
}

func TestHSM_RejectsReplayedGrant(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t, "add_key", false)
	if _, err := f.hsm.Apply(g); err != nil {
		t.Fatal(err)
	}
	if _, err := f.hsm.Apply(g); !errors.Is(err, vehicle.ErrAlreadyApplied) {
		t.Fatalf("expected already-applied, got %v", err)
	}
}

func TestHSM_RejectsGrantForStaleChallenge(t *testing.T) {
	// A grant minted for an earlier challenge must not unlock a new session.
	f := newFixture(t)
	g := f.grant(t, "add_key", false)
	f.hsm.IssueChallenge([]byte("a-new-service-nonce")) // new session at the car
	if err := f.hsm.CheckGrant(g); !errors.Is(err, vehicle.ErrNonceMismatch) {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
}

func TestHSM_ProvisionalKeyNeedsOwnerNearbyToStart(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t, "replace_all_keys_lost", true)
	rec, err := f.hsm.Apply(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.hsm.CanStart(rec, false, 0); err == nil {
		t.Fatal("provisional key must not start without the owner nearby")
	}
	if err := f.hsm.CanStart(rec, true, 0); err != nil {
		t.Fatalf("provisional key should start with owner nearby: %v", err)
	}
}
