// Package store provides the in-memory reference implementation of the
// service's persistence boundary, plus the data-loading helpers used by the
// demo and tests.
//
// A production store must additionally: make state transitions transactional,
// persist the audit log to write-once storage, and keep the nonce cache
// durable and replicated so a replay cannot slip through a restart.
package store

import (
	"fmt"
	"sync"
	"time"

	"example.com/vehicle-key-authz/internal/model"
)

// Memory is a thread-safe in-memory Store.
type Memory struct {
	mu       sync.RWMutex
	vehicles map[string]*model.Vehicle
	stations map[string]*model.Station
	techs    map[string]*model.Technician
	devices  map[string]*model.DiagnosticDevice
	checkins map[string]*model.CheckIn
	sessions map[string]*model.Session
	nonces   map[string]bool
	grants   []grantRecord
}

type grantRecord struct {
	VIN       string
	StationID string
	Tier      model.RiskTier
	At        time.Time
	HighRisk  bool
}

// New returns an empty store.
func New() *Memory {
	return &Memory{
		vehicles: map[string]*model.Vehicle{},
		stations: map[string]*model.Station{},
		techs:    map[string]*model.Technician{},
		devices:  map[string]*model.DiagnosticDevice{},
		checkins: map[string]*model.CheckIn{},
		sessions: map[string]*model.Session{},
		nonces:   map[string]bool{},
	}
}

func (m *Memory) Vehicle(vin string) (*model.Vehicle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.vehicles[vin]
	if !ok {
		return nil, fmt.Errorf("store: vehicle %s not found", vin)
	}
	return v, nil
}

func (m *Memory) Station(id string) (*model.Station, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.stations[id]
	if !ok {
		return nil, fmt.Errorf("store: station %s not found", id)
	}
	return s, nil
}

func (m *Memory) Tech(id string) (*model.Technician, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.techs[id]
	if !ok {
		return nil, fmt.Errorf("store: technician %s not found", id)
	}
	return t, nil
}

func (m *Memory) Device(id string) (*model.DiagnosticDevice, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.devices[id]
	if !ok {
		return nil, fmt.Errorf("store: device %s not found", id)
	}
	return d, nil
}

func (m *Memory) CheckIn(id string) (*model.CheckIn, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.checkins[id]
	if !ok {
		return nil, fmt.Errorf("store: check-in %s not found", id)
	}
	return c, nil
}

func (m *Memory) PutCheckIn(c *model.CheckIn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkins[c.ID] = c
}

func (m *Memory) Session(id string) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("store: session %s not found", id)
	}
	return s, nil
}

func (m *Memory) PutSession(s *model.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
}

// HighRiskCounts counts high-risk grants in the rolling 24h window per vehicle
// and per station.
func (m *Memory) HighRiskCounts(vin, stationID string, now time.Time) (int, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cutoff := now.Add(-24 * time.Hour)
	var v, st int
	for _, g := range m.grants {
		if !g.HighRisk || g.At.Before(cutoff) {
			continue
		}
		if g.VIN == vin {
			v++
		}
		if g.StationID == stationID {
			st++
		}
	}
	return v, st
}

func (m *Memory) RecordGrant(vin, stationID string, tier model.RiskTier, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants = append(m.grants, grantRecord{
		VIN: vin, StationID: stationID, Tier: tier, At: at,
		HighRisk: tier == model.TierHigh,
	})
}

// SeenNonce returns true if the nonce had already been used. Calling it
// records the nonce, so the first call returns false.
func (m *Memory) SeenNonce(scope, nonce string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := scope + "\x00" + nonce
	if m.nonces[k] {
		return true
	}
	m.nonces[k] = true
	return false
}

// --- seeding helpers (used by demo and tests) ------------------------------

func (m *Memory) PutVehicle(v *model.Vehicle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vehicles[v.VIN] = v
}
func (m *Memory) PutStation(s *model.Station) { m.mu.Lock(); defer m.mu.Unlock(); m.stations[s.ID] = s }
func (m *Memory) PutTech(t *model.Technician) { m.mu.Lock(); defer m.mu.Unlock(); m.techs[t.ID] = t }
func (m *Memory) PutDevice(d *model.DiagnosticDevice) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[d.ID] = d
}
