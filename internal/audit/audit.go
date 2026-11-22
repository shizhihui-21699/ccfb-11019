// Package audit provides a tamper-evident, append-only record of every
// authorization decision.
//
// Each entry commits to the hash of its predecessor, so deleting or editing
// an entry breaks the chain from that point on. The service periodically
// anchors the chain head in write-once storage (here: a separate witness sink
// interface; in production, S3 object lock or a transparency log). A stolen
// station's colluders cannot quietly erase the record of the keys they made.
package audit

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"example.com/vehicle-key-authz/internal/canon"
	"example.com/vehicle-key-authz/internal/vcrypto"
)

// Entry is one immutable audit record.
type Entry struct {
	Seq       uint64         `json:"seq"`
	PrevHash  string         `json:"prev_hash"`
	At        int64          `json:"at_ms"`
	Kind      string         `json:"kind"`
	Actor     string         `json:"actor"`
	VIN       string         `json:"vin,omitempty"`
	StationID string         `json:"station_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
	Hash      string         `json:"hash"`
}

// Log is an in-memory append-only chain. It is safe for concurrent use.
type Log struct {
	mu      sync.Mutex
	entries []Entry
	last    string
	sink    Sink
	now     func() time.Time
}

// Sink receives the head hash so an external system can anchor it.
type Sink interface {
	Anchor(seq uint64, hash string) error
}

// NewLog creates a log. now may be nil for the wall clock.
func NewLog(sink Sink, now func() time.Time) *Log {
	if now == nil {
		now = time.Now
	}
	genesis := hex.EncodeToString(vcrypto.Hash([]byte("vkz-audit-genesis")))
	return &Log{last: genesis, sink: sink, now: now}
}

// Append adds an entry and returns its hash.
func (l *Log) Append(kind, actor, vin, stationID, sessionID string, detail map[string]any) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := Entry{
		Seq:       uint64(len(l.entries)),
		PrevHash:  l.last,
		At:        l.now().UnixMilli(),
		Kind:      kind,
		Actor:     actor,
		VIN:       vin,
		StationID: stationID,
		SessionID: sessionID,
		Detail:    detail,
	}
	payload := struct {
		Seq       uint64         `json:"seq"`
		PrevHash  string         `json:"prev_hash"`
		At        int64          `json:"at_ms"`
		Kind      string         `json:"kind"`
		Actor     string         `json:"actor"`
		VIN       string         `json:"vin"`
		StationID string         `json:"station_id"`
		SessionID string         `json:"session_id"`
		Detail    map[string]any `json:"detail"`
	}{e.Seq, e.PrevHash, e.At, e.Kind, e.Actor, e.VIN, e.StationID, e.SessionID, e.Detail}
	e.Hash = hex.EncodeToString(vcrypto.Hash(canon.MustMarshal(payload)))
	l.entries = append(l.entries, e)
	l.last = e.Hash
	if l.sink != nil {
		if err := l.sink.Anchor(e.Seq, e.Hash); err != nil {
			return e, fmt.Errorf("audit: anchor seq %d: %w", e.Seq, err)
		}
	}
	return e, nil
}

// Entries returns a copy of the log.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Head returns the current chain head.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.entries)), l.last
}

// Verify recomputes the chain and reports the first inconsistency.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := hex.EncodeToString(vcrypto.Hash([]byte("vkz-audit-genesis")))
	for i, e := range l.entries {
		if e.Seq != uint64(i) {
			return fmt.Errorf("audit: entry %d has seq %d", i, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: entry %d prev hash mismatch", i)
		}
		payload := struct {
			Seq       uint64         `json:"seq"`
			PrevHash  string         `json:"prev_hash"`
			At        int64          `json:"at_ms"`
			Kind      string         `json:"kind"`
			Actor     string         `json:"actor"`
			VIN       string         `json:"vin"`
			StationID string         `json:"station_id"`
			SessionID string         `json:"session_id"`
			Detail    map[string]any `json:"detail"`
		}{e.Seq, e.PrevHash, e.At, e.Kind, e.Actor, e.VIN, e.StationID, e.SessionID, e.Detail}
		want := hex.EncodeToString(vcrypto.Hash(canon.MustMarshal(payload)))
		if e.Hash != want {
			return fmt.Errorf("audit: entry %d hash mismatch", i)
		}
		prev = e.Hash
	}
	return nil
}
