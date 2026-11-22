// Package api exposes the authorization service over HTTP.
//
// The transport is deliberately thin: it decodes JSON, calls the service, and
// maps errors to status codes. It performs no authorization of its own. In
// particular it never decides "this device is trusted" — the device's mTLS
// identity is used only for routing and rate limiting, and every meaningful
// check lives in the service and policy layers where the audit log covers it.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"example.com/vehicle-key-authz/internal/service"
)

// Server adapts a Service to net/http.
type Server struct {
	Svc *service.Service
	// MaxBodyBytes caps request size; proof bundles are small.
	MaxBodyBytes int64
}

// New returns a Server.
func New(svc *service.Service) *Server {
	return &Server{Svc: svc, MaxBodyBytes: 1 << 20}
}

// Handler returns the mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/checkins", s.handleIngestCheckIn)
	mux.HandleFunc("POST /v1/sessions", s.handleOpenSession)
	mux.HandleFunc("POST /v1/sessions/proofs", s.handleSubmitProofs)
	mux.HandleFunc("POST /v1/sessions/cancel", s.handleCancel)
	mux.HandleFunc("POST /v1/revocations", s.handleRevoke)
	mux.HandleFunc("POST /v1/recoveries/veto", s.handleVeto)
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	return mux
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, s.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed_request", err.Error())
		return false
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		writeErr(w, http.StatusBadRequest, "malformed_request", "trailing data")
		return false
	}
	return true
}

func (s *Server) handleIngestCheckIn(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Assertion []byte `json:"assertion"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	ci, err := s.Svc.IngestCheckIn(req.Assertion)
	if err != nil {
		mapErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"check_in_id": ci.ID, "vin": ci.VIN, "station_id": ci.StationID,
		"expires_at_ms": ci.ExpiresAt.UnixMilli(),
	})
}

func (s *Server) handleOpenSession(w http.ResponseWriter, r *http.Request) {
	var req service.OpenRequest
	if !s.decode(w, r, &req) {
		return
	}
	res, err := s.Svc.OpenSession(req)
	if err != nil {
		mapErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleSubmitProofs(w http.ResponseWriter, r *http.Request) {
	var pb service.ProofBundle
	if !s.decode(w, r, &pb) {
		return
	}
	out, err := s.Svc.SubmitProofs(pb)
	if err != nil {
		mapErr(w, err)
		return
	}
	status := http.StatusOK
	if !out.Allowed {
		// 403 with a body that explains exactly which physical step is
		// missing, so the technician is not left guessing.
		status = http.StatusForbidden
	}
	writeJSON(w, status, out)
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID    string `json:"session_id"`
		TechnicianID string `json:"technician_id"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.Svc.Cancel(req.SessionID, req.TechnicianID); err != nil {
		mapErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revocation []byte `json:"revocation"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.Svc.RevokeKey(req.Revocation); err != nil {
		mapErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleVeto(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.Svc.Veto(req.Token); err != nil {
		mapErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func mapErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, service.ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, "unauthorized", err.Error())
	case errors.Is(err, service.ErrProof):
		writeErr(w, http.StatusBadRequest, "proof_rejected", err.Error())
	case errors.Is(err, service.ErrReplay):
		writeErr(w, http.StatusConflict, "replay", err.Error())
	case errors.Is(err, service.ErrExpired):
		writeErr(w, http.StatusGone, "expired", err.Error())
	case errors.Is(err, service.ErrDenied):
		writeErr(w, http.StatusForbidden, "denied", err.Error())
	case errors.Is(err, service.ErrState):
		writeErr(w, http.StatusConflict, "invalid_state", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": code, "message": msg})
}
