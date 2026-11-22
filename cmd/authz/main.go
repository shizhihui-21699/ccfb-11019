// Command authz runs the vehicle key authorization service.
//
// Configuration is via environment, and the process refuses to start without
// an issuer key: this service must never come up in a mode where it would
// have to sign grants with a key it generated on the fly, because the vehicle
// only trusts keys provisioned at manufacture.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/vehicle-key-authz/internal/api"
	"example.com/vehicle-key-authz/internal/audit"
	"example.com/vehicle-key-authz/internal/policy"
	"example.com/vehicle-key-authz/internal/service"
	"example.com/vehicle-key-authz/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "authz:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	issuer, err := loadIssuerFromEnv()
	if err != nil {
		return err
	}
	st := store.New()
	log := audit.NewLog(nil, time.Now)
	svc := service.New(st, policy.DefaultConfig(), log, issuer)

	srv := api.New(svc)
	addr := envOr("VKZ_LISTEN", ":8443")
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// loadIssuerFromEnv reads the authority signing key. In production this is an
// HSM/KMS handle, not an inline private key; the environment form here exists
// so the demo and tests can inject one deliberately.
func loadIssuerFromEnv() (service.IssuerKey, error) {
	keyID := envOr("VKZ_ISSUER_KEY_ID", "")
	hexKey := os.Getenv("VKZ_ISSUER_PRIVATE_KEY_HEX")
	if keyID == "" || hexKey == "" {
		return service.IssuerKey{}, errors.New("VKZ_ISSUER_KEY_ID and VKZ_ISSUER_PRIVATE_KEY_HEX must be set; refusing to start without an authority key")
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return service.IssuerKey{}, fmt.Errorf("issuer private key is not valid hex: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return service.IssuerKey{}, fmt.Errorf("issuer private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
	}
	priv := ed25519.PrivateKey(raw)
	pub := priv.Public().(ed25519.PublicKey)
	return service.IssuerKey{KeyID: keyID, Private: priv, Public: pub}, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
