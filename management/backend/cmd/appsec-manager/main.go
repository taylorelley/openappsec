// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command appsec-manager is the open-appsec Manager server: a self-hosted
// replacement for the SaaS management portal.
//
// It serves two listeners with deliberately different trust levels:
//
//   - the admin plane (default :8080), authenticated and optionally TLS, which
//     serves the web UI and its API;
//   - the agent plane (default :80), which agents and the appsec-agent-sync
//     companion talk to. This must be plain HTTP on port 80 because
//     core/logging/k8s_svc_stream.cc hardcodes the port and marks the
//     connection unsecured when posting to $TUNING_HOST. Keep it on an
//     internal network.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openappsec/openappsec/management/backend/internal/api/admin"
	agentapi "github.com/openappsec/openappsec/management/backend/internal/api/agent"
	"github.com/openappsec/openappsec/management/backend/internal/audit"
	"github.com/openappsec/openappsec/management/backend/internal/auth"
	"github.com/openappsec/openappsec/management/backend/internal/config"
	"github.com/openappsec/openappsec/management/backend/internal/events"
	"github.com/openappsec/openappsec/management/backend/internal/fleet"
	"github.com/openappsec/openappsec/management/backend/internal/ingest"
	"github.com/openappsec/openappsec/management/backend/internal/learning"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
	"github.com/openappsec/openappsec/management/backend/internal/store"
	"github.com/openappsec/openappsec/management/backend/web"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel(),
	})))

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	switch os.Getenv("MANAGER_LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Connecting retries, because in a compose deployment the manager usually
	// starts before Postgres is ready to accept connections.
	dbCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	db, err := store.Open(dbCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}
	if err := db.EnsureEventPartitions(ctx, time.Now().UTC(), 2); err != nil {
		return err
	}
	slog.Info("database ready")

	authSvc := auth.NewService(db.Pool, cfg.SessionTTL)
	auditLog := audit.New(db.Pool)
	eventsSvc := events.NewService(db.Pool)
	fleetSvc := fleet.NewService(db.Pool)
	policySvc := policy.NewService(db.Pool, cfg.PolicyOutputPath)
	learnSvc := learning.NewService(db.Pool, cfg.SharedStoragePath)
	writer := ingest.NewWriter(db.Pool)
	scraper := fleet.NewScraper(fleetSvc)

	boot, err := authSvc.Bootstrap(ctx, cfg.BootstrapAdminUser, cfg.BootstrapAdminPassword)
	if err != nil {
		return err
	}
	if boot.Created {
		if boot.GeneratedPassword != "" {
			// Logged once, at startup, because there is no other way for the
			// operator to learn it. Change it at first login.
			slog.Warn("created the initial admin account with a generated password",
				"username", boot.Username, "password", boot.GeneratedPassword)
		} else {
			slog.Info("created the initial admin account", "username", boot.Username)
		}
	}

	if err := policySvc.EnsureSeedRevision(ctx); err != nil {
		return err
	}
	// Re-render on startup so a recreated volume is repopulated without
	// waiting for the next policy change.
	if err := policySvc.WriteVolumeArtifact(ctx); err != nil {
		slog.Warn("could not write the policy artifact", "path", cfg.PolicyOutputPath, "error", err)
	}
	if err := learnSvc.RepublishAll(ctx); err != nil {
		slog.Warn("could not republish tuning decisions", "error", err)
	}

	ui, err := web.Assets()
	if err != nil {
		slog.Warn("no embedded web UI in this build", "error", err)
		ui = nil
	}

	secureCookies := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	adminSrv := &http.Server{
		Addr: cfg.AdminListen,
		Handler: admin.NewServer(authSvc, auditLog, eventsSvc, fleetSvc, policySvc,
			learnSvc, secureCookies, ui).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	agentSrv := &http.Server{
		Addr:              cfg.AgentListen,
		Handler:           agentapi.NewServer(db.Pool, writer, fleetSvc, policySvc, learnSvc).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go runBackground(ctx, db, authSvc, eventsSvc, fleetSvc, scraper, cfg)

	errCh := make(chan error, 2)

	go func() {
		if secureCookies {
			slog.Info("admin plane listening", "addr", cfg.AdminListen, "tls", true)
			errCh <- adminSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		slog.Warn("admin plane listening without TLS; put it behind a terminating proxy "+
			"or set MANAGER_TLS_CERT and MANAGER_TLS_KEY", "addr", cfg.AdminListen)
		errCh <- adminSrv.ListenAndServe()
	}()

	go func() {
		slog.Info("agent plane listening", "addr", cfg.AgentListen)
		errCh <- agentSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = adminSrv.Shutdown(shutdownCtx)
	_ = agentSrv.Shutdown(shutdownCtx)
	return nil
}

// runBackground drives the periodic maintenance the manager depends on:
// partition provisioning, retention, rollups, metric scrapes and session
// expiry. Each tick is independent so one failing job cannot stall the others.
func runBackground(
	ctx context.Context,
	db *store.Store,
	authSvc *auth.Service,
	eventsSvc *events.Service,
	fleetSvc *fleet.Service,
	scraper *fleet.Scraper,
	cfg config.Config,
) {
	scrape := time.NewTicker(cfg.MetricsScrapeEvery)
	rollup := time.NewTicker(cfg.RollupEvery)
	maintenance := time.NewTicker(time.Hour)
	defer scrape.Stop()
	defer rollup.Stop()
	defer maintenance.Stop()

	// Run the maintenance pass once at startup rather than waiting an hour.
	doMaintenance(ctx, db, authSvc, fleetSvc, cfg)

	for {
		select {
		case <-ctx.Done():
			return

		case <-scrape.C:
			scraper.ScrapeAll(ctx)

		case <-rollup.C:
			// Recompute the last two days so late-arriving events, such as a
			// flushed agent event buffer, are folded in.
			if err := eventsSvc.Rollup(ctx, time.Now().UTC().AddDate(0, 0, -2)); err != nil {
				slog.Error("rollup failed", "error", err)
			}

		case <-maintenance.C:
			doMaintenance(ctx, db, authSvc, fleetSvc, cfg)
		}
	}
}

func doMaintenance(
	ctx context.Context,
	db *store.Store,
	authSvc *auth.Service,
	fleetSvc *fleet.Service,
	cfg config.Config,
) {
	if err := db.EnsureEventPartitions(ctx, time.Now().UTC(), 2); err != nil {
		slog.Error("provisioning event partitions failed", "error", err)
	}
	if dropped, err := db.DropExpiredEventPartitions(ctx, cfg.EventRetentionDays); err != nil {
		slog.Error("event retention failed", "error", err)
	} else if len(dropped) > 0 {
		slog.Info("dropped expired event partitions", "partitions", dropped)
	}
	if n, err := authSvc.PurgeExpiredSessions(ctx); err != nil {
		slog.Error("session purge failed", "error", err)
	} else if n > 0 {
		slog.Debug("purged expired sessions", "count", n)
	}
	if err := fleetSvc.PurgeMetrics(ctx, 7*24*time.Hour); err != nil {
		slog.Error("metrics purge failed", "error", err)
	}
}
