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

// Package config reads the manager's runtime configuration from the environment.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// AdminListen serves the web UI and the authenticated admin API.
	AdminListen string
	// AgentListen serves the agent plane. This must be plain HTTP on port 80:
	// core/logging/k8s_svc_stream.cc hardcodes port 80 and UNSECURE_CONN when
	// posting to $TUNING_HOST, so the agent cannot be pointed anywhere else.
	AgentListen string

	DatabaseURL string

	// PolicyOutputPath is the shared-volume location the rendered
	// local_policy.yaml is written to for co-located agents. Empty disables
	// volume delivery, leaving only the pull-companion path.
	PolicyOutputPath string

	// SharedStoragePath is the root of the volume served by the
	// appsec-shared-storage service. Tuning decisions must be written there
	// rather than only served over HTTP: the agent fetches decisions.data from
	// SHARED_STORAGE_HOST, not from the tuning host that receives its events
	// (components/security_apps/waap/waap_clib/TuningDecision.cc). Empty
	// disables file publication, leaving only this manager's HTTP endpoint.
	SharedStoragePath string

	// TLS for the admin plane. When either is empty the admin plane serves
	// plain HTTP, which is only appropriate behind a terminating proxy.
	TLSCertFile string
	TLSKeyFile  string

	SessionTTL         time.Duration
	EventRetentionDays int

	// AllowPrivateScrapeTargets permits the metrics scraper to connect to
	// RFC1918 and unique-local addresses. The normal deployment is exactly
	// that — agents on a private compose or cluster network — so it defaults
	// to true; set it false where the manager can reach infrastructure the
	// agents should not be able to make it call.
	AllowPrivateScrapeTargets bool
	MetricsScrapeEvery        time.Duration
	RollupEvery               time.Duration

	// BootstrapAdminUser/Password seed the first admin account. If the password
	// is empty a random one is generated and written to the log once.
	BootstrapAdminUser     string
	BootstrapAdminPassword string
}

func Load() (Config, error) {
	c := Config{
		AdminListen:            env("MANAGER_ADMIN_LISTEN", ":8080"),
		AgentListen:            env("MANAGER_AGENT_LISTEN", ":80"),
		PolicyOutputPath:       env("MANAGER_POLICY_OUTPUT", "/ext/appsec/local_policy.yaml"),
		SharedStoragePath:      env("MANAGER_SHARED_STORAGE_PATH", "/db"),
		TLSCertFile:            env("MANAGER_TLS_CERT", ""),
		TLSKeyFile:             env("MANAGER_TLS_KEY", ""),
		BootstrapAdminUser:     env("MANAGER_ADMIN_USER", "admin"),
		BootstrapAdminPassword: env("MANAGER_ADMIN_PASSWORD", ""),
	}

	c.DatabaseURL = os.Getenv("MANAGER_DATABASE_URL")
	if c.DatabaseURL == "" {
		// Assembled through url.URL rather than by string formatting: a
		// password containing '#', '/' or '@' would otherwise be parsed as a
		// fragment or authority delimiter and silently truncate the DSN.
		dsn := url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(env("MANAGER_DB_USER", "postgres"), os.Getenv("MANAGER_DB_PASSWORD")),
			Host:   net.JoinHostPort(env("MANAGER_DB_HOST", "appsec-db"), env("MANAGER_DB_PORT", "5432")),
			Path:   "/" + env("MANAGER_DB_NAME", "appsec_manager"),
			// "prefer" rather than "disable": it uses TLS when the server
			// offers it and falls back when it does not, so the stock compose
			// deployment still connects while a database that does have TLS
			// is no longer talked to in the clear by default. Set
			// MANAGER_DB_SSLMODE=require (or verify-full, with a CA) when the
			// database is not on the same private network.
			RawQuery: url.Values{"sslmode": {env("MANAGER_DB_SSLMODE", "prefer")}}.Encode(),
		}
		c.DatabaseURL = dsn.String()
	}

	var err error
	if c.SessionTTL, err = envDuration("MANAGER_SESSION_TTL", 12*time.Hour); err != nil {
		return c, err
	}
	if c.MetricsScrapeEvery, err = envDuration("MANAGER_METRICS_SCRAPE_INTERVAL", time.Minute); err != nil {
		return c, err
	}
	if c.RollupEvery, err = envDuration("MANAGER_ROLLUP_INTERVAL", 5*time.Minute); err != nil {
		return c, err
	}

	// The interval values drive time.NewTicker, which panics on a
	// non-positive duration, and a non-positive session TTL would expire every
	// session the moment it was issued. Refuse at startup rather than crash or
	// misbehave later.
	for _, d := range []struct {
		key   string
		value time.Duration
	}{
		{"MANAGER_SESSION_TTL", c.SessionTTL},
		{"MANAGER_METRICS_SCRAPE_INTERVAL", c.MetricsScrapeEvery},
		{"MANAGER_ROLLUP_INTERVAL", c.RollupEvery},
	} {
		if d.value <= 0 {
			return c, fmt.Errorf("%s must be a positive duration, got %s", d.key, d.value)
		}
	}
	if c.EventRetentionDays, err = envInt("MANAGER_EVENT_RETENTION_DAYS", 30); err != nil {
		return c, err
	}
	// DropExpiredEventPartitions treats a non-positive window as "nothing to
	// do", so a typo here would not fail and not retain-and-drop either: the
	// events table would simply grow without bound. Refuse it at startup.
	if c.EventRetentionDays <= 0 {
		return c, fmt.Errorf("MANAGER_EVENT_RETENTION_DAYS must be a positive number of days, got %d",
			c.EventRetentionDays)
	}
	if c.AllowPrivateScrapeTargets, err = envBool("MANAGER_ALLOW_PRIVATE_SCRAPE_TARGETS", true); err != nil {
		return c, err
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
