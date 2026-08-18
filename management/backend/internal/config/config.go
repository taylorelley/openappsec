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
	MetricsScrapeEvery time.Duration
	RollupEvery        time.Duration

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
		host := env("MANAGER_DB_HOST", "appsec-db")
		port := env("MANAGER_DB_PORT", "5432")
		user := env("MANAGER_DB_USER", "postgres")
		pass := env("MANAGER_DB_PASSWORD", "")
		name := env("MANAGER_DB_NAME", "appsec_manager")
		c.DatabaseURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			user, pass, host, port, name)
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
	if c.EventRetentionDays, err = envInt("MANAGER_EVENT_RETENTION_DAYS", 30); err != nil {
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
