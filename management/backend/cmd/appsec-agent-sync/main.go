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

// Command appsec-agent-sync keeps one open-appsec agent in step with an
// open-appsec Manager.
//
// Run it on the agent's host or as a sidecar sharing the agent's network
// namespace: it needs loopback access to the agent's orchestration API, which
// refuses connections from anywhere else.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openappsec/openappsec/management/backend/internal/companion"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg := companion.Config{}
	flag.StringVar(&cfg.ManagerURL, "manager", env("MANAGER_URL", ""),
		"base URL of the manager's agent plane, e.g. http://appsec-manager")
	flag.StringVar(&cfg.Token, "token", env("MANAGER_ENROLLMENT_TOKEN", ""),
		"enrollment token issued when this agent was registered")
	flag.StringVar(&cfg.PolicyPath, "policy-path", env("POLICY_PATH", "/ext/appsec/local_policy.yaml"),
		"where to write the policy, as this process sees it")
	flag.StringVar(&cfg.AgentPolicyPath, "agent-policy-path",
		env("AGENT_POLICY_PATH", "/etc/cp/conf/local_policy.yaml"),
		"the same file as the agent sees it; passed to set-apply-policy")
	flag.StringVar(&cfg.OrchestrationURL, "orchestration-url",
		env("ORCHESTRATION_URL", "http://127.0.0.1:7777"),
		"the agent's local orchestration API")
	interval := flag.Duration("interval", envDuration("SYNC_INTERVAL", 30*time.Second),
		"how often to check the manager for a new policy")
	once := flag.Bool("once", false, "perform a single sync and exit")
	flag.Parse()

	cfg.Interval = *interval

	if cfg.ManagerURL == "" || cfg.Token == "" {
		fmt.Fprintln(os.Stderr,
			"both -manager and -token are required (or MANAGER_URL and MANAGER_ENROLLMENT_TOKEN)")
		flag.Usage()
		os.Exit(2)
	}

	c := companion.New(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := c.Sync(ctx); err != nil {
			slog.Error("sync failed", "error", err)
			os.Exit(1)
		}
		return
	}

	slog.Info("appsec-agent-sync started",
		"manager", cfg.ManagerURL, "interval", cfg.Interval, "policyPath", cfg.PolicyPath)
	if err := c.Run(ctx); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
