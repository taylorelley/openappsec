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

package fleet

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// AllowPrivateScrapeTargets permits scraping addresses that are otherwise
// refused as internal.
//
// It defaults to true because the normal deployment is exactly that: agents on
// a private compose or cluster network. Set it false where the manager can
// reach infrastructure the agents should not be able to make it call.
var AllowPrivateScrapeTargets = true

// ParseMetricsEndpoint validates an agent's metrics endpoint and returns the
// URL to scrape.
//
// This is a server-side-request-forgery boundary, not a formatting helper. The
// value is not only set by an operator: RecordStatus also takes it from the
// status push, so an enrolled agent can choose what the manager connects to.
// Without validation an agent could point the manager at a cloud metadata
// service or another internal host, and the scraped values would then be
// readable through the agent's metrics view.
func ParseMetricsEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("fleet: metrics endpoint is empty")
	}

	host, port := endpoint, strconv.Itoa(DefaultMetricsPort)

	// A full URL is accepted only for http and https, and its path is
	// discarded: the manager always scrapes /metrics.
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return "", fmt.Errorf("fleet: malformed metrics endpoint: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", fmt.Errorf("fleet: metrics endpoint scheme %q is not allowed", parsed.Scheme)
		}
		host = parsed.Hostname()
		if p := parsed.Port(); p != "" {
			port = p
		}
		if err := checkTarget(host); err != nil {
			return "", err
		}
		return (&url.URL{
			Scheme: parsed.Scheme,
			Host:   net.JoinHostPort(host, port),
			Path:   "/metrics",
		}).String(), nil
	}

	// Otherwise a bare host, or host:port.
	if h, p, err := net.SplitHostPort(endpoint); err == nil {
		host, port = h, p
	}
	if host == "" {
		return "", fmt.Errorf("fleet: metrics endpoint has no host")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("fleet: metrics endpoint port %q is not valid", port)
	}
	if err := checkTarget(host); err != nil {
		return "", err
	}

	return (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
		Path:   "/metrics",
	}).String(), nil
}

// checkTarget refuses the address families that make SSRF worth attempting.
//
// A hostname is allowed through, because resolving it here would only move the
// check earlier than the actual dial and could still differ from what the
// transport resolves later.
func checkTarget(host string) error {
	if host == "" {
		return fmt.Errorf("fleet: metrics endpoint has no host")
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil // a hostname; nothing to classify here
	}

	switch {
	case ip.IsLoopback():
		return fmt.Errorf("fleet: refusing to scrape the loopback address %q", host)
	case ip.IsUnspecified():
		return fmt.Errorf("fleet: refusing to scrape the unspecified address %q", host)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.169.254 is the cloud metadata address; the whole range goes.
		return fmt.Errorf("fleet: refusing to scrape the link-local address %q", host)
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return fmt.Errorf("fleet: refusing to scrape the multicast address %q", host)
	case ip.IsPrivate() && !AllowPrivateScrapeTargets:
		return fmt.Errorf("fleet: refusing to scrape the private address %q", host)
	}
	return nil
}
